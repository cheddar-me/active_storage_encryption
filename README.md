## What does this do?

This library will enable the use of per-blob encryption keys with ActiveStorage. It enables file encryption with a separate encryption key generated for every `ActiveStorage::Blob`. It uses [CSEK](https://cloud.google.com/storage/docs/encryption/using-customer-supplied-keys) on Google Cloud, [SSE-K](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html#specifying-s3-c-encryption) on AWS, and [block_cipher_kit](https://rubygems.org/gems/block_cipher_kit) for files on disk to add a layer of encryption to every uploaded file. Every `Blob` gets its own, random encryption key.

During streaming download, either the cloud provider or a Rails controller will decrypt the requested chunk of the file as it gets served to the client.

## Installation

Install the gem and run the migration.

```shell
bundle add active_storage_encryption
bin/rails active_storage_encryption:install
bin/rails db:migrate
```

Then, set up an encrypted service in `config/storage.yml` like so (in this example we use an `EncryptedDisk` service, which you can play around with in development):

```yaml
# storage.yml
encrypted_local_disk:
  service: EncryptedDisk # this is the service implementation you need to use
  private_url_policy: stream
  root: <%= Rails.root.join("storage", "encrypted") %>
```

Then, on your model carrying the attachments:

```ruby
class User < ApplicationRecord
  has_one_attached :id_document_scan, service: :encrypted_local_disk
end
```

And.. that's it! For both GCS and S3, you will need to create an additional ActiveStorage service. The configuration is exactly the same as stock ActiveStorage services, with the addition of the `private_url_policy` [parameter.](#private-url-constraints)

## How it works

This gem protects from a relatively common data breach scenario - cloud account access. Should an attacker gain access to your cloud storage bucket, the files stored there will be of no use to them without them also having a separate, specific encryption key for every file they want to retrieve.

The standard implementation of this usually works like this:

* You generate an encryption key which satisfies the provider's requirements
* You then send that key in a header along with your upload PUT request. The PUT request sends the file unencrypted to the provider, along with the key you have generated and signed.
* Before depositing your file in the bucket, the provider applies its encryption (and usually - some form of chunking, but that is transparent to you) to the data it receives from you
* Once the encrypted file is in the cloud storage, there is no plaintext version present anywhere
* Every read access to the file requires that you provide the encryption key

With this gem, you configure encrypted storage services in your `storage.yml` config, and run the included migration - which adds the `encryption_key` column to your `active_storage_blobs` table. Interactions with the cloud storage will then add the encryption key to all requests.

Once a `Blob` destined to be stored on an encrypted storage service (you set the `service:` where the blob should go in your `has_attached` calls) gets created in Rails, the blob will get a random encryption key generated for it. All further operations with the `Blob` are going to use that generated encryption key, automatically. None of the calls to the Blob will require the encryption key to be provided explicitly - everything should work as if you were dealing with a standard `ActiveStorage::Blob`.

This enables enhanced security for sensitive data, such as uploaded documents of all sorts, identity photos, biometric data and the like.

## Configuration

The use of encrypted file storage can be enabled by plugging an appropriate Service in your storage configuration. With the way the library works, your standard ActiveStorage services you already have will not magically start encrypting the data stored in them. It is recommended to define separate services for your sensitive data, as behaviour of the encrypted data stores differs in subtle ways from a standard ActiveStorage service.

## What this gem _can_ do

It is a tool for additional protection of sensitive files.

Normally, your cloud storage used for binary data will already support some form of encryption-at-rest, usually using the could provider's KMS (key management service). This is a sensible default, however it does not protect you from one important attack vector: a party obtaining access to your cloud storage bucket. If they do manage to obtain that access, they usually also have access to the KMS (by virtue of having access to a cloud account you control) and can bulk-download all of your data, unencrypted. All an attacker needs are cloud credentials for an account with "read" and "list" permissions.

With per-object encryption, however, just access to the bucket does not give the attacker much. Since every object is encrypted with a separate key, they need to have a key for every single file. That key is not stored in the provider's KMS, so even an account with KMS access won't be able to decrypt them.

Additionally, neither the cloud console (web UI) nor the API client will be able to download those objects without the keys.

The only way to obtain access would be for the attacker to have access to:

* A database dump of the `active_storage_blobs` table
* Your application's secrets (to decrypt the values in the table).
* The cloud storage bucket

It's way more work, and way more hassle. This is great for sensitive files, and increases security considerably.

## What this gem _cannot_ do

This gem does not provide an E2E encrypted solution. The file still gets encrypted by your cloud provider, and decrypted by your cloud provider. While it offers a strong protection _at rest_ it does not offer extra protection _in transit._ If you need that level of protection, you may want to look into [S3 client encryption](https://ankane.org/activestorage-s3-encryption) or other similar tech.

## Encrypted Service implementations

At the moment, we provide a few encrypted `Service` subclasses that you can use.

### EncryptedGCSService - Google Cloud Storage

The `EncryptedGCSService` supports most of the features of the stock `GCSService`:

* Upload and download
* Presigned PUT requests (direct upload)
* Preset metadata (content-disposition, content-type etc.)

Implementation details:

* Presigned URLs are subject to the [same constraints](#private-url-constraints) as the other providers. GCP will only serve you objects if you supply the headers. If you wish to generate URLs that can be used without headers, streaming goes through our provided controller.
* In the stock `Service` the `#compose` operation is "hopless": you tell GCP to "splice" multiple objects in-situ without having to download their content into your application. With encryption, `#compose` can't be performed "hoplessly" as the "compose" RPC call for encrypted objects requires the source objects be encrypted with the same encryption key - all of them. The resulting object will also be encrypted with that key. With this gem, every `Blob` gets encrypted with its own random key, so performing a `#compose` requires downloading the objects, decrypting them and reuploading the composed object. This gets done in a streaming manner to conserve disk space and memory (we provide a resumable upload client for GCS even though the official SDK does not), but the operation is no longer "hopless".

### EncryptedS3Service - AWS S3

The `EncryptedS3Service` supports most of the features of the stock `S3Service`.

Implementation details:

* SSE-K is a feature that AWS provides. Other services offering S3-compatible object storage (Minio, Ceph...) may not support this feature - check the documentation of your provider.
* Presigned URLs are subject to the [same constraints](#private-url-constraints) as with GCS. S3 will only serve you objects if you supply the headers. If you wish to generate URLs that can be used without headers, streaming goes through our provided controller.
* The `#compose` operation is not hopless with S3, so there is no reduction in functionality vis-a-vis the standard `S3Service`.

## EncryptedDiskSevice - Filesystem

Can be used instead of the cloud services in development, or on the server if desired. The service will use AES-256-GCM encryption, with a way to switch to a different/more modern encryption scheme in the future.

Implementation details:

* Files will have the `.encrypted-v<N>` filename extension. The `v-<N>` stands for the version of the encryption scheme applied.
* Presigned URLs are subject to the [same constraints](#private-url-constraints) as the other providers. To resemble other encrypted Services, presigned URLs with header requirement will only be served by the provided controller if appropriate headers are sent with the request. If you wish to generate URLs that can be used without headers, streaming goes through our provided controller.
* The schemes for encryption are in the `block_cipher_kit` gem. Currently we use AES-256-GCM for blobs, with the authentication tag verified in case of a full download. Random access uses AES-256-CTR.
* A SHA2 digest of the encryption key is stored at the beginning of the encrypted file. This is used to deny download rapidly if an incorrect encryption key is provided.
* The IV is stored at the start of the ciphertext, after the digest of the encryption key. The IV gets generated at random for every Blob being encrypted.

## Additional information

* The stored `digest` (the Base64-encoded MD5 of the blob) will be for the plaintext file contents. This reduces security somewhat, because MD5 has known collisions and facilitates (to some extend) mounting a "known plaintext" attack.
* The stored `filesize` will be for the plaintext. This, again, facilitates an attack somewhat.

## Downloading the plaintext file contents in full or in part

Data will be automatically decrypted using the correct key on `Blob#open` or `Blob#download`. `EncryptedDiskSevice` will also apply the GCM validation check at the end of download/read (authenticate the cipher).

All of our encrypted Services support `download_range` for random access to the blob's plaintext. The decryption will be done in a streaming manner, without buffering:

* Cloud providers give you access to plaintext segments of the file using the HTTP `Range:` header (ranges are in plaintext offsets)
* `EncryptedDiskSevice` provides the same, but inside the app will access OS files - decrypting them in a streaming manner.

## Constraints with encrypted Blobs

There are also subtle differences in how cloud providers treat encrypted objects in their object storage vs. how other objects are treated, as well as which facilities change or become unavailable once your object is encrypted. Additionally, some ActiveStorage operations change semantics or start requiring an `encryption_key:` argument. Understanding those limitations is key to using active_storage_encryption correctly and effectively.

Key differences are as follows:

* If a Service supports encryption, _every_ blob stored on it will be encrypted. No exceptions. You cannot supply an encryption key of `nil` to bypass encryption on that service.
* A blob stored onto - or retrieved from - an encrypted Service must have an `#encryption_key` that is not `nil`
* Most operations performed on an encrypted Service must supply the encryption key, or multiple encryption keys (in case of `Service#compose`)
* An encrypted Service cannot be `public: true` - no CDNs we are aware of can proxy objects with per-object encryption keys.
* An encrypted Service cannot generate a signed GET URL unless you let that URL go through a streaming controller (we provide one), or you are going to send headers to the cloud providers' download endpoint. We default to using the streaming controller, which may cause a performance impact on your app due to slow clients. See more [here.](#private-url-constraints)
* Objects using per-object encryption are usually **inaccessible for cloud automation** - for example, scripts that load files into a cloud database using paths to the bucket will likely not work, as data is no longer readable for them. There will also be limitations for CLI clients. For example, the `gcloud` CLI only allows you to supply 100 encryption keys, and thus will only be able to download 100 objects at once.

## Private URL constraints

Both major cloud providers (S3 and GCP cloud storage) disallow using signed GET URLs unless you also supply the encryption key (and encryption parameters, as well as the key checksum) in the GET request headers. This has _severe_ implications for use of `Blob#url` and `rails_blob_path` / `rails_blob_url`, namely:

* You cannot redirect to a signed GET URL for an ActiveStorage blob (for downloading). Standard Rails `blob_path` helpers lead to an ActiveStorage controller which will try to redirect your browser to such a URL, but the browser will then receive a `403 Forbidden` response.
* You can no longer use a signed GET URL for an ActiveStorage blob as the `src` attribute for an `img`, `video` or `audio` element

Cloud providers presumably disallow supplying the encryption key inside the URL itself because they want to prevent those URLs gettng saved in web server / load balancer logs, and from being shared. This is a valid security concern, as most URL signing schemes are just for _signing_ but not for _encryption._ An encryption key of this nature could also be retained by a malicious party and reused.

However, for practical purposes you _may_ want to permit such URLs to be generated by your application, with very limited expiry time. We allow for this, with an associated limitation that the blob binary data **is then going to be streamed.** In that setup your Rails app functions as a streaming proxy, which will perform the request to cloud storage - passing along the requisite credentials - and stream the output to your client. This may not be the most performant way to stream data, but when per-file encryption is required this usually concerns sensitive files, which are not very widely shared anyway. We believe streaming to be a sensible compromise. Note that you want the streaming URLs to be short-lived!

To configure this facility, every encrypted `Service` we provide supports the `private_url_policy` configuration parameter. The possible values are as follows:

* `private_url_policy: disable` will make every call to `Blob#url` raise an exception. This will be raised by the stock Rails `ActiveStorage::Blobs::RedirectController#show`
* `private_url_policy: require_headers` will generate signed URLS, and you will need to ensure these URLs are only requested with the correct HTTP headers. The URLs will not expose the encryption key. When trying to use `rails_blob_path` you will end up receiving a 403 from the cloud storage provider after the redirect. You still may want to generate those URLs if you want to use them elsewhere and will be willing to manually add HTTP headers to the request.
* `private_url_policy: stream` will stream the decrypted Blob through our Rails controller. The URLs to that controller will not expose the encryption key. `rails_blob_path` will work, and generate a URL to the stock Rails `ActiveStorage::Blobs::RedirectController#show` action. That action, in turn, will generate a URL leading to `ActiveStorageEncryption::EncryptedBlobsController#show`. That action will stream out your file from whichever encrypted service your Blob is using.

For using the `require_headers` option you may want to use `Blob#headers_for_private_download` method - it will return you a `Hash` of headers that have to be supplied along with your request to the signed URL of the cloud service.

## Key exposure on upload

Both implementations of customer-supplied encryption keys (S3 and GCP) sign the checksum of the encryption key issued to the uploading client, so that the client may not alter the encryption key your application has issued. However, neither of them support key wrapping - encrypting the key before giving it to the client for performing the upload. GCP does support key wrapping, but only for its Compute Platform, and not for Cloud Storage. Therefore, the uploading client (the one that performs the PUT to the cloud storage or to our controller) is going to be able to decode and retain the raw encryption key.

You can, of course, rewrite the object in storage to decrypt it and re-encrypt it with a new encryption key, which the original uploader does not possess. This takes extra resources, however.

## Key exposure on download

When we stream through the controller, we encrypt the token instead of just signing it. This conceals the encryption key of the Blob, and uses standard Rails encryption. For our purposes we consider this configuration sufficiently secure.

## Direct uploads

All supported services accept the encryption key as part of the headers for the PUT direct upload. The provided Service implementations will generate the correct headers for you. However, your upload client _must_ use the headers provided to you by the server, and not invent its own. The standard ActiveStorage JS bundles honor those headers - but if you use your own uploader you will need to ensure it honors and forwards the headers too.

We also configure the services to generate _and_ require the `Content-MD5` header. The client doing the PUT will need to precompute the MD5 for the object before starting the PUT request or getting a PUT url (as the checksum gets signed by the cloud SDK or by our `EncryptedDiskService`). This is so that any data transmission errors can be intercepted early (we know of one case where a bug in Ruby, combined with a particular HTTP client library, led to bytes getting uploaded out of order).

## Security considerations / notes

* It is imperative that you let the server generate the encryption key, and not generate one on the client. Where possible, we add the headers for the encryption key to the signed URL parameters, so client generated keys will deliberately _not_ function. Letting the client generate the keys can lead to key reuse (unintentional or - worse - intentional).
* The key used is _not_ a passphrase or a password. It is a high-entropy bag of bytes, generated for every blob separately using `SecureRandom`. We generate more bytes than the cloud providers usually expect (32 bytes for AES) and take the starting bytes off that longer key - that is to allow mirroring to services that have varying key lengths, using the same encryption key.
* To the best of our knowledge, both S3 and GCS use AES-256-GCM (or a variation thereof) for encryption. Random access to GCM blocks requires dropping the auth tag validation (cipher authentication) of GCM, and downgrades it to CTR. We find this an acceptable tradeoff to enable random access.
* You must use `attribute_encrypted` and encrypt your `encryption_key` in the `active_storage_blobs` table, otherwise your data is not really safe in case a database dump gets exfiltrated.
* active_storage_encryption has not been verified by information security experts or cryptographers. While we do our best to have it be robust and secure, mishaps may happen. You have been warned.
* While cloud providers do publish some information about their encryption approaches, we do not know several crucial details allowing one to say that "this encryption scheme is secure enough for our needs". Namely:
  * Neither GCP nor AWS say how the IV gets generated. A compromised IV (repeated IV) simplifies breaking a block cipher considerably.
  * Neither GCP nor AWS say when they reset the IV. Counter-based IVs have a limit on the number of counter values and blocks that they support. For GCM and CTR the practical limit is around 64GB per encrypted message. To add extra safety, it is sometimes advised to "stitch" the message from multiple messages with the IV getting regenerated at random, for every message. If providers do use such "chunking", we could not find information about the size of the chunks nor the mechanics by which the IV gets generated for them.

Finally: this gem has not been verified by an information security expert or a cryptographer. While we did take all the possible precautions with regards to producing a secure design, we are all humans and might have omitted something.

## Mirroring

We provide a version of the `EncryptedMirrorService` which is going to use the same encryption key when mirroring to multiple services. It needs some modifications in comparison to a standard `MirrorService` because if any services it mirrors to use encryption, it needs an encryption key to be provided upstream for all write operations - so that it can be passed on to downstream Services. You can only mirror an encrypted `Blob` to encrypted services.

## Key truncation

In practice, all services use some form of AES-256 and therefore use a 32-byte encryption key. However, we can't exclude the possibility that there will be support for newer encryption schemes in the future with a longer encryption key being available. Because we potentially may need to allow a `Blob` to be encrypted and decrypted by service A, and then encrypted by service B, there is a possibility that key length requirements for those services could differ. Therefore, we generate a longer `encryption_key` (from the same random byte source) than strictly necessary for AES-256 and save it in your `active_storage_blobs` table. This key then gets truncated to satisfy the key length requirements of a particular encrypted Service.

This has an important implication for how the Service classes are written: they need to truncate the encryption keys to their conformant length themselves.

Important, once again: **do not use passwords for this encryption key.** If you really want to use passwords, use something like PBKDF (available via [ActiveSupport::KeyGenerator](https://api.rubyonrails.org/classes/ActiveSupport/KeyGenerator.html) to derive a high-entropy key from your passphrase in a safe manner.

## Storing your encryption keys securely

The `encryption_key` must be subjected to ActiveRecord attribute encryption. Of course, you may not do it, but... no - wait. Once more:

> [!WARNING]  
> The `ActiveStorage::Blob#encryption_key` attribute must be an encrypted ActiveRecord attribute. Do set up your attribute encryption.

The value in that column is what's called "key material". It is highly sensitive and the attacker obtaining a database dump will immediately have unfettered access to all the encryption keys, for all Blobs that you have. You can refer to [this guide](https://guides.rubyonrails.org/active_record_encryption.html) on how to set up attribute encryption. The variant you want is **non-deterministic encryption** (you likely do not want to search for a specific encryption key in your database).

## Migrating your blobs into an encrypted store

We provide a method on the `Blob` for this - called `migrate_to_encrypted_service(service)`. The method will:

* Generate an `encryption_key` for the blob in question
* Stream the plaintext data into a copy on the encrypted service, applying encryption
* Transactionally store the encryption key on the `Blob` _and_ switch its `service` to the encrypted service.


## License
The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
