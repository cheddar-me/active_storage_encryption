# frozen_string_literal: true

require "active_storage/service/s3_service"

class ActiveStorageEncryption::EncryptedS3Service < ActiveStorage::Service::S3Service
  include ActiveStorageEncryption::PrivateUrlPolicy
  def encrypted? = true

  def initialize(public: false, **options_for_s3_service_and_private_url_policy)
    raise ArgumentError, "encrypted files cannot be served via a public URL or a CDN" if public
    super
  end

  def service_name
    # ActiveStorage::Service::DiskService => Disk
    # Overridden because in Rails 8 this is "self.class.name.split("::").third.remove("Service")"
    self.class.name.split("::").last.remove("Service")
  end

  def headers_for_direct_upload(key, encryption_key:, **options_for_super)
    # See https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html#specifying-s3-c-encryption
    super(key, **options_for_super).merge!(sse_headers(encryption_key))
  end

  def exist?(key)
    # The stock S3Service uses S3::Object#exists? here. That method does
    # a HEAD request to the S3 bucket under the hood. But there is a problem
    # with that approach: to get all the metadata attributes of an object on S3
    # (which is what the HEAD request should return to you) you need the encryption key.
    # The interface of the ActiveStorage services does not provide for extra arguments
    # for `Service#exist?`, so all we would get using that SDK call would be an error.
    #
    # But we don't need the object metadata - we need to know is whether the object exists
    # at all. And this can be done with a GET request instead. We ask S3 to give us the first byte of the
    # object. S3 will then raise an exception - the exception will be different
    # depending on whether the object does not exist _or_ the object does exist, but
    # is encrypted. We can use the distinction between those exceptions to tell
    # whether the object is there or not.
    #
    # There is also a case where the object is not encrypted - in that situation
    # our single-byte GET request will actually succeed. This also means that the
    # object exists in the bucket.
    object_for(key).get(range: "bytes=0-0")
    # If we get here without an exception - the object exists in the bucket,
    # but is not encrypted. For example, it was stored using a stock S3Service.
    true
  rescue Aws::S3::Errors::InvalidRequest, Aws::S3::Errors::InvalidArgument
    # With this exception S3 tells us that the object exists but we have to furnish
    # the encryption key (the exception will have a message with "object was stored
    # using a form of Server Side Encryption..."). AWS raises InvalidRequest;
    # S3-compatible stores such as Hetzner Object Storage raise InvalidArgument.
    true
  rescue Aws::S3::Errors::NoSuchKey
    # And this truly means the object is not present
    false
  end

  def headers_for_private_download(key, encryption_key:, **)
    sse_headers(encryption_key)
  end

  def url_for_direct_upload(key, encryption_key:, expires_in:, content_type:, content_length:, checksum:, custom_metadata: {})
    instrument :url, key: key do |payload|
      payload[:url] = presigned_url_with_signed_sse_headers(key, :put, encryption_key:, expires_in: expires_in.to_i,
        content_type: content_type, content_length: content_length, content_md5: checksum,
        metadata: custom_metadata, whitelist_headers: ["content-length"], **upload_options)
    end
  end

  def upload(*args, encryption_key:, **kwargs)
    with_upload_options_for_customer_key(sse_options(encryption_key)) do
      super(*args, **kwargs)
    end
  end

  def download(key, encryption_key:, &block)
    if block_given?
      instrument :streaming_download, key: key do
        stream(key, encryption_key: encryption_key, &block)
      end
    else
      instrument :download, key: key do
        object_for(key).get(**sse_options(encryption_key)).body.string.force_encoding(Encoding::BINARY)
      rescue Aws::S3::Errors::NoSuchKey
        raise ActiveStorage::FileNotFoundError
      end
    end
  end

  def download_chunk(key, range, encryption_key:)
    instrument :download_chunk, key: key, range: range do
      object_for(key).get(range: "bytes=#{range.begin}-#{range.exclude_end? ? range.end - 1 : range.end}", **sse_options(encryption_key)).body.string.force_encoding(Encoding::BINARY)
    rescue Aws::S3::Errors::NoSuchKey
      raise ActiveStorage::FileNotFoundError
    end
  end

  def compose(source_keys, destination_key, source_encryption_keys:, encryption_key:, filename: nil, content_type: nil, disposition: nil, custom_metadata: {})
    if source_keys.length != source_encryption_keys.length
      raise ArgumentError, "With #{source_keys.length} keys to compose there should be exactly as many source_encryption_keys, but got #{source_encryption_keys.length}"
    end
    content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename
    upload_options_for_compose = upload_options.merge(sse_options(encryption_key))
    object_for(destination_key).upload_stream(
      content_type: content_type,
      content_disposition: content_disposition,
      part_size: MINIMUM_UPLOAD_PART_SIZE,
      metadata: custom_metadata,
      **upload_options_for_compose
    ) do |s3_multipart_io|
      s3_multipart_io.binmode
      source_keys.zip(source_encryption_keys).each do |(source_key, source_encryption_key)|
        stream(source_key, encryption_key: source_encryption_key) do |chunk|
          s3_multipart_io.write(chunk)
        end
      end
    end
  end

  private

  # Reads the object for the given key in chunks, yielding each to the block.
  def stream(key, encryption_key:)
    object = object_for(key)

    chunk_size = 5.megabytes
    offset = 0

    # Doing a HEAD (what .exists? does under the hood) also requires the encryption key headers,
    # but the SDK does not send them along. Instead of doing a HEAD, you can also do a GET - but for the first byte.
    # This will give you the content-length of the object, and the SDK will pass the correct encryption headers.
    # There is an issue in the SDK here https://github.com/aws/aws-sdk-ruby/issues/1342 which is allegedly fixed
    # by https://github.com/aws/aws-sdk-ruby/pull/1343/files but it doesn't seem like it.
    # Also, we do not only call `S3::Object#exists?`, but also `S3::Object#content_length` - which does not have a way to pass
    # encryption options either.
    response = object.get(range: "bytes=0-0", **sse_options(encryption_key))
    object_content_length = response.content_range.scan(/\d+$/).first.to_i

    while offset < object_content_length
      yield object.get(range: "bytes=#{offset}-#{offset + chunk_size - 1}", **sse_options(encryption_key)).body.string.force_encoding(Encoding::BINARY)
      offset += chunk_size
    end
  rescue Aws::S3::Errors::NoSuchKey
    raise ActiveStorage::FileNotFoundError
  end

  def sse_options(encryption_key)
    truncated_key_bytes = encryption_key.byteslice(0, 32)
    {
      sse_customer_algorithm: "AES256",
      sse_customer_key: truncated_key_bytes,
      sse_customer_key_md5: Digest::MD5.base64digest(truncated_key_bytes)
    }
  end

  # This is the same as sse_options but expressed with raw header names
  def sse_headers(encryption_key)
    sdk_sse_options = sse_options(encryption_key)
    {
      "x-amz-server-side-encryption-customer-algorithm" => sdk_sse_options.fetch(:sse_customer_algorithm),
      "x-amz-server-side-encryption-customer-key" => Base64.strict_encode64(sdk_sse_options.fetch(:sse_customer_key)),
      "x-amz-server-side-encryption-customer-key-MD5" => sdk_sse_options.fetch(:sse_customer_key_md5)
    }
  end

  def private_url(key, encryption_key:, **options)
    case private_url_policy
    when :disable
      if private_url_policy == :disable
        raise ActiveStorageEncryption::StreamingDisabled, <<~EOS
          Requested a signed GET URL for #{key.inspect} on service #{name}. This service
          has disabled presigned URLs (private_url_policy: disable), you have to use `Blob#download` instead.
        EOS
      end
    when :stream
      private_url_for_streaming_via_controller(key, encryption_key:, **options)
    when :require_headers
      presigned_url_with_signed_sse_headers(key, :get, encryption_key:, expires_in: options.fetch(:expires_in).to_i,
        response_content_disposition: content_disposition_with(type: options.fetch(:disposition), filename: options.fetch(:filename)),
        response_content_type: options.fetch(:content_type))
    end
  end

  # The stock S3Service uses `presigned_url`, which hoists all x-amz-* headers into the query string.
  # That has two problems with SSE-C: the key would leak into the URL, and some providers
  # (DigitalOcean Spaces) ignore SSE-C params in the query string. `presigned_request` keeps them
  # as signed headers instead - the client then has to send exactly those values, so it also
  # can't swap the encryption key for one of its own. See `sse_headers` for what gets sent.
  def presigned_url_with_signed_sse_headers(key, method, encryption_key:, **params)
    url, _headers_the_client_must_send = object_for(key).presigned_request(method, **params, **sse_options(encryption_key))
    url
  end

  def public_url(key, **client_opts)
    raise "This should never be called"
  end

  def upload_options
    super.merge(Thread.current[:aws_sse_options].to_h)
  end

  def with_upload_options_for_customer_key(overriding_upload_options)
    # Gotta be careful here, because this call can be re-entrant.
    # If one thread calls `upload_options` to do an upload, and does not
    # return for some time, we want this thread to be using the upload options
    # reserved for it - otherwise objects can get not their encryption keys, but
    # others'. If we want to have upload_options be tailored to every specific upload,
    # we would need to override way more of this Service class than is really needed.
    # You can actually see that sometimes there is reentrancy here:
    #
    # MUX = Mutex.new
    # opens_before = MUX.synchronize { @opens ||= 0; @opens += 1; @opens - 1 }
    previous = Thread.current[:aws_sse_options]
    Thread.current[:aws_sse_options] = overriding_upload_options
    yield
  ensure
    # To check that there is reentrancy:
    # opens_after = MUX.synchronize { @opens -= 1 }
    # warn [opens_before, opens_after].inspect #exiting wo"
    # In our tests:
    # [2, 11]
    # [10, 10]
    # [0, 9]
    # [9, 8]
    # [5, 7]
    # [3, 6]
    # [6, 5]
    # [1, 4]
    # [8, 3]
    # [4, 2]
    # [7, 1]
    # [11, 0]
    # [0, 0]
    # [0, 0]
    # [0, 0]
    # [0, 0]
    # [0, 0]
    Thread.current[:aws_sse_options] = previous
  end
end
