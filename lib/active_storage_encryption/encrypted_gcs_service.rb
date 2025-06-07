# frozen_string_literal: true

require "active_storage/service/gcs_service"
require "google/cloud/storage/service"

class ActiveStorageEncryption::EncryptedGCSService < ActiveStorage::Service::GCSService
  autoload :ResumableUpload, __dir__ + "/encrypted_gcs_service/resumable_upload.rb"

  include ActiveStorageEncryption::PrivateUrlPolicy
  GCS_ENCRYPTION_KEY_LENGTH_BYTES = 32 # google wants to get a 32 byte key

  def encrypted? = true

  def public? = false

  def service_name
    # ActiveStorage::Service::DiskService => Disk
    # Overridden because in Rails 8 this is "self.class.name.split("::").third.remove("Service")"
    self.class.name.split("::").last.remove("Service")
  end

  def upload(key, io, encryption_key: nil, checksum: nil, content_type: nil, disposition: nil, filename: nil, custom_metadata: {})
    instrument :upload, key: key, checksum: checksum do
      # GCS's signed URLs don't include params such as response-content-type response-content_disposition
      # in the signature, which means an attacker can modify them and bypass our effort to force these to
      # binary and attachment when the file's content type requires it. The only way to force them is to
      # store them as object's metadata.
      content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename
      bucket.create_file(io, key, md5: checksum, cache_control: @config[:cache_control], content_type: content_type, content_disposition: content_disposition, metadata: custom_metadata, encryption_key: derive_service_encryption_key(encryption_key))
    rescue Google::Cloud::InvalidArgumentError => e
      raise ActiveStorage::IntegrityError, e
    end
  end

  def url_for_direct_upload(key, expires_in:, checksum:, encryption_key:, content_type: nil, custom_metadata: {}, filename: nil, **)
    instrument :url, key: key do |payload|
      headers = headers_for_direct_upload(key, checksum:, encryption_key:, content_type:, filename:, custom_metadata:)

      version = :v4

      args = {
        content_md5: checksum,
        expires: expires_in,
        headers: headers,
        method: "PUT",
        version: version
      }

      if @config[:iam]
        args[:issuer] = issuer
        args[:signer] = signer
      end

      generated_url = bucket.signed_url(key, **args)

      payload[:url] = generated_url

      generated_url
    end
  end

  def headers_for_direct_upload(key, checksum: nil, encryption_key:, filename: nil, disposition: nil, content_type: "binary/octet-stream", custom_metadata: {}, **)
    headers = {
      "Content-Type" => content_type,
      **gcs_encryption_key_headers(derive_service_encryption_key(encryption_key)),
      **custom_metadata_headers(custom_metadata)
    }
    # Content-MD5 is very useful but it is not always possible to provide ahead of time.
    # For example, when doing a resumable upload it will not be available before starting.
    headers["Content-MD5"] = checksum if checksum
    headers["Content-Disposition"] = content_disposition_with(type: disposition, filename: filename) if filename

    if @config[:cache_control].present?
      headers["Cache-Control"] = @config[:cache_control]
    end
    headers
  end

  def compose(source_keys, destination_key, source_encryption_keys:, encryption_key:, filename: nil, content_type: nil, disposition: nil, custom_metadata: {})
    if source_keys.length != source_encryption_keys.length
      raise ArgumentError, "With #{source_keys.length} keys to compose there should be exactly as many source_encryption_keys, but got #{source_encryption_keys.length}"
    end
    content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename
    destination_encryption_key = derive_service_encryption_key(encryption_key)
    file_for_destination = file_for(destination_key)
    # ...content_type: "binary/octet-stream", **signed_url_options

    # As per https://cloud.google.com/storage/docs/xml-api/post-object-resumable the encryption key is
    # provided in the headers for the resumable upload start, in the POST request
    headers = headers_for_direct_upload(destination_encryption_key, encryption_key: destination_encryption_key)

    content_type ||= "binary/octet-stream"
    filename ||= ActiveStorage::Filename.new(destination_key)
    disposition ||= "inline"
    expires_in = 30.seconds.to_i

    signed_url_params = signed_url_parameters = signed_url_parameters(disposition, filename, content_type, destination_encryption_key, expires_in)
    uploader = ResumableUpload.new(file_for_destination, headers: headers, **signed_url_params)

    uploader.stream do |destination|
      destination.binmode
      source_keys.zip(source_encryption_keys).each do |(source_key, source_encryption_key)|
        stream(source_key, encryption_key: derive_service_encryption_key(source_encryption_key)) do |chunk|
          destination.write(chunk)
        end
      end
    end
  end

  def download(key, encryption_key: nil, &block)
    if block_given?
      instrument :streaming_download, key: key do
        stream(key, encryption_key: encryption_key, &block)
      end
    else
      instrument :download, key: key do
        file_for(key).download(encryption_key: derive_service_encryption_key(encryption_key)).string
      rescue Google::Cloud::NotFoundError => e
        raise ActiveStorage::FileNotFoundError, e
      end
    end
  end

  def download_chunk(key, range, encryption_key: nil)
    instrument :download_chunk, key: key, range: range do
      file_for(key).download(range: range, encryption_key: derive_service_encryption_key(encryption_key)).string
    rescue Google::Cloud::NotFoundError => e
      raise ActiveStorage::FileNotFoundError, e
    end
  end

  # Reads the file for the given key in chunks, yielding each to the block.
  def stream(key, encryption_key: nil)
    file = file_for(key, skip_lookup: false)

    chunk_size = 5.megabytes
    offset = 0

    raise ActiveStorage::FileNotFoundError unless file.present?

    while offset < file.size
      yield file.download(range: offset..(offset + chunk_size - 1), encryption_key: derive_service_encryption_key(encryption_key)).string
      offset += chunk_size
    end
  end

  private

  def signed_url_parameters(disposition, filename, content_type, encryption_key, expires_in)
    args = {
      expires: expires_in,
      query: {
        "response-content-disposition" => content_disposition_with(type: disposition, filename: filename),
        "response-content-type" => content_type
      },
      headers: gcs_encryption_key_headers(derive_service_encryption_key(encryption_key))
    }

    if @config[:iam]
      args[:issuer] = issuer
      args[:signer] = signer
    end
    args
  end

  def private_url(key, expires_in:, filename:, content_type:, disposition:, encryption_key:, **remaining_options_for_streaming_url)
    if private_url_policy == :require_headers
      signed_url_parameters = signed_url_parameters(disposition, filename, content_type, encryption_key, expires_in)
      file_for(key).signed_url(**signed_url_parameters, version: :v4)
    else
      private_url_for_streaming_via_controller(key, expires_in:, filename:, content_type:, disposition:, encryption_key:, **remaining_options_for_streaming_url)
    end
  end

  def public_url(key, filename:, encryption_key:, content_type: nil, disposition: :inline, **)
    raise "Public URL's are disabled for this service"
  end

  def gcs_encryption_key_headers(key)
    {
      "x-goog-encryption-algorithm" => "AES256",
      "x-goog-encryption-key" => Base64.strict_encode64(key),
      "x-goog-encryption-key-sha256" => Digest::SHA256.base64digest(key)
    }
  end

  def derive_service_encryption_key(blob_encryption_key)
    raise ArgumentError, "The blob encryption_key must be at least #{GCS_ENCRYPTION_KEY_LENGTH_BYTES} bytes long" unless blob_encryption_key.bytesize >= GCS_ENCRYPTION_KEY_LENGTH_BYTES
    blob_encryption_key[0...GCS_ENCRYPTION_KEY_LENGTH_BYTES]
  end
end
