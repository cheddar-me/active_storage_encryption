# frozen_string_literal: true

require "active_storage/service/gcs_service"
require "google/cloud/storage/service"

class ActiveStorageEncryption::EncryptedGCSService < ActiveStorage::Service::GCSService
  include ActiveStorageEncryption::PrivateUrlPolicy
  GCS_ENCRYPTION_KEY_LENGTH_BYTES = 32 # google wants to get a 32 byte key

  def encrypted? = true

  def public? = false

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

  def headers_for_direct_upload(key, checksum:, encryption_key:, filename: nil, disposition: nil, content_type: nil, custom_metadata: {}, **)
    headers = {
      "Content-Type" => content_type,
      "Content-MD5" => checksum, # Not strictly required, but it ensures the file bytes we upload match what we want. This way google will error when we upload garbage.
      **gcs_encryption_key_headers(derive_service_encryption_key(encryption_key)),
      **custom_metadata_headers(custom_metadata)
    }
    headers["Content-Disposition"] = content_disposition_with(type: disposition, filename: filename) if filename

    if @config[:cache_control].present?
      headers["Cache-Control"] = @config[:cache_control]
    end
    headers
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

  def compose(source_keys, destination_key, encryption_key:, filename: nil, content_type: nil, disposition: nil, custom_metadata: {})
    # Because we will always have a different encryption_key on a blob when created and google requires us to have the same encryption_keys on all source blobs
    # we need to work this out a bit more. For now we don't need this and thus won't support it in this service.
    raise NotImplementedError, "Currently composing files is not supported"
  end

  private

  def private_url(key, expires_in:, filename:, content_type:, disposition:, encryption_key:, **remaining_options_for_streaming_url)
    if private_url_policy == :require_headers
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

      file_for(key).signed_url(**args, version: :v4)
    else
      private_url_for_streaming_via_controller(key, expires_in:, filename:, content_type:, disposition:, encryption_key:, **remaining_options_for_streaming_url)
    end
  end

  def public_url(key, filename:, encryption_key:, content_type: nil, disposition: :inline, **)
    raise "Public urls are disabled for this service"
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
