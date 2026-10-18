# frozen_string_literal: true

module ActiveStorageEncryption::PrivateUrlPolicy
  STREAMING_URL_FILENAME_SEGMENT = "file"

  DEFAULT_POLICY = :stream

  def initialize(private_url_policy: DEFAULT_POLICY, filename_in_streaming_url: true, **any_other_options_for_service)
    self.private_url_policy = private_url_policy.to_sym
    self.filename_in_streaming_url = filename_in_streaming_url
    super(**any_other_options_for_service)
  end

  def filename_in_streaming_url=(new_value)
    @filename_in_streaming_url = new_value
  end

  def filename_in_streaming_url?
    @filename_in_streaming_url
  end

  def private_url_policy=(new_value)
    allowed = [:disable, :require_headers, :stream]
    raise ArgumentError, "private_url_policy: must be one of #{allowed.join(",")}" unless allowed.include?(new_value.to_sym)
    @private_url_policy = new_value.to_sym
  end

  def private_url_policy
    @private_url_policy
  end

  def private_url_for_streaming_via_controller(key, expires_in:, filename:, content_type:, disposition:, encryption_key:, blob_byte_size:)
    if private_url_policy == :disable
      raise ActiveStorageEncryption::StreamingDisabled, <<~EOS
        Requested a signed GET URL for #{key.inspect} on service #{name}. This service
        has disabled presigned URLs (private_url_policy: disable), you have to use `Blob#download` instead.
      EOS
    end
    # This method requires the "blob_byte_size" because it is needed for HTTP ranges (you need to know the range of a resource),
    # The ActiveStorage::ProxyController retrieves the blob from the DB for that, but we can embed it right in the token.
    content_disposition = content_disposition_with(type: disposition, filename: filename)
    verified_key_with_expiration = ActiveStorageEncryption.token_encryptor.encrypt_and_sign(
      {
        key: key,
        disposition: content_disposition,
        encryption_key_sha256: Digest::SHA256.base64digest(encryption_key),
        content_type: content_type,
        service_name: name,
        blob_byte_size: blob_byte_size,
        encryption_key: Base64.strict_encode64(encryption_key)
      },
      expires_in: expires_in,
      purpose: :encrypted_get
    )

    # Both url_helpers and url_options are on the DiskService, but we need them here for other Services too
    url_helpers = ActiveStorageEncryption::Engine.routes.url_helpers
    url_options = ActiveStorage::Current.url_options

    if url_options.blank?
      raise ArgumentError, "Cannot generate URL for #{filename} because ActiveStorage::Current.url_options is not set"
    end

    # Request paths end up in proxy and server logs, so the path can carry a fixed segment instead.
    # The filename then travels inside the encrypted token and reaches the browser via Content-Disposition.
    url_filename = filename_in_streaming_url? ? filename : STREAMING_URL_FILENAME_SEGMENT
    url_helpers.encrypted_blob_streaming_get_url(verified_key_with_expiration, filename: url_filename, **url_options)
  end
end
