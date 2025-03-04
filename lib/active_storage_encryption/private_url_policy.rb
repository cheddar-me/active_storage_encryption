# frozen_string_literal: true

module ActiveStorageEncryption::PrivateUrlPolicy
  DEFAULT_POLICY = :stream

  def initialize(private_url_policy: DEFAULT_POLICY, **any_other_options_for_service)
    self.private_url_policy = private_url_policy.to_sym
    super(**any_other_options_for_service)
  end

  def private_url_policy=(new_value)
    allowed = [:disable, :require_headers, :stream]
    raise ArgumentError, "private_url_policy: must be one of #{allowed.join(",")}" unless allowed.include?(new_value.to_sym)
    @private_url_policy = new_value.to_sym
  end

  def private_url_policy
    @private_url_policy
  end

  def private_url_for_streaming_via_controller(key, expires_in:, filename:, content_type:, disposition:, encryption_key:)
    if private_url_policy == :disable
      raise ActiveStorageEncryption::StreamingDisabled, <<~EOS
        Requested a signed GET URL for #{key.inspect} on service #{name}. This service
        has disabled presigned URLs (private_url_policy: disable), you have to use `Blob#download` instead.
      EOS
    end

    content_disposition = content_disposition_with(type: disposition, filename: filename)
    verified_key_with_expiration = ActiveStorageEncryption.token_encryptor.encrypt_and_sign(
      {
        key: key,
        disposition: content_disposition,
        encryption_key_sha256: Digest::SHA256.base64digest(encryption_key),
        content_type: content_type,
        service_name: name,
        encryption_key: Base64.strict_encode64(encryption_key)
      },
      expires_in: expires_in,
      purpose: :encrypted_get
    )

    # Both url_helpers and url_options are on the DiskService, but we need them here for other Services too
    url_helpers = Rails.application.routes.url_helpers
    url_options = ActiveStorage::Current.url_options

    if url_options.blank?
      raise ArgumentError, "Cannot generate URL for #{filename} because ActiveStorage::Current.url_options is not set"
    end

    url_helpers.encrypted_blob_streaming_get_url(verified_key_with_expiration, filename: filename, **url_options)
  end
end
