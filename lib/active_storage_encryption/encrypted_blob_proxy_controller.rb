# frozen_string_literal: true
require "serve_byte_range"

# This controller is analogous to the ActiveStorage::ProxyController
class ActiveStorageEncryption::EncryptedBlobProxyController < ActionController::Base
  include ActiveStorage::SetCurrent

  class InvalidParams < StandardError
  end

  DEFAULT_BLOB_STREAMING_DISPOSITION = "inline"

  self.etag_with_template_digest = false
  skip_forgery_protection

  # Streams the decrypted contents of an encrypted blob
  def show
    params = read_params_from_token_and_headers_for_get
    service = lookup_service(params[:service_name])
    raise InvalidParams, "#{service.name} does not allow private URLs" if service.private_url_policy == :disable

    # Test the encryption key beforehand, so that the exception does not get raised when serving the actual body
    service.download_chunk(params[:key], 0..0, encryption_key: params[:encryption_key])

    stream_blob(service:,
      key: params[:key],
      encryption_key: params[:encryption_key],
      blob_byte_size: params[:blob_byte_size],
      filename: params[:filename],
      disposition: params[:disposition] || DEFAULT_BLOB_STREAMING_DISPOSITION,
      type: params[:content_type])
  rescue ActiveStorage::FileNotFoundError
    head :not_found
  rescue InvalidParams, ActiveStorageEncryption::StreamingTokenInvalidOrExpired, ActiveSupport::MessageEncryptor::InvalidMessage, ActiveStorageEncryption::IncorrectEncryptionKey
    head :forbidden
  end

  private

  def read_params_from_token_and_headers_for_get
    token_str = params.require(:token)

    # The token params for GET / private_url download are encrypted, as they contain the object encryption key.
    token_params = ActiveStorageEncryption.token_encryptor.decrypt_and_verify(token_str, purpose: :encrypted_get).symbolize_keys
    encryption_key = Base64.decode64(token_params.fetch(:encryption_key))
    service = lookup_service(token_params.fetch(:service_name))

    # To be more like cloud services: verify presence of headers, if we were asked to (but this is optional)
    if service.private_url_policy == :require_headers
      b64_encryption_key = request.headers["x-active-storage-encryption-key"]
      raise InvalidParams, "x-active-storage-encryption-key header is missing" if b64_encryption_key.blank?
      raise InvalidParams, "Incorrect encryption key supplied via header" unless Rack::Utils.secure_compare(Base64.decode64(b64_encryption_key), encryption_key)
    end

    {
      key: token_params.fetch(:key),
      service_name: token_params.fetch(:service_name),
      disposition: token_params.fetch(:disposition),
      content_type: token_params.fetch(:content_type),
      encryption_key: Base64.decode64(token_params.fetch(:encryption_key)),
      blob_byte_size: token_params.fetch(:blob_byte_size)
    }
  end

  def lookup_service(name)
    service = ActiveStorage::Blob.services.fetch(name) { ActiveStorage::Blob.service }
    raise InvalidParams, "No ActiveStorage default service defined and service #{name.inspect} was not found" unless service
    raise InvalidParams, "#{service.name} is not providing file encryption" unless service.try(:encrypted?)
    service
  end

  def stream_blob(service:, key:, blob_byte_size:, encryption_key:, filename:, disposition:, type:)
    # The ActiveStorage::ProxyController buffers the entire response into memory
    # when serving multipart byte ranges, which is extremely inefficient. We use our own thing
    # which can actually stream from the Service directly, using byte ranges. This limits the
    # amount of data buffered to 5 megabytes. There can be a better scheme with pagewise caching
    # in tempfiles, but that's for later.
    streaming_proc = ->(client_requested_range, response_io) {
      chunk_size = 5.megabytes
      client_requested_range.begin.step(client_requested_range.end, chunk_size) do |subrange_start|
        chunk_end = subrange_start + chunk_size - 1
        subrange_end = (chunk_end > client_requested_range.end) ? client_requested_range.end : chunk_end
        range_on_service = subrange_start..subrange_end
        response_io.write(service.download_chunk(key, range_on_service, encryption_key:))
      end
    }

    # A few header things for streaming:
    # 1. We need to ensure Rack::ETag does not suddenly start buffering us, for that either
    # the ETag header or the Last-Modified header must be set. We set an ETag from the blob key,
    # so nothing to do here.
    # 2. Disable buffering for both nginx and Google Load Balancer, see
    # https://cloud.google.com/appengine/docs/flexible/how-requests-are-handled?tab=python#x-accel-buffering
    response.headers["X-Accel-Buffering"] = "no"
    # 3. Make sure Rack::Deflater does not touch our response body either, see
    # https://github.com/felixbuenemann/xlsxtream/issues/14#issuecomment-529569548
    response.headers["Content-Encoding"] = "identity"

    # Range requests use ETags to ensure that if a client goes to download a range of a resource
    # it has already has some data of, it either gets the full resource - if it changed - or
    # the bytes the client requested. An ActiveStorage blob never changes once it has been uploaded -
    # it stays on the service "just as it was" until it gets deleted, so we can reliably use the key
    # of the blob as the ETag.
    blob_etag = key.inspect # Strong ETags must be quoted
    status, headers, ranges_body = ServeByteRange.serve_ranges(request.env,
      resource_size: blob_byte_size,
      etag: blob_etag, # TODO
      resource_content_type: type,
      &streaming_proc)

    response.status = status
    headers.each { |(header, value)| response.headers[header] = value }
    self.response_body = ranges_body
  end
end
