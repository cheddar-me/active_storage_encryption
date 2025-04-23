# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::EncryptedGCSServiceTest < ActiveSupport::TestCase
  def config
    {
      project_id: "sandbox-ci-25b8",
      bucket: "sandbox-ci-testing-secure-documents",
      private_url_policy: "stream",
      credentials: JSON.parse(File.read(ENV["GCS_CREDENTIALS_JSON_FILE_PATH"]))
    }
  end

  setup do
    if ENV["GCS_CREDENTIALS_JSON_FILE_PATH"].blank?
      skip "You need GCS_CREDENTIALS_JSON_FILE_PATH set in your env and it needs to point to the JSON keyfile for GCS"
    end

    @textfile = StringIO.new("Secure document that needs to be stored encrypted.")
    @textfile2 = StringIO.new("While being neatly organized all in a days work aat the job.")
    @service = ActiveStorageEncryption::EncryptedGCSService.new(**config)
    @service.name = "encrypted_gcs_service"

    @encryption_key = ActiveStorage::Blob.generate_random_encryption_key
    @gcs_key_length_range = (0...ActiveStorageEncryption::EncryptedGCSService::GCS_ENCRYPTION_KEY_LENGTH_BYTES) # 32 bytes
  end

  def run_id
    # We use a shared GCS bucket, and multiple runs of the test suite may write into it at the same time.
    # To prevent clobbering and conflicts, assign a "test run ID" and mix it into the object keys. Keep that
    # value stable across the test suite.
    @test_suite_run_id ||= SecureRandom.base36(10)
  end

  def test_encrypted_question_method
    assert @service.encrypted?
  end

  def test_forbids_private_urls_with_disabled_policy
    @service.private_url_policy = :disable

    rng = Random.new(Minitest.seed)
    key = "#{run_id}-streamed-key-#{rng.hex(4)}"
    encryption_key = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:)

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")

    assert_raises(ActiveStorageEncryption::StreamingDisabled) do
      @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key:, expires_in: 10.seconds)
    end
  end

  def test_exists
    rng = Random.new(Minitest.seed)

    key = "#{run_id}-encrypted-exists-key-#{rng.hex(4)}"
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it
    plaintext_upload_bytes = rng.bytes(1024)

    assert_nothing_raised { @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:) }
    refute @service.exist?(key + "-definitely-not-present")
    assert @service.exist?(key)
  end

  def test_generates_private_streaming_urls_with_streaming_policy
    @service.private_url_policy = :stream

    rng = Random.new(Minitest.seed)
    key = "#{run_id}-streamed-key-#{rng.hex(4)}"
    encryption_key = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:)

    # The streaming URL generation uses Rails routing, so it needs
    # ActiveStorage::Current.url_options to be set
    # We need to use a hostname for ActiveStorage which is in the Rails authorized hosts.
    # see https://stackoverflow.com/a/60573259/153886
    ActiveStorage::Current.url_options = {
      host: "www.example.com",
      protocol: "https"
    }

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, blob_byte_size: plaintext_upload_bytes.bytesize,
      filename: filename_with_sanitization, content_type: "binary/octet-stream",
      disposition: "inline", encryption_key:, expires_in: 10.seconds)
    assert url.include?("/active-storage-encryption/blob/")
  end

  def test_generates_private_urls_with_require_headers_policy
    @service.private_url_policy = :require_headers

    rng = Random.new(Minitest.seed)
    key = "#{run_id}-streamed-key-#{rng.hex(4)}"
    encryption_key = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:)

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, blob_byte_size: plaintext_upload_bytes.bytesize,
      filename: filename_with_sanitization, content_type: "binary/octet-stream",
      disposition: "inline", encryption_key:, expires_in: 240.seconds)

    query_params_hash = URI.decode_www_form(URI.parse(url).query).to_h

    # Downcased header names for this test since that's what we get back from signing process.
    expected_headers = ["x-goog-encryption-algorithm", "x-goog-encryption-key", "x-goog-encryption-key-sha256"]
    signed_headers = query_params_hash["X-Goog-SignedHeaders"].split(";")
    assert expected_headers.all? { |header| header.in?(signed_headers) }

    uri = URI(url)
    req = Net::HTTP::Get.new(uri)
    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http|
      http.request(req)
    }
    assert_equal "400", res.code

    # TODO make this a headers_for_private_download like in the s3 service
    download_headers = {
      "content-type" => "binary/octet-stream",
      "Content-Disposition" => "inline; filename=\"temp.bin\"; filename*=UTF-8''temp.bin",
      "x-goog-encryption-algorithm" => "AES256",
      "x-goog-encryption-key" => Base64.strict_encode64(encryption_key[@gcs_key_length_range]),
      "x-goog-encryption-key-sha256" => Digest::SHA256.base64digest(encryption_key[@gcs_key_length_range])
    }
    download_headers.each_pair { |key, value| req[key] = value }

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http|
      http.request(req)
    }
    assert_equal "200", res.code
    assert_equal plaintext_upload_bytes, res.body
  end

  def test_basic_gcs_readback
    rng = Random.new(Minitest.seed)

    key = "#{run_id}-encrypted-key-#{rng.hex(4)}"
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it
    plaintext_upload_bytes = rng.bytes(1024)

    assert_nothing_raised do
      @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:)
    end
    readback = @service.download(key, encryption_key:)
    assert_equal readback, plaintext_upload_bytes
  end

  def test_accepts_direct_upload_with_signature_and_headers
    rng = Random.new(Minitest.seed)

    key = "#{run_id}-encrypted-key-direct-upload-#{rng.hex(4)}"
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it
    plaintext_upload_bytes = rng.bytes(1024)

    url = @service.url_for_direct_upload(key,
      encryption_key:,
      expires_in: 5.minutes.to_i,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))

    query_params_hash = URI.decode_www_form(URI.parse(url).query).to_h

    # Downcased header names for this test since that's what we get back from signing process.
    expected_headers = ["content-md5", "x-goog-encryption-algorithm", "x-goog-encryption-key", "x-goog-encryption-key-sha256"]
    signed_headers = query_params_hash["X-Goog-SignedHeaders"].split(";")
    assert expected_headers.all? { |header| header.in?(signed_headers) }

    assert_equal "300", query_params_hash["X-Goog-Expires"]

    should_be_headers = {
      "Content-Type" => "binary/octet-stream",
      "Content-MD5" => Digest::MD5.base64digest(plaintext_upload_bytes),
      "x-goog-encryption-algorithm" => "AES256",
      "x-goog-encryption-key" => Base64.strict_encode64(encryption_key[@gcs_key_length_range]),
      "x-goog-encryption-key-sha256" => Digest::SHA256.base64digest(encryption_key[@gcs_key_length_range])
    }

    headers = @service.headers_for_direct_upload(key,
      encryption_key:,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))

    assert_equal should_be_headers.sort, headers.sort

    res = Net::HTTP.put(URI(url), plaintext_upload_bytes, headers)
    assert_equal "200", res.code

    assert_equal plaintext_upload_bytes, @service.download(key, encryption_key:)

    @service.delete(key)
    refute @service.exist?(key)
  end
end
