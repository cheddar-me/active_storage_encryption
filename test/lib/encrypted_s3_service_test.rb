# frozen_string_literal: true

require "test_helper"
require "net/http"

class ActiveStorageEncryption::EncryptedS3ServiceTest < ActiveSupport::TestCase
  def config
    {
      access_key_id: ENV.fetch("AWS_ACCESS_KEY_ID"),
      secret_access_key: ENV.fetch("AWS_SECRET_ACCESS_KEY"),
      region: "eu-central-1",
      bucket: "active-storage-encryption-test-bucket"
    }
  end

  setup do
    if ENV["AWS_ACCESS_KEY_ID"].blank? || ENV["AWS_SECRET_ACCESS_KEY"].blank?
      skip "You need AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY set in your env to test the EncryptedS3Service"
    end
  end

  setup do
    require "active_storage/service/s3_service"
    @service = ActiveStorageEncryption::EncryptedS3Service.new(**config)
    @service.name = "amazing_encrypting_s3_service" # Needed for the DiskController and service lookup
  end

  def run_id
    # We use a shared S3 bucket, and multiple runs of the test suite may write into it at the same time.
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
    k = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")

    assert_raises(ActiveStorageEncryption::StreamingDisabled) do
      @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    end
  end

  def test_generates_private_streaming_urls_with_streaming_policy
    @service.private_url_policy = :stream

    rng = Random.new(Minitest.seed)
    key = "#{run_id}-streamed-key-#{rng.hex(4)}"
    k = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

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
      disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    assert url.include?("/active-storage-encryption/blob/")
  end

  def test_generates_private_urls_with_require_headers_policy
    @service.private_url_policy = :require_headers

    rng = Random.new(Minitest.seed)
    key = "#{run_id}-streamed-key-#{rng.hex(4)}"
    k = Random.bytes(68)
    plaintext_upload_bytes = rng.bytes(425)
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, blob_byte_size: plaintext_upload_bytes.bytesize,
      filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 240.seconds)

    assert url.include?("x-amz-server-side-encryption-customer-algorithm")
    refute url.include?("x-amz-server-side-encryption-customer-key=") # The key should not be in the URL

    uri = URI(url)
    req = Net::HTTP::Get.new(uri)
    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http|
      http.request(req)
    }
    assert_equal "400", res.code

    headers = @service.headers_for_private_download(key, encryption_key: k)
    headers.each_pair do |h, v|
      req[h] = v
    end

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http|
      http.request(req)
    }
    assert_equal "200", res.code
    assert_equal plaintext_upload_bytes, res.body
  end

  def test_s3_config_sane_and_works_with_stock_service
    # maybe remove later
    stock_s3_service = ActiveStorage::Service::S3Service.new(**config)
    rng = Random.new(Minitest.seed)
    key = "#{run_id}-unencrypted-key-#{rng.hex(4)}"
    plaintext_upload_bytes = rng.bytes(1024)
    assert_nothing_raised do
      stock_s3_service.upload(key, StringIO.new(plaintext_upload_bytes))
    end
    readback = stock_s3_service.download(key)
    assert_equal readback, plaintext_upload_bytes
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

  def test_basic_s3_readback
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

  def test_s3_upload_requiring_multipart
    rng = Random.new(Minitest.seed)
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it

    # The minimum multipart part size is 5MB
    multipart_threshold = 1024 * 1024 * 5
    total_size = multipart_threshold + 3
    plaintext_upload_bytes = rng.bytes(total_size)

    key = "#{run_id}-encrypted-key-#{rng.hex(4)}"
    service_with_smaller_part_size = ActiveStorageEncryption::EncryptedS3Service.new(**config, upload: {multipart_threshold:})
    assert_nothing_raised do
      service_with_smaller_part_size.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key:)
    end

    readback = service_with_smaller_part_size.download(key, encryption_key:)
    assert_equal total_size, readback.bytesize
  end

  def test_accepts_direct_upload_with_signature_and_headers
    rng = Random.new(Minitest.seed)

    key = "#{run_id}-encrypted-key-direct-upload-#{rng.hex(4)}"
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it
    plaintext_upload_bytes = rng.bytes(1024)

    url = @service.url_for_direct_upload(key,
      encryption_key:,
      expires_in: 1.minute,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))
    headers = @service.headers_for_direct_upload(key,
      encryption_key:,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))

    refute url.include?("x-amz-server-side-encryption-customer-key=") # The key should not be in the URL
    assert url.include?("x-amz-server-side-encryption-customer-key-md5=") # The checksum must be in the URL

    res = Net::HTTP.put(URI(url), plaintext_upload_bytes, headers)
    assert_equal "200", res.code

    assert_equal plaintext_upload_bytes, @service.download(key, encryption_key:)
  end

  def test_rejects_direct_upload_if_client_manipulates_the_encryption_key
    skip "Currently does not work, investigate"

    rng = Random.new(Minitest.seed)

    key = "#{run_id}-encrypted-key-direct-upload-#{rng.hex(4)}"
    encryption_key = rng.bytes(47) # Make it bigger than required, to ensure the service truncates it
    plaintext_upload_bytes = rng.bytes(1024)

    url = @service.url_for_direct_upload(key,
      encryption_key:,
      expires_in: 1.minute,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))
    headers = @service.headers_for_direct_upload(key,
      encryption_key:,
      content_type: "binary/octet-stream",
      content_length: plaintext_upload_bytes.bytesize,
      checksum: Digest::MD5.base64digest(plaintext_upload_bytes))

    # Replace the key and its checksum
    other_key = Random.bytes(32)
    fake_headers = headers.merge({
      "x-amz-server-side-encryption-customer-key" => Base64.strict_encode64(other_key),
      "x-amz-server-side-encryption-customer-key-MD5" => Digest::MD5.base64digest(other_key)
    })
    res = Net::HTTP.put(URI(url), plaintext_upload_bytes, fake_headers)
    refute_equal "200", res.code
  end

  # Read the objects from something slow, so that threads may switch between one another
  class SnoozyStringIO < StringIO
    def read(n = nil, outbuf = nil)
      sleep(rand((0.1..0.2)))
      super
    end
  end

  def test_uploads_correctly_across_multiple_threads
    # Due to a hack that we are applying to reuse most of the stock S3Service, we
    # temporarily override @upload_options on the service when an upload is in progress.
    # This must be done in a thread-local manner, otherwise some uploads may, potentially,
    # get uploaded with the wrong encryption key - belonging to an upload from a different
    # thread. While a test like this is by no means exhaustive, it should reveal this
    # race condition if it occurs.
    rng = Random.new(Minitest.seed)
    objects = 12.times.map do |n|
      key = "#{run_id}-threaded-upload-#{n}-#{rng.hex(4)}"
      encryption_key = rng.bytes(32)
      bytes = rng.bytes(512)
      {key:, encryption_key:, io: SnoozyStringIO.new(bytes)}
    end

    threads = objects.map do |o|
      Thread.new do
        @service.upload(o.fetch(:key), o.fetch(:io), encryption_key: o.fetch(:encryption_key))
      end
    end
    threads.map(&:join)

    objects.each do |o|
      readback = @service.download(o.fetch(:key), encryption_key: o.fetch(:encryption_key))
      assert_equal o.fetch(:io).string, readback
    end
  end

  def test_composes_objects
    rng = Random.new(Minitest.seed)

    key1 = "#{run_id}-to-compose-key-1-#{rng.hex(4)}"
    k1 = rng.bytes(68)
    buf1 = rng.bytes(1024 * 7)

    key2 = "#{run_id}-to-compose-key-2-#{rng.hex(4)}"
    k2 = rng.bytes(68)
    buf2 = rng.bytes(1024 * 3)

    assert_nothing_raised do
      @service.upload(key1, StringIO.new(buf1), encryption_key: k1)
      @service.upload(key2, StringIO.new(buf2), encryption_key: k2)
    end

    composed_key = "#{run_id}-composed-key-3-#{rng.hex(4)}"
    k3 = Random.bytes(68)
    assert_nothing_raised do
      @service.compose([key1, key2], composed_key, source_encryption_keys: [k1, k2], encryption_key: k3, content_type: "binary/octet-stream")
    end

    readback_composed_bytes = @service.download(composed_key, encryption_key: k3)
    assert_equal Digest::SHA256.hexdigest(buf1 + buf2), Digest::SHA256.hexdigest(readback_composed_bytes)
  end
end
