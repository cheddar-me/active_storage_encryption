# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryptionEncryptedBlobProxyControllerTest < ActionDispatch::IntegrationTest
  setup do
    @storage_dir = Dir.mktmpdir
    @other_storage_dir = Dir.mktmpdir
    @service = ActiveStorageEncryption::EncryptedDiskService.new(root: @storage_dir, private_url_policy: "stream")
    @service.name = "amazing_encrypting_disk_service" # Needed for the controller and service lookup

    # Hack: sneakily add our service to them configurations
    # ActiveStorage::Blob.services.send(:services)["amazing_encrypting_disk_service"] = @service

    # We need to set our service as the default, because the controller does lookup from the application config -
    # which does not include the service we define here
    @previous_default_service = ActiveStorage::Blob.service
    @previous_services = ActiveStorage::Blob.services

    # To catch potential issues where something goes to the default service by mistake, let's set a
    # different Service as the default
    @non_encrypted_default_service = ActiveStorage::Service::DiskService.new(root: @other_storage_dir)
    ActiveStorage::Blob.service = @non_encrypted_default_service
    ActiveStorage::Blob.services = {@service.name => @service} # That too

    # This needs to be set
    ActiveStorageEncryption::Engine.routes.default_url_options = {host: "www.example.com"}

    # We need to use a hostname for ActiveStorage which is in the Rails authorized hosts.
    # see https://stackoverflow.com/a/60573259/153886
    ActiveStorage::Current.url_options = {
      host: "www.example.com",
      protocol: "https"
    }
    freeze_time # For testing expiring tokens
    https! # So that all requests are simulated as SSL
  end

  def teardown
    unfreeze_time
    ActiveStorage::Blob.service = @previous_default_service
    ActiveStorage::Blob.services = @previous_services
    FileUtils.rm_rf(@storage_dir)
    FileUtils.rm_rf(@other_storage_dir)
  end

  def engine_routes
    ActiveStorageEncryption::Engine.routes.url_helpers
  end

  test "show() serves the complete decrypted blob body" do
    rng = Random.new(Minitest.seed)
    plaintext = rng.bytes(512)

    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(plaintext), content_type: "x-office/severance", filename: "secret.bin", service_name: @service.name)
    assert blob.encryption_key

    streaming_url = blob.url(disposition: "inline") # This generates a URL with the byte size
    get streaming_url

    assert_response :success
    assert_equal "x-office/severance", response.headers["content-type"]
    assert_equal blob.key.inspect, response.headers["etag"]
    assert_equal plaintext, response.body
  end

  test "show() serves a blob of 0 size" do
    Random.new(Minitest.seed)
    plaintext = "".b

    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(plaintext), content_type: "x-office/severance", filename: "secret.bin", service_name: @service.name)
    assert blob.encryption_key

    streaming_url = blob.url(disposition: "inline") # This generates a URL with the byte size
    get streaming_url

    assert_response :success
    assert response.body.empty?
  end

  test "show() returns a 404 when the blob no longer exists on the service" do
    Random.new(Minitest.seed)
    plaintext = "hello"

    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(plaintext), content_type: "x-office/severance", filename: "secret.bin", service_name: @service.name)
    assert blob.encryption_key

    streaming_url = blob.url(disposition: "inline") # This generates a URL with the byte size
    blob.service.delete(blob.key)

    get streaming_url

    assert_response :not_found
  end

  test "show() serves HTTP ranges" do
    rng = Random.new(Minitest.seed)
    plaintext = rng.bytes(5.megabytes + 13)

    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(plaintext), content_type: "x-office/severance", filename: "secret.bin", service_name: @service.name)
    assert blob.encryption_key

    streaming_url = blob.url(disposition: "inline") # This generates a URL with the byte size
    get streaming_url, headers: {"Range" => "bytes=0-0"}

    assert_response :partial_content
    assert_equal "1", response.headers["content-length"]
    assert_equal "bytes 0-0/5242893", response.headers["content-range"]
    assert_equal "x-office/severance", response.headers["content-type"]
    assert_equal plaintext[0..0], response.body

    get streaming_url, headers: {"Range" => "bytes=1-2"}

    assert_response :partial_content
    assert_equal "2", response.headers["content-length"]
    assert_equal "bytes 1-2/5242893", response.headers["content-range"]
    assert_equal "x-office/severance", response.headers["content-type"]
    assert_equal plaintext[1..2], response.body

    get streaming_url, headers: {"Range" => "bytes=1-2,8-10,12-23"}

    assert_response :partial_content
    assert response.headers["content-type"].start_with?("multipart/byteranges; boundary=")
    assert_nil response.headers["content-range"]
    assert_equal 350, response.body.bytesize

    get streaming_url, headers: {"Range" => "bytes=99999999999999999-99999999999999999"}
    assert_response :range_not_satisfiable
  end

  test "show() refuses a request which goes to a non-encrypted Service" do
    rng = Random.new(Minitest.seed)

    key = SecureRandom.base36(12)
    encryption_key = rng.bytes(32)
    plaintext = rng.bytes(512)
    @service.upload(key, StringIO.new(plaintext).binmode, encryption_key: encryption_key)

    streaming_url = @service.url(key, encryption_key: encryption_key, filename: ActiveStorage::Filename.new("private.doc"),
      expires_in: 30.seconds, disposition: "inline", content_type: "x-office/severance",
      blob_byte_size: plaintext.bytesize)

    # Sneak in a non-encrypted service under the same key
    ActiveStorage::Blob.services[@service.name] = @non_encrypted_default_service

    get streaming_url
    assert_response :forbidden
  end

  test "show() refuses a request which has an incorrect encryption key" do
    rng = Random.new(Minitest.seed)

    key = SecureRandom.base36(12)
    encryption_key = rng.bytes(32)
    plaintext = rng.bytes(512)
    @service.upload(key, StringIO.new(plaintext).binmode, encryption_key: encryption_key)

    another_encryption_key = rng.bytes(32)
    refute_equal encryption_key, another_encryption_key

    streaming_url = @service.url(key, encryption_key: another_encryption_key,
      filename: ActiveStorage::Filename.new("private.doc"), expires_in: 30.seconds,
      disposition: "inline", content_type: "x-office/severance", blob_byte_size: plaintext.bytesize)
    get streaming_url

    assert_response :forbidden
  end

  test "show() refuses a request with a garbage token" do
    get engine_routes.encrypted_blob_streaming_get_path(token: "garbage", filename: "exfil.bin")
    assert_response :forbidden
  end

  test "show() refuses a request with a token that has been encrypted using an incorrect encryption key" do
    https!
    rng = Random.new(Minitest.seed)
    encryptor_key = rng.bytes(32)
    other_encryptor = ActiveStorageEncryption::TokenEncryptor.new(encryptor_key, url_safe: encryptor_key)

    key = SecureRandom.base36(12)
    encryption_key = rng.bytes(32)
    @service.upload(key, StringIO.new(rng.bytes(512)).binmode, encryption_key: encryption_key)

    streaming_url = ActiveStorageEncryption.stub(:token_encryptor, -> { other_encryptor }) do
      @service.url(key, encryption_key: encryption_key,
        filename: ActiveStorage::Filename.new("private.doc"), expires_in: 3.seconds,
        disposition: "inline", content_type: "binary/octet-stream",
        blob_byte_size: 512)
    end

    get streaming_url
    assert_response :forbidden
  end

  test "show() refuses a request with a token that has expired" do
    rng = Random.new(Minitest.seed)

    key = SecureRandom.base36(12)
    encryption_key = rng.bytes(32)
    @service.upload(key, StringIO.new(rng.bytes(512)).binmode, encryption_key: encryption_key)

    streaming_url = @service.url(key, encryption_key: encryption_key,
      filename: ActiveStorage::Filename.new("private.doc"), expires_in: 3.seconds,
      disposition: "inline", content_type: "binary/octet-stream",
      blob_byte_size: 512)
    travel 5.seconds

    get streaming_url
    assert_response :forbidden
  end

  test "show() requires headers if the private_url_policy of the service is set to :require_headers" do
    rng = Random.new(Minitest.seed)

    key = SecureRandom.base36(12)
    encryption_key = rng.bytes(32)
    plaintext = rng.bytes(512)
    @service.upload(key, StringIO.new(plaintext).binmode, encryption_key: encryption_key)

    # The policy needs to be set before we generate the token (the token includes require_headers)
    @service.private_url_policy = :require_headers
    streaming_url = @service.url(key, encryption_key: encryption_key,
      filename: ActiveStorage::Filename.new("private.doc"), expires_in: 30.seconds, disposition: "inline",
      content_type: "x-office/severance", blob_byte_size: plaintext.bytesize)

    get streaming_url
    assert_response :forbidden # Without headers

    get streaming_url, headers: {"HTTP_X_ACTIVE_STORAGE_ENCRYPTION_KEY" => Base64.strict_encode64(encryption_key)}
    assert_response :success
    assert_equal "x-office/severance", response.headers["content-type"]
    assert_equal plaintext, response.body
  end

  test "show() refuses a request if the service no longer permits private URLs, even if the URL was generated when it used to permit them" do
    rng = Random.new(Minitest.seed)

    SecureRandom.base36(12)
    plaintext = rng.bytes(512)

    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(plaintext), content_type: "x-office/severance", filename: "secret.bin", service_name: @service.name)
    assert blob.encryption_key
    streaming_url = blob.url(disposition: "inline", content_type: "x-office/severance")

    @service.private_url_policy = :disable

    get streaming_url
    assert_response :forbidden # Without headers

    get streaming_url, headers: {"HTTP_X_ACTIVE_STORAGE_ENCRYPTION_KEY" => Base64.strict_encode64(blob.encryption_key)}
    assert_response :forbidden # With headers
  end
end
