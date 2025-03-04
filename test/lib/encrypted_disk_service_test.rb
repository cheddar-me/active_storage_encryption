# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::EncryptedDiskServiceTest < ActiveSupport::TestCase
  def setup
    @storage_dir = Dir.mktmpdir
    @service = ActiveStorageEncryption::EncryptedDiskService.new(root: @storage_dir)
    @service.name = "amazing_encrypting_disk_service" # Needed for the DiskController and service lookup
    @previous_default_service = ActiveStorage::Blob.service
  end

  def teardown
    FileUtils.rm_rf(@storage_dir)
    ActiveStorage::Blob.service = @previous_default_service
  end

  def test_headers_for_direct_upload
    key = "key-1"
    k = Random.bytes(68)
    md5 = Digest::MD5.base64digest("x")
    headers = @service.headers_for_direct_upload(key, content_type: "image/jpeg", encryption_key: k, checksum: md5)
    assert_equal headers["x-active-storage-encryption-key"], Base64.strict_encode64(k)
    assert_equal headers["content-md5"], md5
  end

  def test_upload_with_checksum
    # We need to test this to make sure the checksum gets verified after decryption
    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string

    incorrect_base64_md5 = Digest::MD5.base64digest("Something completely different")
    assert_raises(ActiveStorage::IntegrityError) do
      @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k, checksum: incorrect_base64_md5)
    end
    refute @service.exist?(key)

    correct_base64_md5 = Digest::MD5.base64digest(plaintext_upload_bytes)
    assert_nothing_raised do
      @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k, checksum: correct_base64_md5)
    end
    assert @service.exist?(key)
  end

  def test_put_via_controller
    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string

    ActiveStorage::Blob.service = @service # So that the controller can find it
    b64md5 = Digest::MD5.base64digest(plaintext_upload_bytes)

    url = @service.url_for_direct_upload(key, expires_in: 60.seconds, content_type: "binary/octet-stream", content_length: plaintext_upload_bytes.bytesize, checksum: b64md5, encryption_key: k, custom_metadata: {})
    assert url.include?("/encrypted-storage/blob/")

    uri = URI.parse(url)
    # Do a super-minimalistic test on the DiskController. ActionController is actually a Rack app (or, rather: every controller action is a Rack app).
    # It can thus be called with a minimal Rack env. For the definition of "minimal", see https://github.com/rack/rack/blob/main/SPEC.rdoc#the-environment-
    rack_env = {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => uri.path,
      "QUERY_STRING" => uri.query,
      "REQUEST_METHOD" => "PUT",
      "SERVER_NAME" => uri.host,
      "rack.input" => StringIO.new(plaintext_upload_bytes),
      "CONTENT_LENGTH" => plaintext_upload_bytes.bytesize.to_s(10),
      "CONTENT_TYPE" => "binary/octet-stream",
      "HTTP_X_ACTIVE_STORAGE_ENCRYPTION_KEY" => Base64.strict_encode64(k),
      "HTTP_CONTENT_MD5" => Digest::MD5.base64digest(plaintext_upload_bytes),
      "action_dispatch.request.parameters" => {
        # The controller expects the Rails router to have injected this param by extracting
        # it from the route path
        "token" => uri.path.split("/").last
      }
    }
    action_app = ActiveStorageEncryption::EncryptedBlobsController.action(:update)
    status, _headers, _body = action_app.call(rack_env)
    assert_equal 204, status # "Accepted"

    readback_bytes = @service.download(key, encryption_key: k)
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_bytes)
  end

  def test_get_with_headers_always_succeeds
    @service.private_url_policy = :require_headers

    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    ActiveStorage::Blob.service = @service # So that the controller can find it

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    assert url.include?("/encrypted-storage/blob/")

    uri = URI.parse(url)

    # Do a super-minimalistic test on the DiskController. ActionController is actually a Rack app (or, rather: every controller action is a Rack app).
    # It can thus be called with a minimal Rack env. For the definition of "minimal", see https://github.com/rack/rack/blob/main/SPEC.rdoc#the-environment-
    rack_env = {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => uri.path,
      "QUERY_STRING" => uri.query,
      "REQUEST_METHOD" => "GET",
      "SERVER_NAME" => uri.host,
      "HTTP_X_ACTIVE_STORAGE_ENCRYPTION_KEY" => Base64.strict_encode64(k),
      "rack.input" => StringIO.new(""),
      "action_dispatch.request.parameters" => {
        # The controller expects the Rails router to have injected this param by extracting
        # it from the route path. The upload param is mapped to :encoded_token, the download param is
        # mapped to :encoded_key - likely because there was an exploit with ActiveStorage where keys
        # generated for download could be used for uploading (and thus - overwriting)
        "token" => uri.path.split("/")[-2] # For "show", the last path param is actually the filename - this is because Content-Disposition can be unreliable for download filename
      }
    }
    action_app = ActiveStorageEncryption::EncryptedBlobsController.action(:show)
    status, _headers, body = action_app.call(rack_env)

    assert_equal 200, status

    readback_bytes = (+"").b.tap do |buf|
      body.each { |chunk| buf << chunk }
    end
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_bytes)
  end

  def test_get_without_headers_succeeds_if_service_permits
    @service.private_url_policy = :stream

    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    ActiveStorage::Blob.service = @service # So that the controller can find it

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    assert url.include?("/encrypted-storage/blob/")

    uri = URI.parse(url)

    # Do a super-minimalistic test on the DiskController. ActionController is actually a Rack app (or, rather: every controller action is a Rack app).
    # It can thus be called with a minimal Rack env. For the definition of "minimal", see https://github.com/rack/rack/blob/main/SPEC.rdoc#the-environment-
    rack_env = {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => uri.path,
      "QUERY_STRING" => uri.query,
      "REQUEST_METHOD" => "GET",
      "SERVER_NAME" => uri.host,
      "rack.input" => StringIO.new(""),
      "action_dispatch.request.parameters" => {
        # The controller expects the Rails router to have injected this param by extracting
        # it from the route path. The upload param is mapped to :encoded_token, the download param is
        # mapped to :encoded_key - likely because there was an exploit with ActiveStorage where keys
        # generated for download could be used for uploading (and thus - overwriting)
        "token" => uri.path.split("/")[-2] # For "show", the last path param is actually the filename - this is because Content-Disposition can be unreliable for download filename
      }
    }
    action_app = ActiveStorageEncryption::EncryptedBlobsController.action(:show)
    status, _headers, body = action_app.call(rack_env)

    assert_equal 200, status

    readback_bytes = (+"").b.tap do |buf|
      body.each { |chunk| buf << chunk }
    end
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_bytes)
  end

  def test_generating_url_fails_if_streaming_is_off_for_the_service
    @service.private_url_policy = :disable

    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    assert_raises ActiveStorageEncryption::StreamingDisabled do
      @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    end
  end

  def test_get_without_headers_fails_if_service_does_not_permit
    @service.private_url_policy = :require_headers

    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    ActiveStorage::Blob.service = @service # So that the controller can find it

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    uri = URI.parse(url)

    # Do a super-minimalistic test on the DiskController. ActionController is actually a Rack app (or, rather: every controller action is a Rack app).
    # It can thus be called with a minimal Rack env. For the definition of "minimal", see https://github.com/rack/rack/blob/main/SPEC.rdoc#the-environment-
    rack_env = {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => uri.path,
      "QUERY_STRING" => uri.query,
      "REQUEST_METHOD" => "GET",
      "SERVER_NAME" => uri.host,
      "rack.input" => StringIO.new(""),
      # Omit x-disk-encryption-key
      "action_dispatch.request.parameters" => {
        "token" => uri.path.split("/")[-2] # For "show", the last path param is actually the filename - this is because Content-Disposition can be unreliable for download filename
      }
    }
    action_app = ActiveStorageEncryption::EncryptedBlobsController.action(:show)
    status, _headers, _body = action_app.call(rack_env)
    assert_equal 403, status
  end

  def test_upload_then_download_using_correct_key
    storage_blob_key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string

    assert_nothing_raised do
      @service.upload(storage_blob_key, StringIO.new(plaintext_upload_bytes), encryption_key: k)
    end

    assert @service.exist?(storage_blob_key)

    encrypted_file_paths = Dir.glob(@storage_dir + "/**/*.encrypted-*").sort
    readback_encrypted_bytes = File.binread(encrypted_file_paths.last)

    # Make sure the output is, indeed, encrypted
    refute_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_encrypted_bytes)

    # Readback the entire file, decrypting it
    readback_plaintext_bytes = (+"").b
    @service.download(storage_blob_key, encryption_key: k) { |bytes| readback_plaintext_bytes << bytes }
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_plaintext_bytes)

    # Test random access
    from_offset = Random.rand(0..999)
    chunk_size = Random.rand(0..1024)
    range = (from_offset..(from_offset + chunk_size))
    chunk_from_upload = plaintext_upload_bytes[range]
    assert_equal chunk_from_upload, @service.download_chunk(storage_blob_key, range, encryption_key: k)
  end

  def test_upload_requires_key_of_certain_length
    storage_blob_key = "key-1"
    k = Random.bytes(12)
    plaintext_upload_bytes = generate_random_binary_string

    assert_raises(ArgumentError) do
      @service.upload(storage_blob_key, StringIO.new(plaintext_upload_bytes), encryption_key: k)
    end
  end

  def test_upload_then_download_using_user_supplied_key_of_arbitrary_length
    storage_blob_key = "key-1"
    k = Random.new(Minitest.seed).bytes(128)
    plaintext_upload_bytes = generate_random_binary_string

    assert_nothing_raised do
      @service.upload(storage_blob_key, StringIO.new(plaintext_upload_bytes), encryption_key: k)
    end
    assert @service.exist?(storage_blob_key)

    # Readback the entire file, decrypting it
    readback_plaintext_bytes = (+"").b
    @service.download(storage_blob_key, encryption_key: k) { |bytes| readback_plaintext_bytes << bytes }
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_plaintext_bytes)
  end

  def test_upload_via_older_encryption_scheme_still_can_be_retrieved
    # We want to ensure that if we have a file encrypted using an older scheme (v1 in this case) it still gets picked
    # up by the service and decrypted correctly.
    rng = Random.new(Minitest.seed)
    encryption_key = Random.new(Minitest.seed).bytes(128)
    scheme = ActiveStorageEncryption::EncryptedDiskService::V1Scheme.new(encryption_key)
    key = rng.hex(32)

    # We need to make the path for the file manually. The Rails DiskService does it like this -
    # to make file enumeration faster:
    # def folder_for(key)
    #  [ key[0..1], key[2..3] ].join("/")
    # end
    subfolder = [key[0..1], key[2..3]].join("/")
    subfolder_path = File.join(@storage_dir, subfolder)
    FileUtils.mkdir_p(subfolder_path)

    file_path = File.join(subfolder_path, key + ".encrypted-v1")
    plaintext = rng.bytes(2048)
    File.open(file_path, "wb") do |f|
      scheme.streaming_encrypt(from_plaintext_io: StringIO.new(plaintext), into_ciphertext_io: f)
    end

    # Now read it using the service. We should get the same plaintext back.
    readback = @service.download(key, encryption_key:)
    assert_equal plaintext.bytesize, readback.bytesize
    assert_equal plaintext[32...64], readback[32...64]
  end

  def test_composes_objects
    key1 = "key-1"
    k1 = Random.bytes(68)
    buf1 = generate_random_binary_string

    key2 = "key-2"
    k2 = Random.bytes(68)
    buf2 = generate_random_binary_string

    assert_nothing_raised do
      @service.upload(key1, StringIO.new(buf1), encryption_key: k1)
      @service.upload(key2, StringIO.new(buf2), encryption_key: k2)
    end

    composed_key = "key-3"
    k3 = Random.bytes(68)
    assert_nothing_raised do
      @service.compose([key1, key2], composed_key, source_encryption_keys: [k1, k2], encryption_key: k3)
    end

    readback_composed_bytes = @service.download(composed_key, encryption_key: k3)
    assert_equal Digest::SHA256.hexdigest(buf1 + buf2), Digest::SHA256.hexdigest(readback_composed_bytes)
  end

  def test_upload_then_failing_download_with_incorrect_key
    rng = Random.new(Minitest.seed)
    storage_blob_key = "key-1"
    k1 = rng.bytes(68)
    k2 = rng.bytes(68)
    refute_equal k1, k2

    plaintext_upload_bytes = generate_random_binary_string
    assert_nothing_raised do
      @service.upload(storage_blob_key, StringIO.new(plaintext_upload_bytes), encryption_key: k1)
    end
    assert @service.exist?(storage_blob_key)

    # Readback the bytes, but use the wrong IV and key
    assert_raises(ActiveStorageEncryption::IncorrectEncryptionKey) do
      @service.download(storage_blob_key, encryption_key: k2) { |bytes| readback_plaintext_bytes << bytes }
    end

    # Readback the bytes with the correct IV and key
    readback_plaintext_bytes = (+"").b
    @service.download(storage_blob_key, encryption_key: k1) { |bytes| readback_plaintext_bytes << bytes }
    assert_equal Digest::SHA256.hexdigest(plaintext_upload_bytes), Digest::SHA256.hexdigest(readback_plaintext_bytes)
  end

  def test_non_encrypted_service_goes_through_normally
    content = generate_random_binary_string
    blob = assert_nothing_raised do
      ActiveStorage::Blob.create_and_upload!(
        io: StringIO.new(content),
        filename: "random.text",
        content_type: "text/plain",
        service_name: "test" # use regular disk service
      )
    end
    service = blob.service
    downloaded_blob = assert_nothing_raised do
      service.download(blob.key)
    end
    assert_equal content, downloaded_blob
  end

  def generate_random_binary_string(size = 17.kilobytes + 13)
    Random.bytes(size)
  end
end
