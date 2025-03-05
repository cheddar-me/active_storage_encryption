# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::EncryptedDiskServiceTest < ActiveSupport::TestCase
  def setup
    @storage_dir = Dir.mktmpdir

    @service1 = ActiveStorageEncryption::EncryptedDiskService.new(root: @storage_dir + "/primary-encrypted")
    @service2 = ActiveStorage::Service::DiskService.new(root: @storage_dir + "/secondary-plain")
    @service3 = ActiveStorageEncryption::EncryptedDiskService.new(root: @storage_dir + "/secondary-encrypted")

    @service = ActiveStorageEncryption::EncryptedMirrorService.new(primary: @service1, mirrors: [@service2, @service3])
    @service.name = "amazing_mirror_service" # Needed for service lookup
    @previous_default_service = ActiveStorage::Blob.service

    # The EncryptedDiskService generates URLs by itself, so it needs
    # ActiveStorage::Current.url_options to be set
    # We need to use a hostname for ActiveStorage which is in the Rails authorized hosts.
    # see https://stackoverflow.com/a/60573259/153886
    ActiveStorage::Current.url_options = {
      host: "www.example.com",
      protocol: "https"
    }
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

  def test_generates_direct_upload_url_for_primary
    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string

    ActiveStorage::Blob.service = @service # So that the controller can find it
    b64md5 = Digest::MD5.base64digest(plaintext_upload_bytes)

    url = @service.url_for_direct_upload(key, expires_in: 60.seconds, content_type: "binary/octet-stream", content_length: plaintext_upload_bytes.bytesize, checksum: b64md5, encryption_key: k, custom_metadata: {})
    assert url.include?("/active-storage-encryption/blob/")
  end

  def passes_through_private_url_policy_from_primary
    @service1.private_url_policy = :disable
    assert_equal :disable, @service.private_url_policy

    @service1.private_url_policy = :stream
    assert_equal :stream, @service.private_url_policy
  end

  def test_does_not_accept_private_url_policy
    assert_raises(ArgumentError) do
      @service.private_url_policy = :stream
    end
  end

  def test_get_without_headers_succeeds_if_service_permits
    @service1.private_url_policy = :stream

    key = "key-1"
    k = Random.bytes(68)
    plaintext_upload_bytes = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext_upload_bytes), encryption_key: k)

    ActiveStorage::Blob.service = @service # So that the controller can find it

    # ActiveStorage wraps the passed filename in a wrapper thingy
    filename_with_sanitization = ActiveStorage::Filename.new("temp.bin")
    url = @service.url(key, filename: filename_with_sanitization, content_type: "binary/octet-stream", disposition: "inline", encryption_key: k, expires_in: 10.seconds)
    assert url.include?("/active-storage-encryption/blob/")
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

  def generate_random_binary_string(size = 17.kilobytes + 13)
    Random.bytes(size)
  end
end
