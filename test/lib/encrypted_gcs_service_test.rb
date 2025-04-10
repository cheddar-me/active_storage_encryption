# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::EncryptedGCSServiceTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    VCR.turn_off!
    WebMock.disable!
    @account = accounts(:feta_personal)
    @textfile = StringIO.new("Secure document that needs to be stored encrypted.")
    @textfile2 = StringIO.new("While being neatly organized all in a days work aat the job.")
    @gcs_service = ActiveStorage::Blob.services.fetch(:secure_uploads_online)

    @encryption_key = ActiveStorage::Blob.generate_random_encryption_key
    @gcs_key_length_range = (0...ActiveStorage::Service::EncryptedGCSService::GCS_ENCRYPTION_KEY_LENGTH_BYTES) # 32 bytes
  end

  teardown do
    VCR.turn_on!
    WebMock.enable!
  end

  test "uploads, downloads and then purges an encrypted blob" do
    slow_test!

    blob = with_image_file do |file|
      create_blob_without_uploading(
        filename: File.basename(file),
        content_type: "image/jpeg",
        encryption_key: @encryption_key,
        checksum: compute_checksum_in_chunks(file),
        byte_size: file.size
      )
    end
    url = blob.service_url_for_direct_upload(expires_in: 5.minutes.to_i)
    query_params_hash = URI.decode_www_form(URI.parse(url).query).to_h

    # Downcased header names for this test since that's what we get back from signing process.
    expected_headers = ["content-md5", "x-goog-encryption-algorithm", "x-goog-encryption-key", "x-goog-encryption-key-sha256"]
    signed_headers = query_params_hash["X-Goog-SignedHeaders"].split(";")
    assert expected_headers.all? { |header| header.in?(signed_headers) }

    assert_equal "300", query_params_hash["X-Goog-Expires"]

    headers = blob.service_headers_for_direct_upload
    should_be_headers = {
      "Content-Type" => blob.content_type,
      "Content-MD5" => blob.checksum,
      "Content-Disposition" => "inline; filename=\"cheeseboard.jpeg\"; filename*=UTF-8''cheeseboard.jpeg",
      "x-goog-encryption-algorithm" => "AES256",
      "x-goog-encryption-key" => Base64.strict_encode64(@encryption_key[@gcs_key_length_range]),
      "x-goog-encryption-key-sha256" => Digest::SHA256.base64digest(@encryption_key[@gcs_key_length_range])
    }

    assert_equal should_be_headers.sort, headers.sort

    # Do the upload to our GCS bucket
    res = with_image_file do |file|
      # Use plain old Net::HTTP here since currently version 1.4.0 of HTTPX (which is used by Faraday in our env) mangles up the file bytes before upload.
      # when passing a File object directly.
      # See https://cheddar-me.slack.com/archives/C01FEPX7PA9/p1739290056637849
      # https://gitlab.com/os85/httpx/-/issues/338
      # and https://bugs.ruby-lang.org/issues/21131
      Net::HTTP.put(URI(url), file.read, headers)
    end
    assert_equal "200", res.code

    assert @gcs_service.exist?(blob.key)

    download_headers = {
      "content-type" => blob.content_type,
      "Range" => "bytes=0-249",
      "Content-Disposition" => "inline; filename=\"cheeseboard.jpeg\"; filename*=UTF-8''cheeseboard.jpeg",
      "x-goog-encryption-algorithm" => "AES256",
      "x-goog-encryption-key" => Base64.strict_encode64(@encryption_key[@gcs_key_length_range]),
      "x-goog-encryption-key-sha256" => Digest::SHA256.base64digest(@encryption_key[@gcs_key_length_range])
    }

    download_url = blob.url(expires_in: 5.minute.to_i)

    # Do the download from our GCS bucket
    res = Net::HTTP.get_response(URI(download_url), download_headers)
    assert_equal "206", res.code # 206: partial content

    file_binary_content = with_image_file do |file|
      file.read(250)
    end
    assert_equal res.body, file_binary_content

    # Delete the file later via a job
    blob.purge_later
    perform_enqueued_jobs

    refute @gcs_service.exist?(blob.key)
  end

  test "Compose will give an unsopported error" do
    slow_test!

    blob1 = create_blob_without_uploading(
      encryption_key: @encryption_key,
      content_type: "text/plain",
      checksum: compute_checksum_in_chunks(@textfile),
      byte_size: @textfile.size,
      filename: "text1.txt",
      key: "key-1"
    )

    blob2 = create_blob_without_uploading(
      encryption_key: @encryption_key,
      content_type: "text/plain",
      checksum: compute_checksum_in_chunks(@textfile2),
      byte_size: @textfile2.size,
      filename: "text2.txt",
      key: "key-2"
    )

    # Not uploading the blobs for now, since we expect an error right away anyway.

    assert_raises NotImplementedError do
      ActiveStorage::Blob.compose(
        [blob1, blob2],
        key: "key-3",
        filename: ActiveStorage::Filename.new("composed-text.txt"),
        content_type: "text/plain",
        service_name: "secure_uploads_online",
        encryption_key: @encryption_key # all blobs need the same encryption_key to get composed, including the target blob
      )
    end
  end

  private

  def compute_checksum_in_chunks(io)
    raise ArgumentError, "io must be rewindable" unless io.respond_to?(:rewind)

    OpenSSL::Digest.new("MD5").tap do |checksum|
      read_buffer = "".b
      while io.read(5.megabytes, read_buffer)
        checksum << read_buffer
      end

      io.rewind
    end.base64digest
  end

  def create_blob_without_uploading(encryption_key:, content_type:, filename:, byte_size:, checksum:, key: nil)
    ActiveStorage::Blob.create_before_direct_upload!(
      key: key,
      filename: filename,
      byte_size: byte_size,
      checksum: checksum,
      metadata: {"identified" => true},
      content_type: content_type,
      encryption_key: encryption_key,
      service_name: "secure_uploads_online" # this will use the actual Google cloud service.
    )
  end

  def with_image_file(&blk)
    File.open("./test/fixtures/files/cheeseboard.jpeg", "rb", &blk)
  end
end
