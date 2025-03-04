require "test_helper"

class ActiveStorageEncryptionResumableGCSUploadTest < ActiveSupport::TestCase
  setup do
    VCR.turn_off!
    WebMock.disable!
  end

  teardown do
    VCR.turn_on!
    WebMock.enable!
  end

  def bucket
    # This is a hack allowing us to use test credentials for GCP, need to change later
    service = ActiveStorage::Blob.services.fetch(:secure_uploads_online)
    @bucket ||= service.send(:bucket)
  end

  def random_filename
    random_component = Random.bytes(4).unpack1("H*")
    "test-upload-#{random_component}.bin"
  end

  def test_performs_small_resumable_upload_which_is_below_chunk_threshold
    slow_test!

    test_gcp_file = bucket.file(random_filename, skip_lookup: true)
    upload = ActiveStorageEncryption::ResumableGCSUpload.new(test_gcp_file)
    assert_nothing_raised do
      upload.stream do |sink|
        sink.write("Hello from a tiny resumable upload")
      end
    end

    # Wait for the file to get composed - this can take a little while after a resumable upload
    loop do
      break if test_gcp_file.exists?
      sleep 0.1
    end

    readback = test_gcp_file.download.read
    assert_equal "Hello from a tiny resumable upload", readback
  end

  def test_performs_sizeable_resumable_upload
    slow_test!

    rng = Random.new(Minitest.seed)
    test_gcp_file = bucket.file(random_filename, skip_lookup: true)
    upload = ActiveStorageEncryption::ResumableGCSUpload.new(test_gcp_file, content_type: "x-top-secret/binary")
    assert_nothing_raised do
      upload.stream do |sink|
        2.times do
          sink.write(rng.bytes(5 * 1024 * 1024 + 1))
        end
      end
    end

    # Wait for the file to get composed - this can take a little while after a resumable upload
    loop do
      break if test_gcp_file.exists?
      sleep 0.1
    end

    expected_size = (5 * 1024 * 1024 + 1) * 2
    assert_equal expected_size, test_gcp_file.size
    assert_equal "x-top-secret/binary", test_gcp_file.content_type
  end
end
