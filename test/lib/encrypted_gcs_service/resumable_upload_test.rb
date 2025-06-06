require "test_helper"

class ActiveStorageEncryptionResumableGCSUploadTest < ActiveSupport::TestCase
  def bucket
    @bucket ||= begin
      config = {
        project_id: "sandbox-ci-25b8",
        bucket: "sandbox-ci-testing-secure-documents",
        private_url_policy: "stream"
      }
      service = ActiveStorageEncryption::EncryptedGCSService.new(**config)
      service.send(:bucket)
    end
  end

  def random_filename
    random_component = Random.bytes(4).unpack1("H*")
    "test-upload-#{random_component}.bin"
  end

  def test_performs_small_resumable_upload_which_is_below_chunk_threshold
    test_gcp_file = bucket.file(random_filename, skip_lookup: true)
    upload = ActiveStorageEncryption::EncryptedGCSService::ResumableUpload.new(test_gcp_file)
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
    rng = Random.new(Minitest.seed)
    test_gcp_file = bucket.file(random_filename, skip_lookup: true)
    upload = ActiveStorageEncryption::EncryptedGCSService::ResumableUpload.new(test_gcp_file, content_type: "x-top-secret/binary")
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
