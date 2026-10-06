# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::EncryptedS3ServiceExistenceTest < ActiveSupport::TestCase
  setup do
    require "active_storage/service/s3_service"
    @service = ActiveStorageEncryption::EncryptedS3Service.new(
      bucket: "bucket", region: "eu-central-1", access_key_id: "x", secret_access_key: "x", stub_responses: true
    )
  end

  test "an encrypted object exists when AWS refuses the keyless read with InvalidRequest" do
    @service.client.client.stub_responses(:get_object, "InvalidRequest")

    assert @service.exist?("key")
  end

  test "an encrypted object exists when an S3-compatible store refuses the keyless read with InvalidArgument" do
    @service.client.client.stub_responses(:get_object, "InvalidArgument")

    assert @service.exist?("key")
  end

  test "a missing object does not exist" do
    @service.client.client.stub_responses(:get_object, "NoSuchKey")

    assert_not @service.exist?("key")
  end
end
