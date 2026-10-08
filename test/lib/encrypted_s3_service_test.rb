# frozen_string_literal: true

require "test_helper"
require_relative "../support/s3_compatible_service_tests"

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

  include S3CompatibleServiceTests
end
