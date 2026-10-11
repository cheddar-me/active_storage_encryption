# frozen_string_literal: true

require "test_helper"
require_relative "../support/s3_compatible_service_tests"

class ActiveStorageEncryption::EncryptedS3ServiceTest < ActiveSupport::TestCase
  ENV_VARS = %w[AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_S3_BUCKET AWS_S3_REGION]

  def config
    {
      access_key_id: ENV.fetch("AWS_ACCESS_KEY_ID"),
      secret_access_key: ENV.fetch("AWS_SECRET_ACCESS_KEY"),
      region: ENV.fetch("AWS_S3_REGION"),
      bucket: ENV.fetch("AWS_S3_BUCKET")
    }
  end

  setup do
    if ENV_VARS.any? { |v| ENV[v].blank? }
      skip "You need #{ENV_VARS.join(", ")} set in your env to test the EncryptedS3Service"
    end
  end

  include S3CompatibleServiceTests
end
