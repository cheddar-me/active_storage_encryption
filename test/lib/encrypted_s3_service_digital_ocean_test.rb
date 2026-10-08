# frozen_string_literal: true

require "test_helper"
require_relative "../support/s3_compatible_service_tests"

class ActiveStorageEncryption::EncryptedS3ServiceDigitalOceanTest < ActiveSupport::TestCase
  ENV_VARS = %w[DO_SPACES_ACCESS_KEY_ID DO_SPACES_SECRET_ACCESS_KEY DO_SPACES_BUCKET]

  def config
    region = ENV["DO_SPACES_REGION"].presence || "fra1"
    {
      access_key_id: ENV.fetch("DO_SPACES_ACCESS_KEY_ID"),
      secret_access_key: ENV.fetch("DO_SPACES_SECRET_ACCESS_KEY"),
      region:,
      endpoint: "https://#{region}.digitaloceanspaces.com",
      bucket: ENV.fetch("DO_SPACES_BUCKET")
    }
  end

  setup do
    if ENV_VARS.any? { |v| ENV[v].blank? }
      skip "You need #{ENV_VARS.join(", ")} set in your env to test the EncryptedS3Service against DigitalOcean Spaces"
    end
  end

  include S3CompatibleServiceTests
end
