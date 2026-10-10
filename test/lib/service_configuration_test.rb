# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::ServiceConfigurationTest < ActiveSupport::TestCase
  test "every encrypted service resolves by its storage.yml name" do
    root = Dir.mktmpdir
    configurations = {
      disk: {service: "EncryptedDisk", root: root},
      mirror: {service: "EncryptedMirror", primary: :disk, mirrors: [:disk]},
      s3: {service: "EncryptedS3", bucket: "b", region: "eu-central-1", access_key_id: "x", secret_access_key: "x"}
    }

    assert_kind_of ActiveStorageEncryption::EncryptedDiskService, ActiveStorage::Service.configure(:disk, configurations)
    assert_kind_of ActiveStorageEncryption::EncryptedMirrorService, ActiveStorage::Service.configure(:mirror, configurations)
    assert_kind_of ActiveStorageEncryption::EncryptedS3Service, ActiveStorage::Service.configure(:s3, configurations)
  ensure
    FileUtils.rm_rf(root)
  end
end
