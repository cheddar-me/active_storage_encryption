# frozen_string_literal: true

# Needed so that Rails can find our service definition. It will perform the following
# steps. Given an "EncryptedDisk" value of the `service:` key in the YAML, it will:
#
# * Force-require a file at "active_storage/service/encrypted_disk", from any path on the $LOAD_PATH
# * Instantiate a class called "ActiveStorage::Service::EncryptedDiskService"
require_relative "../../active_storage_encryption"
class ActiveStorage::Service::EncryptedS3Service < ActiveStorageEncryption::EncryptedS3Service
end
