# frozen_string_literal: true

ActiveSupport::Reloader.to_prepare do
  require "active_storage_encryption"
  ActiveStorage::Blob.send(:include, ActiveStorageEncryption::Overrides::EncryptedBlobClassMethods)
  ActiveStorage::Blob.send(:prepend, ActiveStorageEncryption::Overrides::EncryptedBlobInstanceMethods)
  ActiveStorage::Blob::Identifiable.send(:prepend, ActiveStorageEncryption::Overrides::BlobIdentifiableInstanceMethods)
  ActiveStorage::Downloader.send(:prepend, ActiveStorageEncryption::Overrides::DownloaderInstanceMethods)
end
