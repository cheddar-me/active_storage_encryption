Rails.application.routes.draw do
  mount ActiveStorageEncryption::Engine => "/active_storage_encryption"
end
