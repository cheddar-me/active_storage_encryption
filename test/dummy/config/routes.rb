Rails.application.routes.draw do
  mount ActiveStorageEncryption::Engine => "/active-storage-encryption"
end
