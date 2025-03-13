# frozen_string_literal: true

ActiveStorageEncryption::Engine.routes.draw do
  put "/blob/:token", to: "encrypted_blobs#update", as: "encrypted_blob_put"
  post "/blob/direct-uploads", to: "encrypted_blobs#create_direct_upload", as: "create_encrypted_blob_direct_upload"
  get "/blob/:token/*filename(.:format)", to: "encrypted_blob_proxy#show", as: "encrypted_blob_streaming_get"
end
