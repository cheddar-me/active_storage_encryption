# frozen_string_literal: true

Rails.application.routes.draw do
  mount ActiveStorageEncryption::Engine => "/active-storage-encryption"
end
