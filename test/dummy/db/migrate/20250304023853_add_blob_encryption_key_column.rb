# frozen_string_literal: true

class AddBlobEncryptionKeyColumn < ActiveRecord::Migration[7.2]
  def change
    add_column :active_storage_blobs, :encryption_key, :string
  end
end
