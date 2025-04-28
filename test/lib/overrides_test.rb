# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::OverridesTest < ActiveSupport::TestCase
  setup do
  end

  def test_encryption_key_is_set_on_encrypted_service_before_saving
    blob = ActiveStorage::Blob.new(
      key: "yoyo",
      filename: "test.txt",
      byte_size: 10,
      checksum: "abab",
      metadata: {"identified" => true},
      content_type: "text/plain",
      encryption_key: "blabla",
      service_name: "encrypted_disk"
    )

    assert blob.valid?

    blob.encryption_key = nil

    refute blob.valid?
    assert_equal ["Encryption key must be present for this service"], blob.errors.full_messages
  end

  def test_attach_uploads_encrypted_blob
    require 'pry'; binding.pry

  end
end
