# frozen_string_literal: true
require "active_storage/service/mirror_service"

class ActiveStorageEncryption::EncryptedMirrorService < ActiveStorage::Service::MirrorService
  delegate :private_url_policy, to: :primary

  class MirrorJobWithEncryption < ActiveStorage::MirrorJob
    def perform(key, checksum:, encryption_key_token:)
      decrypted_token = decrypt_and_verify(encryption_key_token, purpose: :mirror)
      encryption_key = Base64.decode64(decrypted_token.fetch(:encryption_key))
      ActiveStorage::Blob.service.try(:mirror_with_encryption, key, checksum: checksum, encryption_key: encryption_key)
    end
  end

  def private_url_policy=(_)
    raise ArgumentError, "EncryptedMirrorService uses the private_url_policy of the primary"
  end

  def encrypted?
    true
  end

  def upload(key, io, checksum: nil, encryption_key:, **options)
    io.rewind
    if primary.try(:encrypted?)
      primary.upload(key, io, checksum: checksum, encryption_key: encryption_key, **options)
    else
      primary.upload(key, io, checksum: checksum, **options)
    end
    mirror_later_with_encryption(key, checksum: checksum, encryption_key: encryption_key, **options)
  end

  def mirror_with_encryption(key, checksum:, encryption_key:)
    instrument :mirror, key: key, checksum: checksum do
      mirrors_in_need_of_mirroring = mirrors.select { |service| !service.exist?(key) }
      return if mirrors_in_need_of_mirroring.empty?
      primary.open(key, checksum: checksum, encryption_key:) do |io|
        mirrors_in_need_of_mirroring.each do |service|
          io.rewind
          # Accommodate Services which do not accept `encryption_key`
          options = service.try(:encrypted?) ? {encryption_key: encryption_key} : {}
          service.upload(key, io, checksum: checksum, **options)
        end
      end
    end
  end

  private

  def mirror_later_with_encryption(key, checksum:, encryption_key: nil)
    encryption_key_token = ActiveStorageEncryption.token_encryptor.encrypt_and_sign(
      {
        encryption_key: Base64.strict_encode64(encryption_key)
      },
      purpose: :mirror
    )
    MirrorJobWithEncryption.perform_later(key, checksum: checksum, encryption_key_token:)
  end
end
