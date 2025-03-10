# frozen_string_literal: true

require "active_storage/service/mirror_service"

class ActiveStorageEncryption::EncryptedMirrorService < ActiveStorage::Service::MirrorService
  delegate :private_url_policy, to: :primary

  class MirrorJobWithEncryption < ActiveStorage::MirrorJob
    def perform(key, checksum:, service_name:, encryption_key_token:)
      service = lookup_service(service_name)
      service.try(:mirror_with_encryption, key, checksum: checksum, encryption_key: encryption_key_from_token(encryption_key_token))
    end

    def encryption_key_from_token(encryption_key_token)
      decrypted_token = ActiveStorageEncryption.token_encryptor.decrypt_and_verify(encryption_key_token, purpose: :mirror)
      Base64.decode64(decrypted_token.fetch("encryption_key"))
    end

    def lookup_service(name)
      # This should be the name in the config, NOT the class name
      service = ActiveStorage::Blob.services.fetch(name) { ActiveStorage::Blob.service }
      raise ArgumentError, "#{service.name} is not providing file encryption" unless service.try(:encrypted?)
      service
    end
  end

  def private_url_policy=(_)
    raise ArgumentError, "EncryptedMirrorService uses the private_url_policy of the primary"
  end

  def encrypted?
    true
  end

  def upload(key, io, encryption_key:, checksum: nil, **options)
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
      primary.open(key, checksum: checksum, verify: checksum.present?, encryption_key: encryption_key) do |io|
        mirrors_in_need_of_mirroring.each do |target|
          io.rewind
          options = target.try(:encrypted?) ? {encryption_key: encryption_key} : {}
          target.upload(key, io, checksum: checksum, **options)
        end
      end
    end
  end

  def service_name
    # ActiveStorage::Service::DiskService => Disk
    # Overridden because in Rails 8 this is "self.class.name.split("::").third.remove("Service")"
    self.class.name.split("::").last.remove("Service")
  end

  private

  def mirror_later_with_encryption(key, checksum:, encryption_key: nil)
    encryption_key_token = ActiveStorageEncryption.token_encryptor.encrypt_and_sign(
      {
        encryption_key: Base64.strict_encode64(encryption_key)
      },
      purpose: :mirror
    )
    MirrorJobWithEncryption.perform_later(key, checksum: checksum, service_name:, encryption_key_token:)
  end
end
