class ActiveStorageEncryption::EncryptedDiskService::V1Scheme
  def initialize(encryption_key)
    @scheme = BlockCipherKit::AES256CFBCIVScheme.new(encryption_key)
    @key_digest = Digest::SHA256.digest(encryption_key.byteslice(0, 16 + 32)) # In this scheme the IV is suffixed with the key
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    validate_key!(from_ciphertext_io)
    @scheme.streaming_decrypt(from_ciphertext_io:, into_plaintext_io:, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    into_ciphertext_io.write(@key_digest)
    @scheme.streaming_encrypt(into_ciphertext_io:, from_plaintext_io:, &blk)
  end

  def decrypt_range(from_ciphertext_io:, range:)
    validate_key!(from_ciphertext_io)
    @scheme.decrypt_range(from_ciphertext_io:, range:)
  end

  def validate_key!(io)
    key_digest_from_io = io.read(@key_digest.bytesize)
    raise ActiveStorageEncryption::IncorrectEncryptionKey unless key_digest_from_io == @key_digest
  end
end
