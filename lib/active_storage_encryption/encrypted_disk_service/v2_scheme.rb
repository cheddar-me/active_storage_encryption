# This scheme uses GCM encryption with CTR-based random access. The auth tag is stored
# at the end of the message. The message is prefixed by a SHA2 digest of the encryption key.
class ActiveStorageEncryption::EncryptedDiskService::V2Scheme
  def initialize(encryption_key)
    @scheme = BlockCipherKit::AES256GCMScheme.new(encryption_key)
    @key_digest = Digest::SHA256.digest(encryption_key.byteslice(0, 32)) # In this scheme just the key is used
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    check_key!(from_ciphertext_io)
    @scheme.streaming_decrypt(from_ciphertext_io:, into_plaintext_io:, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    # See check_key! for rationale. We need a fast KVC (key validation code)
    # to refuse the download if we know the key is incorrect.
    into_ciphertext_io.write(@key_digest)
    @scheme.streaming_encrypt(into_ciphertext_io:, from_plaintext_io:, &blk)
  end

  def decrypt_range(from_ciphertext_io:, range:)
    check_key!(from_ciphertext_io)
    @scheme.decrypt_range(from_ciphertext_io:, range:)
  end

  private def check_key!(io)
    # We need a fast KCV (key check value) to refuse the download
    # if we know the key is incorrect. We can't use the auth tag from GCM
    # because it can only be computed if the entirety of the ciphertext has been read by the
    # cipher - and we want random access. We could use a HMAC(encryption_key, auth_tag) at the
    # tail of ciphertext to achieve the same, but that would require streaming_decrypt to seek inside
    # the ciphertext IO to read the tail of the file - which we don't want to require.
    #
    # Besides, we want to not tie up server resources if we know
    # that the furnished encryption key is incorrect. So: a KVC.
    #
    # We store the SHA2 value of the encryption key at the start of the ciphertext. We assume that the encryption
    # key will be generated randomly and will be very high-entropy, so the only attack strategy for it is brute-force.
    # Brute-force is keyspace / hashrate, as explained here: https://stackoverflow.com/questions/4764026/how-many-sha256-hashes-can-a-modern-computer-compute
    # which, for our key of 32 bytes, gives us this calculation to find out the number of years to crack this SHA on
    # a GeForce 2080Ti (based on https://hashcat.net/forum/thread-10185.html):
    # ((256 ** 32) / (7173 * 1000 * 1000)) / 60 / 60 / 24 / 365
    # which is
    # 511883878862512581460395486615240253212171357229849212045742
    # This is quite some years. So storing the digest of the key is reasonably safe.
    key_digest_from_io = io.read(@key_digest.bytesize)
    raise ActiveStorageEncryption::IncorrectEncryptionKey unless key_digest_from_io == @key_digest
  end
end
