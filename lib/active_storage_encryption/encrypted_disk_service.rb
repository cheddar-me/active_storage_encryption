# frozen_string_literal: true

require "block_cipher_kit"

module ActiveStorageEncryption
  # Provides a local encrypted store for ActiveStorage blobs.
  # Configure it like so:
  #
  #   local_encrypted:
  #     service: EncryptedDisk
  #     root: <%= Rails.root.join("storage/encrypted") %>
  #     private_url_policy: stream
  class EncryptedDiskService < ::ActiveStorage::Service::DiskService
    include ActiveStorageEncryption::PrivateUrlPolicy

    autoload :V1Scheme, __dir__ + "/encrypted_disk_service/v1_scheme.rb"
    autoload :V2Scheme, __dir__ + "/encrypted_disk_service/v2_scheme.rb"

    FILENAME_EXTENSIONS_PER_SCHEME = {
      ".encrypted-v1" => "V1Scheme",
      ".encrypted-v2" => "V2Scheme"
    }

    # This lets the Blob encryption key methods know that this
    # storage service _must_ use encryption
    def encrypted? = true

    def initialize(public: false, **options_for_disk_storage)
      raise ArgumentError, "encrypted files cannot be served via a public URL or a CDN" if public
      super
    end

    def upload(key, io, encryption_key:, checksum: nil, **)
      instrument :upload, key: key, checksum: checksum do
        scheme = create_scheme(key, encryption_key)
        File.open(make_path_for(key), "wb") do |file|
          scheme.streaming_encrypt(from_plaintext_io: io, into_ciphertext_io: file)
        end
        ensure_integrity_of(key, checksum, encryption_key) if checksum
      end
    end

    def download(key, encryption_key:, &block)
      if block_given?
        instrument :streaming_download, key: key do
          stream key, encryption_key, &block
        end
      else
        instrument :download, key: key do
          (+"").b.tap do |buf|
            download(key, encryption_key: encryption_key) do |data|
              buf << data
            end
          end
        end
      end
    end

    def download_chunk(key, range, encryption_key:)
      instrument :download_chunk, key: key, range: range do
        scheme = create_scheme(key, encryption_key)
        File.open(path_for(key), "rb") do |file|
          scheme.decrypt_range(from_ciphertext_io: file, range:)
        end
      rescue Errno::ENOENT
        raise ActiveStorage::FileNotFoundError
      end
    end

    def url_for_direct_upload(key, expires_in:, content_type:, content_length:, checksum:, encryption_key:, custom_metadata: {})
      instrument :url, key: key do |payload|
        upload_token = ActiveStorage.verifier.generate(
          {
            key: key,
            content_type: content_type,
            content_length: content_length,
            encryption_key_sha256: Digest::SHA256.base64digest(encryption_key),
            checksum: checksum,
            service_name: name
          },
          expires_in: expires_in,
          purpose: :encrypted_put
        )

        url_helpers.encrypted_blob_put_url(upload_token, url_options).tap do |generated_url|
          payload[:url] = generated_url
        end
      end
    end

    def path_for(key) # :nodoc:
      # The extension indicates what encryption scheme the file will be using. This method
      # gets used two ways - to get a path for a new object, and to get a path for an existing object.
      # If an existing object is found, we need to return the path for the highest version of that
      # object. If we want to create one - we always return the latest one.
      glob_pattern = File.join(root, folder_for(key), key + ".encrypted-*")
      last_existing_path = Dir.glob(glob_pattern).max
      path_for_new_file = File.join(root, folder_for(key), key + FILENAME_EXTENSIONS_PER_SCHEME.keys.last)
      last_existing_path || path_for_new_file
    end

    def exist?(key)
      File.exist?(path_for(key))
    end

    def compose(source_keys, destination_key, source_encryption_keys:, encryption_key:, **)
      if source_keys.length != source_encryption_keys.length
        raise ArgumentError, "With #{source_keys.length} keys to compose there should be exactly as many source_encryption_keys, but got #{source_encryption_keys.length}"
      end
      File.open(make_path_for(destination_key), "wb") do |destination_file|
        writing_scheme = create_scheme(destination_key, encryption_key)
        writing_scheme.streaming_encrypt(into_ciphertext_io: destination_file) do |writable|
          source_keys.zip(source_encryption_keys).each do |(source_key, encryption_key_for_source)|
            File.open(path_for(source_key), "rb") do |source_file|
              reading_scheme = create_scheme(source_key, encryption_key_for_source)
              reading_scheme.streaming_decrypt(from_ciphertext_io: source_file, into_plaintext_io: writable)
            end
          end
        end
      end
    end

    def headers_for_direct_upload(key, content_type:, encryption_key:, checksum:, **)
      # Both GCP and AWS require the key to be provided in the headers, together with the
      # upload PUT request. This is not needed for the encrypted disk service, but it is
      # useful to check it does get passed to the HTTP client and then to the upload -
      # our controller extension will verify that this header is present, and fail if
      # it is not in place.
      super.merge!("x-active-storage-encryption-key" => Base64.strict_encode64(encryption_key), "content-md5" => checksum)
    end

    private

    def create_scheme(key, encryption_key_from_blob)
      # Check whether this blob already exists and which version it is.
      # path_for_key will give us the path to the existing version.
      filename_extension = File.extname(path_for(key))
      scheme_class_name = FILENAME_EXTENSIONS_PER_SCHEME.fetch(filename_extension)
      scheme_class = self.class.const_get(scheme_class_name)
      scheme_class.new(encryption_key_from_blob.b)
    end

    def private_url(key, **options)
      private_url_for_streaming_via_controller(key, **options)
    end

    def public_url(key, filename:, encryption_key:, content_type: nil, disposition: :attachment, **)
      raise "This should never be called"
    end

    def stream(key, encryption_key, &blk)
      scheme = create_scheme(key, encryption_key)
      File.open(path_for(key), "rb") do |file|
        scheme.streaming_decrypt(from_ciphertext_io: file, &blk)
      end
    rescue Errno::ENOENT
      raise ActiveStorage::FileNotFoundError
    end

    def ensure_integrity_of(key, checksum, encryption_key)
      digest = OpenSSL::Digest.new("MD5")
      stream(key, encryption_key) do |decrypted_data|
        digest << decrypted_data
      end
      unless digest.base64digest == checksum
        delete key
        raise ActiveStorage::IntegrityError
      end
    end

    def service_name
      # Normally: ActiveStorage::Service::DiskService => Disk, so it does
      # a split on "::" on the class name etc. Even though this is private,
      # it does get called from the outside (or by other ActiveStorage::Service methods).
      # Oddly it does _not_ get used in the `ActiveStorage::Configurator` to resolve
      # the class to use.
      "EncryptedDisk"
    end
  end
end
