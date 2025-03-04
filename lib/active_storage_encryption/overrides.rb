module ActiveStorageEncryption
  module Overrides
    module EncryptedBlobClassMethods
      def self.included base
        base.class_eval do
          encrypts :encryption_key
          validates :encryption_key, presence: {message: "must be present for this service"}, if: :service_encrypted?

          class << self
            ENCRYPTION_KEY_LENGTH_BYTES = 16 + 32 # So we have enough

            def service_encrypted?(service_name)
              return false unless service_name

              service = ActiveStorage::Blob.services.fetch(service_name) do
                ActiveStorage::Blob.service
              end

              !!service&.try(:encrypted?)
            end

            def generate_random_encryption_key
              SecureRandom.bytes(ENCRYPTION_KEY_LENGTH_BYTES)
            end

            def create_before_direct_upload!(filename:, byte_size:, checksum:, content_type: nil, metadata: nil, service_name: nil, record: nil, key: nil, encryption_key: nil)
              encryption_key = service_encrypted?(service_name) ? (encryption_key || generate_random_encryption_key) : nil
              create!(key: key, filename: filename, byte_size: byte_size, checksum: checksum, content_type: content_type, metadata: metadata, service_name: service_name, encryption_key: encryption_key)
            end

            def create_and_upload!(io:, filename:, content_type: nil, metadata: nil, service_name: nil, identify: true, record: nil, key: nil, encryption_key: nil)
              create_after_unfurling!(key: key, io: io, filename: filename, content_type: content_type, metadata: metadata, service_name: service_name, identify: identify, encryption_key:).tap do |blob|
                blob.upload_without_unfurling(io)
              end
            end

            def build_after_unfurling(io:, filename:, content_type: nil, metadata: nil, service_name: nil, identify: true, record: nil, key: nil, encryption_key: nil)
              new(key: key, filename: filename, content_type: content_type, metadata: metadata, service_name: service_name, encryption_key:).tap do |blob|
                blob.unfurl(io, identify: identify)
                blob.encryption_key ||= service_encrypted?(service_name) ? (encryption_key || generate_random_encryption_key) : nil
              end
            end

            def create_after_unfurling!(io:, filename:, content_type: nil, metadata: nil, service_name: nil, identify: true, record: nil, key: nil, encryption_key: nil)
              build_after_unfurling(key: key, io: io, filename: filename, content_type: content_type, metadata: metadata, service_name: service_name, identify: identify, encryption_key:).tap(&:save!)
            end

            # Concatenate multiple blobs into a single "composed" blob.
            def compose(blobs, filename:, content_type: nil, metadata: nil, key: nil, service_name: nil, encryption_key: nil)
              raise ActiveRecord::RecordNotSaved, "All blobs must be persisted." if blobs.any?(&:new_record?)

              content_type ||= blobs.pluck(:content_type).compact.first

              new(key: key, filename: filename, content_type: content_type, metadata: metadata, byte_size: blobs.sum(&:byte_size), service_name:, encryption_key:).tap do |combined_blob|
                combined_blob.compose(blobs.pluck(:key))
                combined_blob.save!
              end
            end
          end
        end
      end
    end
  end
end

module ActiveStorageEncryption
  module Overrides
    module EncryptedBlobInstanceMethods
      def service_encrypted?
        !!service&.try(:encrypted?)
      end

      def service_url_for_direct_upload(expires_in: ActiveStorage.service_urls_expire_in)
        if service_encrypted?
          raise "No encryption key present" unless encryption_key
          service.url_for_direct_upload(key, expires_in: expires_in, content_type: content_type, content_length: byte_size, checksum: checksum, custom_metadata: custom_metadata, encryption_key: encryption_key)
        else
          super
        end
      end

      def open(tmpdir: nil, &block)
        service.open(
          key,
          encryption_key: encryption_key,
          checksum: checksum,
          verify: !composed,
          name: ["ActiveStorage-#{id}-", filename.extension_with_delimiter],
          tmpdir: tmpdir,
          &block
        )
      end

      def service_headers_for_direct_upload
        if service_encrypted?
          service.headers_for_direct_upload(key, filename: filename, content_type: content_type, content_length: byte_size, checksum: checksum, custom_metadata: custom_metadata, encryption_key: encryption_key)
        else
          super
        end
      end

      def upload_without_unfurling(io)
        if service_encrypted?
          service.upload(key, io, checksum: checksum, encryption_key: encryption_key, **service_metadata)
        else
          super
        end
      end

      # Downloads the file associated with this blob. If no block is given, the entire file is read into memory and returned.
      # That'll use a lot of RAM for very large files. If a block is given, then the download is streamed and yielded in chunks.
      def download(&block)
        if service_encrypted?
          service.download(key, encryption_key: encryption_key, &block)
        else
          super
        end
      end

      def download_chunk(range)
        if service_encrypted?
          service.download_chunk(key, range, encryption_key: encryption_key)
        else
          super
        end
      end

      def compose(keys)
        if service_encrypted?
          self.composed = true
          service.compose(keys, key, encryption_key: encryption_key, **service_metadata)
        else
          super
        end
      end

      def url(expires_in: ActiveStorage.service_urls_expire_in, disposition: :inline, filename: nil, **options)
        if service_encrypted?
          service.url(
            key, expires_in: expires_in, filename: ActiveStorage::Filename.wrap(filename || self.filename),
            encryption_key: encryption_key,
            content_type: content_type_for_serving, disposition: forced_disposition_for_serving || disposition,
            **options
          )
        else
          super
        end
      end

      # The encryption_key can be in binary and not serializabe to UTF-8 by to_json, thus we always want to
      # leave it out. This is also to better mimic how native ActiveStorage handles it.
      def serializable_hash(options = nil)
        options = if options
          options.merge(except: Array.wrap(options[:except]).concat([:encryption_key]).uniq)
        else
          {except: [:encryption_key]}
        end
        super
      end
    end
  end
end

module ActiveStorageEncryption
  module Overrides
    module BlobIdentifiableInstanceMethods
      private

      # Active storage attach() tries to identify the content_type of the file. For that it downloads a chunk.
      # Since we have an encrypted disk service which needs an encryption_key on everything, every call to it needs the encryption_key passed too.
      def download_identifiable_chunk
        if service_encrypted?
          if byte_size.positive?
            service.download_chunk(key, 0...4.kilobytes, encryption_key: encryption_key)
          else
            "".b
          end
        else
          super
        end
      end
    end
  end
end

module ActiveStorageEncryption
  module Overrides
    module DownloaderInstanceMethods
      def open(key, encryption_key: nil, checksum: nil, verify: true, name: "ActiveStorage-", tmpdir: nil)
        open_tempfile(name, tmpdir) do |file|
          download(key, file, encryption_key: encryption_key)
          verify_integrity_of(file, checksum: checksum) if verify
          yield file
        end
      end

      private

      def download(key, file, encryption_key: nil)
        if service.respond_to?(:encrypted?) && service.encrypted?
          file.binmode
          service.download(key, encryption_key: encryption_key) { |chunk| file.write(chunk) }
          file.flush
          file.rewind
        else
          super(key, file)
        end
      end
    end
  end
end
