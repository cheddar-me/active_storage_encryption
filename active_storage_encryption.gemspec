# frozen_string_literal: true

require_relative "lib/active_storage_encryption/version"

Gem::Specification.new do |spec|
  spec.name = "active_storage_encryption"
  spec.version = ActiveStorageEncryption::VERSION
  spec.authors = ["Julik Tarkhanov", "Sebastian van Hesteren"]
  spec.email = ["me@julik.nl"]
  spec.homepage = "https://github.com/cheddar-me/active_storage_encryption"
  spec.summary = "Customer-supplied encryption key support for ActiveStorage blobs."
  spec.description = "Adds customer-supplied encryption keys to storage services."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  # The homepage link on rubygems.org only appears if you add homepage_uri. Just spec.homepage is not enough.
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Do not remove any files from the gemspec - tests are useful because people can read them
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0")
  end

  spec.add_dependency "rails", ">= 7.2.2.1"
  spec.add_dependency "block_cipher_kit", ">= 0.0.4"
  spec.add_dependency "serve_byte_range", "~> 1.0"
  spec.add_dependency "activestorage"

  # Testing with cloud services
  spec.add_development_dependency "aws-sdk-s3"
  spec.add_development_dependency "net-http"
  spec.add_development_dependency "google-cloud-storage"

  # Code formatting, linting and testing
  spec.add_development_dependency "sqlite3"
  spec.add_development_dependency "standard", ">= 1.35.1"
  spec.add_development_dependency "appraisal"
  spec.add_development_dependency "magic_frozen_string_literal"
  spec.add_development_dependency "rake"
end
