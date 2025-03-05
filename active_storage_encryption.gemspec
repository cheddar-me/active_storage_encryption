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

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  # The homepage link on rubygems.org only appears if you add homepage_uri. Just spec.homepage is not enough.
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib,test}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.add_dependency "rails", ">= 7.2.2.1"
  spec.add_dependency "block_cipher_kit", ">= 0.0.4"
  spec.add_development_dependency "sqlite3"
  spec.add_dependency "activestorage"
  spec.add_development_dependency "standard", ">= 1.35.1"
  spec.add_development_dependency "appraisal"
end
