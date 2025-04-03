# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module ActiveStorageEncryption
  # The generator is used to install ActiveStorageEncryption. It adds the `encryption_key`
  # column to ActiveStorage::Blob.
  # Run it with `bin/rails g active_storage_encryption:install` in your console.
  class InstallGenerator < Rails::Generators::Base
    include ActiveRecord::Generators::Migration

    source_paths << File.join(File.dirname(__FILE__, 2))

    # Generates monolithic migration file that contains all database changes.
    def create_migration_file
      # Adding a new migration to the gem is then just adding a file.
      migration_file_paths_in_order = Dir.glob(__dir__ + "/*.rb.erb").sort
      migration_file_paths_in_order.each do |migration_template_path|
        untemplated_migration_filename = File.basename(migration_template_path).gsub(/\.erb$/, "")
        migration_template(migration_template_path, File.join(db_migrate_path, untemplated_migration_filename))
      end
    end
  end
end
