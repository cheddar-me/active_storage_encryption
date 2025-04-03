# frozen_string_literal: true

module ActiveStorageEncryption
  class Engine < ::Rails::Engine
    isolate_namespace ActiveStorageEncryption

    generators do
      require "generators/install_generator"
    end
  end
end
