# frozen_string_literal: true

class User < ApplicationRecord
  has_one_attached :file, service: :encrypted_disk
end
