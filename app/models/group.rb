class Group < ApplicationRecord
  has_many :user_groups, dependent: :destroy
  has_many :users, through: :user_groups
  has_many :application_groups, dependent: :destroy
  has_many :applications, through: :application_groups

  validates :name, presence: true, uniqueness: { case_sensitive: false }
  normalizes :name, with: ->(name) { name.strip.downcase }

  # Parse custom_claims JSON field
  def parsed_custom_claims
    custom_claims || {}
  end
end
