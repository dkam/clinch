class ApplicationGroup < ApplicationRecord
  belongs_to :application
  belongs_to :group

  validates :application_id, uniqueness: {scope: :group_id}

  after_commit :bust_forward_auth_cache

  private

  def bust_forward_auth_cache
    Rails.application.config.forward_auth_cache&.delete("fa_apps")
  end
end
