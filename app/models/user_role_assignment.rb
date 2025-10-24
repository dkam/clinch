class UserRoleAssignment < ApplicationRecord
  belongs_to :user
  belongs_to :application_role

  validates :user, uniqueness: { scope: :application_role }
  validates :source, inclusion: { in: %w[oidc manual group_sync] }

  scope :oidc_managed, -> { where(source: 'oidc') }
  scope :manually_assigned, -> { where(source: 'manual') }
  scope :group_synced, -> { where(source: 'group_sync') }

  def sync_from_oidc?
    source == 'oidc'
  end
end