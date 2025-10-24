class ApplicationRole < ApplicationRecord
  belongs_to :application
  has_many :user_role_assignments, dependent: :destroy
  has_many :users, through: :user_role_assignments

  validates :name, presence: true, uniqueness: { scope: :application_id }
  validates :display_name, presence: true

  scope :active, -> { where(active: true) }

  def user_has_role?(user)
    user_role_assignments.exists?(user: user)
  end

  def assign_to_user!(user, source: 'oidc', metadata: {})
    user_role_assignments.find_or_create_by!(user: user) do |assignment|
      assignment.source = source
      assignment.metadata = metadata
    end
  end

  def remove_from_user!(user)
    assignment = user_role_assignments.find_by(user: user)
    assignment&.destroy
  end
end