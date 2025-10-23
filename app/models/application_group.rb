class ApplicationGroup < ApplicationRecord
  belongs_to :application
  belongs_to :group

  validates :application_id, uniqueness: { scope: :group_id }
end
