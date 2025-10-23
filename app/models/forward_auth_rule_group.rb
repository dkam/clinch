class ForwardAuthRuleGroup < ApplicationRecord
  belongs_to :forward_auth_rule
  belongs_to :group

  validates :forward_auth_rule_id, uniqueness: { scope: :group_id }
end