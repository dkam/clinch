class CreateForwardAuthRuleGroups < ActiveRecord::Migration[8.1]
  def change
    create_table :forward_auth_rule_groups do |t|
      t.references :forward_auth_rule, null: false, foreign_key: true
      t.references :group, null: false, foreign_key: true

      t.timestamps
    end
  end
end
