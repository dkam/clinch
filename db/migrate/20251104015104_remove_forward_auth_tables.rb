class RemoveForwardAuthTables < ActiveRecord::Migration[8.1]
  def change
    # Remove join table first (due to foreign keys)
    drop_table :forward_auth_rule_groups if table_exists?(:forward_auth_rule_groups)

    # Remove forward_auth_rules table
    drop_table :forward_auth_rules if table_exists?(:forward_auth_rules)
  end
end
