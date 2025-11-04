class RemoveRoleRelatedTablesAndColumns < ActiveRecord::Migration[8.1]
  def change
    # Remove join table first (due to foreign keys)
    drop_table :user_role_assignments if table_exists?(:user_role_assignments)

    # Remove application_roles table
    drop_table :application_roles if table_exists?(:application_roles)

    # Remove role-related columns from applications
    remove_column :applications, :role_mapping_mode, :string if column_exists?(:applications, :role_mapping_mode)
    remove_column :applications, :role_prefix, :string if column_exists?(:applications, :role_prefix)
    remove_column :applications, :role_claim_name, :string if column_exists?(:applications, :role_claim_name)
    remove_column :applications, :managed_permissions, :json if column_exists?(:applications, :managed_permissions)
  end
end
