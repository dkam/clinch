class AddRoleMappingToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :role_mapping_mode, :string, default: "disabled", null: false
    add_column :applications, :role_prefix, :string
    add_column :applications, :managed_permissions, :json, default: {}
    add_column :applications, :role_claim_name, :string, default: "roles"

    create_table :application_roles do |t|
      t.references :application, null: false, foreign_key: true
      t.string :name, null: false
      t.string :display_name
      t.text :description
      t.json :permissions, default: {}
      t.boolean :active, default: true

      t.timestamps
    end

    add_index :application_roles, [:application_id, :name], unique: true

    create_table :user_role_assignments do |t|
      t.references :user, null: false, foreign_key: true
      t.references :application_role, null: false, foreign_key: true
      t.string :source, default: "oidc" # 'oidc', 'manual', 'group_sync'
      t.json :metadata, default: {}

      t.timestamps
    end

    add_index :user_role_assignments, [:user_id, :application_role_id], unique: true
  end
end
