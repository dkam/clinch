class AddForwardAuthFieldsToApplications < ActiveRecord::Migration[8.1]
  def change
    # Add ForwardAuth-specific fields
    add_column :applications, :domain_pattern, :string
    add_column :applications, :headers_config, :json, default: {}, null: false

    # Add index on domain_pattern for lookup performance
    add_index :applications, :domain_pattern, unique: true, where: "domain_pattern IS NOT NULL"
  end
end
