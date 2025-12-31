class AddPkceOptionsToApplications < ActiveRecord::Migration[8.1]
  def change
    # Add require_pkce column for confidential clients
    # Default true for new apps (secure by default), existing apps will be false
    add_column :applications, :require_pkce, :boolean, default: true, null: false

    # Set existing applications to not require PKCE (backwards compatibility)
    reversible do |dir|
      dir.up do
        execute "UPDATE applications SET require_pkce = false WHERE id > 0"
      end
    end
  end
end
