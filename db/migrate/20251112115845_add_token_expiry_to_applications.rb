class AddTokenExpiryToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :access_token_ttl, :integer, default: 3600  # 1 hour in seconds
    add_column :applications, :refresh_token_ttl, :integer, default: 2592000  # 30 days in seconds
    add_column :applications, :id_token_ttl, :integer, default: 3600  # 1 hour in seconds
  end
end
