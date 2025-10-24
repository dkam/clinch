class AddClientSecretHashToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :client_secret_hash, :string
    remove_column :applications, :client_secret, :string
  end
end
