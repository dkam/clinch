class AddAuthFieldsToUsers < ActiveRecord::Migration[8.1]
  def change
    add_column :users, :admin, :boolean, default: false, null: false
    add_column :users, :totp_secret, :string
    add_column :users, :totp_required, :boolean, default: false, null: false
    add_column :users, :backup_codes, :text
    add_column :users, :status, :integer, default: 0, null: false

    add_index :users, :status
  end
end
