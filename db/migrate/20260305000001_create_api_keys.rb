class CreateApiKeys < ActiveRecord::Migration[8.1]
  def change
    create_table :api_keys do |t|
      t.references :user, null: false, foreign_key: true
      t.references :application, null: false, foreign_key: true
      t.string :name, null: false
      t.string :token_hmac, null: false
      t.datetime :expires_at
      t.datetime :last_used_at
      t.datetime :revoked_at

      t.timestamps
    end

    add_index :api_keys, :token_hmac, unique: true
    add_index :api_keys, [:user_id, :application_id]
    add_index :api_keys, :expires_at
    add_index :api_keys, :revoked_at
  end
end
