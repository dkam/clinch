class CreateOidcRefreshTokens < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_refresh_tokens do |t|
      t.string :token_digest, null: false  # BCrypt hashed token
      t.references :application, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.references :oidc_access_token, null: false, foreign_key: true
      t.string :scope
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.integer :token_family_id  # For token rotation detection

      t.timestamps
    end

    add_index :oidc_refresh_tokens, :token_digest, unique: true
    add_index :oidc_refresh_tokens, :expires_at
    add_index :oidc_refresh_tokens, :revoked_at
    add_index :oidc_refresh_tokens, :token_family_id
    add_index :oidc_refresh_tokens, [ :application_id, :user_id ]
  end
end
