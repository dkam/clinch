class CreateOidcAccessTokens < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_access_tokens do |t|
      t.string :token, null: false
      t.references :application, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :scope
      t.datetime :expires_at, null: false

      t.timestamps
    end
    add_index :oidc_access_tokens, :token, unique: true
    add_index :oidc_access_tokens, :expires_at
    add_index :oidc_access_tokens, [ :application_id, :user_id ]
  end
end
