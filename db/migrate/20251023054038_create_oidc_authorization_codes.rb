class CreateOidcAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_authorization_codes do |t|
      t.string :code, null: false
      t.references :application, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :redirect_uri, null: false
      t.string :scope
      t.datetime :expires_at, null: false
      t.boolean :used, default: false, null: false

      t.timestamps
    end
    add_index :oidc_authorization_codes, :code, unique: true
    add_index :oidc_authorization_codes, :expires_at
    add_index :oidc_authorization_codes, [ :application_id, :user_id ]
  end
end
