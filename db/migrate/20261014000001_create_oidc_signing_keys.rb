class CreateOidcSigningKeys < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_signing_keys do |t|
      t.text :private_key_pem, null: false
      t.timestamps
    end
  end
end
