class CreateOidcUserConsents < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_user_consents do |t|
      t.references :user, null: false, foreign_key: true
      t.references :application, null: false, foreign_key: true
      t.text :scopes_granted, null: false
      t.datetime :granted_at, null: false

      t.timestamps
    end

    # Add unique index to prevent duplicate consent records
    add_index :oidc_user_consents, [:user_id, :application_id], unique: true
    # Add index for querying recent consents
    add_index :oidc_user_consents, :granted_at
  end
end
