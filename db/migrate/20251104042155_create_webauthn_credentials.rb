class CreateWebauthnCredentials < ActiveRecord::Migration[8.1]
  def change
    create_table :webauthn_credentials do |t|
      # Reference to the user who owns this credential
      t.references :user, null: false, foreign_key: true, index: true

      # WebAuthn specification fields
      t.string :external_id, null: false, index: {unique: true}  # credential ID (base64)
      t.string :public_key, null: false                             # public key (base64)
      t.integer :sign_count, null: false, default: 0                # signature counter (clone detection)

      # Metadata
      t.string :nickname                                            # User-friendly name ("MacBook Touch ID")
      t.string :authenticator_type                                  # "platform" or "cross-platform"
      t.boolean :backup_eligible, default: false                    # Can be backed up (passkey sync)
      t.boolean :backup_state, default: false                       # Currently backed up

      # Tracking
      t.datetime :last_used_at
      t.string :last_used_ip
      t.string :user_agent                                          # Browser/OS info

      t.timestamps
    end

    # Add composite index for user-specific queries
    add_index :webauthn_credentials, [:user_id, :external_id], unique: true
    add_index :webauthn_credentials, [:user_id, :last_used_at]
    add_index :webauthn_credentials, :authenticator_type
    add_index :webauthn_credentials, :last_used_at
  end
end
