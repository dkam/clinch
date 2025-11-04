class AddWebauthnToUsers < ActiveRecord::Migration[8.1]
  def change
    # WebAuthn user handle - stable, opaque identifier for the user
    # Must be unique and never change once assigned
    add_column :users, :webauthn_id, :string
    add_index :users, :webauthn_id, unique: true

    # Policy enforcement - whether this user MUST use WebAuthn
    # Can be set by admins for high-security accounts
    add_column :users, :webauthn_required, :boolean, default: false, null: false

    # User preference for 2FA method (if both TOTP and WebAuthn are available)
    # :totp, :webauthn, or nil for system default
    add_column :users, :preferred_2fa_method, :string
  end
end
