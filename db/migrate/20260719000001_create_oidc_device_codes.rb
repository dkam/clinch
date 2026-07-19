class CreateOidcDeviceCodes < ActiveRecord::Migration[8.1]
  def change
    create_table :oidc_device_codes do |t|
      t.references :application, null: false, foreign_key: true
      # user_id is nullable: it stays blank while the code is pending and is
      # filled in when the user approves the request on the verification page.
      t.references :user, null: true, foreign_key: true

      # Opaque device_code, stored as an HMAC (never plaintext) — matches the
      # OidcAuthorizationCode pattern.
      t.string :device_code_hmac, null: false
      # Short, human-typable code the user enters on the verification page.
      # Stored in plaintext because the user reads it off one screen and types
      # it into another; kept safe by short expiry + single use + rate limiting.
      t.string :user_code, null: false

      t.string :status, null: false, default: "pending" # pending / approved / denied

      t.string :scope
      t.string :nonce

      # PKCE (RFC 8628 permits and recommends PKCE for public clients).
      t.string :code_challenge
      t.string :code_challenge_method

      # Captured at approval time from the approving user's session.
      t.string :acr
      t.integer :auth_time

      t.datetime :expires_at, null: false
      # Timestamp of the last token-endpoint poll, used to enforce the polling
      # interval and emit slow_down (RFC 8628 §3.5).
      t.datetime :last_polled_at
      t.integer :interval, null: false, default: 5

      t.timestamps
    end

    add_index :oidc_device_codes, :device_code_hmac, unique: true
    add_index :oidc_device_codes, :user_code, unique: true
    add_index :oidc_device_codes, :expires_at
  end
end
