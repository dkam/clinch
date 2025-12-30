class RemovePlaintextTokenFromOidcAccessTokens < ActiveRecord::Migration[8.1]
  def change
    # Remove the unique index first
    remove_index :oidc_access_tokens, :token, if_exists: true

    # Remove the plaintext token column - no longer needed
    # Tokens are now stored as BCrypt-hashed token_digest with HMAC token_prefix
    remove_column :oidc_access_tokens, :token, :string
  end
end
