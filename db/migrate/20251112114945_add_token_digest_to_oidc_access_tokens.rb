class AddTokenDigestToOidcAccessTokens < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_access_tokens, :token_digest, :string
    add_column :oidc_access_tokens, :revoked_at, :datetime

    add_index :oidc_access_tokens, :token_digest, unique: true
    add_index :oidc_access_tokens, :revoked_at
  end
end
