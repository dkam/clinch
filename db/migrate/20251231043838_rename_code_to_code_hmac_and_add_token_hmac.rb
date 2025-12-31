class RenameCodeToCodeHmacAndAddTokenHmac < ActiveRecord::Migration[8.1]
  def change
    # Authorization codes: rename code to code_hmac
    rename_column :oidc_authorization_codes, :code, :code_hmac

    # Access tokens: add token_hmac, remove old columns
    add_column :oidc_access_tokens, :token_hmac, :string
    add_index :oidc_access_tokens, :token_hmac, unique: true

    remove_column :oidc_access_tokens, :token_prefix
    remove_column :oidc_access_tokens, :token_digest

    # Refresh tokens: add token_hmac, remove old columns
    add_column :oidc_refresh_tokens, :token_hmac, :string
    add_index :oidc_refresh_tokens, :token_hmac, unique: true

    remove_column :oidc_refresh_tokens, :token_prefix
    remove_column :oidc_refresh_tokens, :token_digest
  end
end
