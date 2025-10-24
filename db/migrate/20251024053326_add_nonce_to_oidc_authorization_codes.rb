class AddNonceToOidcAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_authorization_codes, :nonce, :string
  end
end
