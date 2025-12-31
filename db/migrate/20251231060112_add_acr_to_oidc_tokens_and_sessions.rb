class AddAcrToOidcTokensAndSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :sessions, :acr, :string
    add_column :oidc_authorization_codes, :acr, :string
    add_column :oidc_refresh_tokens, :acr, :string
  end
end
