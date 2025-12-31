class AddAuthTimeToOidcTokens < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_authorization_codes, :auth_time, :integer
    add_column :oidc_refresh_tokens, :auth_time, :integer
  end
end
