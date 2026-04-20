class AddOidcAuthorizationCodeIdToTokens < ActiveRecord::Migration[8.1]
  def change
    add_reference :oidc_access_tokens, :oidc_authorization_code,
                  null: true, foreign_key: true, index: true
    add_reference :oidc_refresh_tokens, :oidc_authorization_code,
                  null: true, foreign_key: true, index: true
  end
end
