class AddClaimsRequestsToOidcAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_authorization_codes, :claims_requests, :json, default: {}, null: false
  end
end
