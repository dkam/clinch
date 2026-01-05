class AddClaimsRequestsToOidcUserConsents < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_user_consents, :claims_requests, :json, default: {}, null: false
  end
end
