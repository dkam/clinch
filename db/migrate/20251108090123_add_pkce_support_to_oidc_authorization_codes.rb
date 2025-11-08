class AddPkceSupportToOidcAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_authorization_codes, :code_challenge, :string
    add_column :oidc_authorization_codes, :code_challenge_method, :string

    # Add index for code_challenge to improve query performance
    add_index :oidc_authorization_codes, :code_challenge
  end
end
