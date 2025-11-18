class MakeOidcAccessTokenTokenNullable < ActiveRecord::Migration[8.1]
  def change
    change_column_null :oidc_access_tokens, :token, true
  end
end
