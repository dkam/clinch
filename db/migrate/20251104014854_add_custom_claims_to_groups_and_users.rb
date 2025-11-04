class AddCustomClaimsToGroupsAndUsers < ActiveRecord::Migration[8.1]
  def change
    add_column :groups, :custom_claims, :json, default: {}, null: false
    add_column :users, :custom_claims, :json, default: {}, null: false
  end
end
