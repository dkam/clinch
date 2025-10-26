class AddHeadersConfigToForwardAuthRule < ActiveRecord::Migration[8.1]
  def change
    add_column :forward_auth_rules, :headers_config, :json, default: {}, null: false
  end
end
