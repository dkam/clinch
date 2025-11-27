class AddBackchannelLogoutUriToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :backchannel_logout_uri, :string
  end
end
