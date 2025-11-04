class AddLandingUrlToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :landing_url, :string
  end
end
