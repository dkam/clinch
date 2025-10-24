class AddDescriptionToApplications < ActiveRecord::Migration[8.1]
  def change
    add_column :applications, :description, :text
  end
end
