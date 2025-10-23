class AddDeviceTrackingToSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :sessions, :device_name, :string
    add_column :sessions, :remember_me, :boolean, default: false, null: false
    add_column :sessions, :expires_at, :datetime
    add_column :sessions, :last_activity_at, :datetime

    add_index :sessions, :expires_at
    add_index :sessions, :last_activity_at
  end
end
