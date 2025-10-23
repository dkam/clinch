class CreateApplications < ActiveRecord::Migration[8.1]
  def change
    create_table :applications do |t|
      t.string :name, null: false
      t.string :slug, null: false
      t.string :app_type, null: false
      t.string :client_id
      t.string :client_secret
      t.text :redirect_uris
      t.text :metadata
      t.boolean :active, default: true, null: false

      t.timestamps
    end
    add_index :applications, :slug, unique: true
    add_index :applications, :client_id, unique: true
    add_index :applications, :active
  end
end
