class CreateGroups < ActiveRecord::Migration[8.1]
  def change
    create_table :groups do |t|
      t.string :name, null: false
      t.text :description

      t.timestamps
    end
    add_index :groups, :name, unique: true
  end
end
