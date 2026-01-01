class CreateApplicationGroups < ActiveRecord::Migration[8.1]
  def change
    create_table :application_groups do |t|
      t.references :application, null: false, foreign_key: true
      t.references :group, null: false, foreign_key: true

      t.timestamps
    end

    add_index :application_groups, [:application_id, :group_id], unique: true
  end
end
