class AddAutoAssignAndAdminToGroups < ActiveRecord::Migration[8.1]
  def change
    add_column :groups, :auto_assign, :boolean, default: false, null: false
    add_column :groups, :admin, :boolean, default: false, null: false
    add_index :groups, :auto_assign, where: "auto_assign"
    add_index :groups, :admin, where: "admin"
  end
end
