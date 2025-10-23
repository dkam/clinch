class ChangeUserStatusToInteger < ActiveRecord::Migration[8.1]
  def change
    change_column :users, :status, :integer
  end
end
