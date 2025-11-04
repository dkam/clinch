class ChangeBackupCodesToJson < ActiveRecord::Migration[8.1]
  def up
    # Change the column type from text to json
    # This will automatically handle JSON serialization/deserialization
    change_column :users, :backup_codes, :json
  end

  def down
    # Revert back to text if needed
    change_column :users, :backup_codes, :text
  end
end
