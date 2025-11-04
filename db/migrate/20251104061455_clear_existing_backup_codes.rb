class ClearExistingBackupCodes < ActiveRecord::Migration[8.1]
  def up
    # Clear all existing backup codes to force regeneration with BCrypt hashing
    # This is a security migration to move from plain text to hashed storage
    User.where.not(backup_codes: nil).update_all(backup_codes: nil)
  end

  def down
    # This migration cannot be safely reversed
    # as the original plain text codes cannot be recovered
    raise ActiveRecord::IrreversibleMigration
  end
end
