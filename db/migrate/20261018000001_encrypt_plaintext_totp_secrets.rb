class EncryptPlaintextTotpSecrets < ActiveRecord::Migration[8.1]
  # CLN-15: a TOTP secret enrolled before encryption was switched on is still
  # plaintext, and was only readable because support_unencrypted_data was on.
  # Encrypt any such secret so that the flag can be turned off and plaintext
  # refused. Reads and writes the column directly, since reading a plaintext
  # value through the model now raises.
  class User < ActiveRecord::Base
    self.table_name = "users"
    encrypts :totp_secret
  end

  def up
    # Not valid ciphertext either, and means the same as NULL
    execute "UPDATE users SET totp_secret = NULL WHERE totp_secret = ''"

    type = User.type_for_attribute(:totp_secret)
    select_rows("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL").each do |id, secret|
      next if ActiveRecord::Encryption.encryptor.encrypted?(secret)

      execute User.sanitize_sql_array(["UPDATE users SET totp_secret = ? WHERE id = ?", type.serialize(secret), id])
    end
  end

  def down
    # Nothing to undo: encrypted secrets read the same either way.
  end
end
