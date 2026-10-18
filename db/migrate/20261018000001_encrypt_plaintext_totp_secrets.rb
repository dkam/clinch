class EncryptPlaintextTotpSecrets < ActiveRecord::Migration[8.1]
  # CLN-15: a TOTP secret enrolled before encryption was switched on is still
  # plaintext, and was only readable because support_unencrypted_data was on.
  # Encrypt any such secret so that the flag can be turned off and plaintext
  # refused. Reads the column directly, since reading a plaintext value through
  # the model now raises; update_all encrypts on the way in.
  class User < ActiveRecord::Base
    self.table_name = "users"
    encrypts :totp_secret
  end

  def up
    # Not valid ciphertext either, and means the same as NULL
    execute "UPDATE users SET totp_secret = NULL WHERE totp_secret = ''"

    select_rows("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL").each do |id, secret|
      next if ActiveRecord::Encryption.encryptor.encrypted?(secret)

      User.where(id: id).update_all(totp_secret: secret)
    end
  end

  def down
    # Nothing to undo: encrypted secrets read the same either way.
  end
end
