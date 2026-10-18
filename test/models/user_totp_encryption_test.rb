require "test_helper"

# CLN-15: TOTP secrets are encrypted, but with support_unencrypted_data on, a
# plaintext value in the column was read as if nothing were wrong. A migration
# encrypts any secret left over from before encryption, so plaintext can then
# be refused.
class UserTotpEncryptionTest < ActiveSupport::TestCase
  SECRET = "JBSWY3DPEHPK3PXP"

  setup do
    @user = users(:alice)
  end

  test "a TOTP secret stored in plaintext is refused, not read" do
    write_raw_secret(SECRET)

    assert_raises(ActiveRecord::Encryption::Errors::Decryption) do
      User.find(@user.id).totp_secret
    end
  end

  test "the migration encrypts TOTP secrets left in plaintext" do
    write_raw_secret(SECRET)

    run_migration

    assert ActiveRecord::Encryption.encryptor.encrypted?(raw_secret), "the stored secret should now be encrypted"
    assert_equal SECRET, User.find(@user.id).totp_secret
  end

  test "the migration leaves encrypted secrets and empty ones alone" do
    @user.update!(totp_secret: SECRET)
    encrypted = raw_secret
    bob = users(:bob)
    bob.update!(totp_secret: nil)

    run_migration

    assert_equal encrypted, raw_secret
    assert_nil User.find(bob.id).totp_secret
  end

  # An empty string isn't valid ciphertext either, so it would be refused too.
  test "the migration clears an empty plaintext secret" do
    write_raw_secret("")

    run_migration

    assert_nil raw_secret
    refute User.find(@user.id).totp_enabled?
  end

  private

  def write_raw_secret(value)
    User.connection.execute(User.sanitize_sql_array(["UPDATE users SET totp_secret = ? WHERE id = ?", value, @user.id]))
  end

  def raw_secret
    User.connection.select_value(User.sanitize_sql_array(["SELECT totp_secret FROM users WHERE id = ?", @user.id]))
  end

  def run_migration
    path = Dir[Rails.root.join("db/migrate/*_encrypt_plaintext_totp_secrets.rb")].first
    flunk "no migration encrypts plaintext TOTP secrets" unless path
    require path
    ActiveRecord::Migration.suppress_messages { EncryptPlaintextTotpSecrets.new.migrate(:up) }
  end
end
