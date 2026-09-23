class AddEmailVerificationToUsers < ActiveRecord::Migration[8.1]
  # CLN-07: email_verified is emitted from email_verified_at rather than
  # hard-coded true. unconfirmed_email holds a self-service change until the
  # new address follows its confirmation link.
  #
  # Existing accounts are backfilled as verified. Until now every relying party
  # has been told they were, and flipping them all to false on upgrade would
  # lock people out of any app that requires a verified address. Accounts still
  # waiting on an invitation start unverified; accepting it verifies them.
  def up
    add_column :users, :email_verified_at, :datetime
    add_column :users, :unconfirmed_email, :string

    execute <<~SQL
      UPDATE users SET email_verified_at = created_at WHERE status != 2
    SQL
  end

  def down
    remove_column :users, :unconfirmed_email
    remove_column :users, :email_verified_at
  end
end
