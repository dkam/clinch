class AddLastOtpAtToUsers < ActiveRecord::Migration[8.1]
  def change
    # Unix timestamp of the most recently accepted TOTP timestep, used to reject
    # replay of a code within its drift window (passed to ROTP's `after:`).
    add_column :users, :last_otp_at, :integer
  end
end
