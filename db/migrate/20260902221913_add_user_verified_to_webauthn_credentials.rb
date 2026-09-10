class AddUserVerifiedToWebauthnCredentials < ActiveRecord::Migration[8.1]
  def change
    # Whether the authenticator performed user verification (PIN or biometric)
    # in the most recent ceremony. A key that only proves possession satisfies
    # userVerification: "preferred" with a touch alone, which is a single factor
    # — so this records what actually happened rather than what was requested.
    #
    # NULL means "not yet observed": existing credentials predate this column and
    # have not been used since. Deliberately not defaulted to false, so the two
    # cases stay distinguishable while we gather data.
    add_column :webauthn_credentials, :user_verified, :boolean, default: nil
  end
end
