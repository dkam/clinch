class AddDeviceCodeReplayTracking < ActiveRecord::Migration[8.1]
  # Replay-revocation for the device grant, mirroring the authorization-code path.
  #
  # The device flow previously destroy!ed the code on redemption, so a replayed
  # redeemed code was indistinguishable from an unknown one and the tokens it
  # minted could not be revoked. Instead we now mark the code redeemed_at and link
  # the issued tokens back to it, so a second redemption is detected as reuse and
  # every descended token is revoked (RFC 6749 §4.1.2 reuse semantics).
  #
  # on_delete: :nullify matches the oidc_authorization_code FK: the cleanup job can
  # still delete expired device codes without orphaning or destroying live tokens.
  def change
    add_column :oidc_device_codes, :redeemed_at, :datetime

    add_reference :oidc_access_tokens, :oidc_device_code, null: true,
      foreign_key: {on_delete: :nullify}
    add_reference :oidc_refresh_tokens, :oidc_device_code, null: true,
      foreign_key: {on_delete: :nullify}
  end
end
