# The RSA key Clinch signs ID tokens, JWT access tokens and logout tokens with,
# when OIDC_PRIVATE_KEY (or the credentials file) doesn't supply one. The first
# process that needs a key generates it and keeps it here, so OIDC works with
# no setup and the key travels with the database's backups. It's encrypted
# with keys derived from SECRET_KEY_BASE, like TOTP secrets, so a copy of the
# database alone can't sign anything.
class OidcSigningKey < ApplicationRecord
  encrypts :private_key_pem

  def self.pem
    first&.private_key_pem || generate
  end

  # On SQLite, Rails opens transactions with BEGIN IMMEDIATE, so a second
  # process generating at the same moment waits here, then finds the first
  # one's key instead of adding its own.
  def self.generate
    transaction do
      first&.private_key_pem || create!(private_key_pem: OpenSSL::PKey::RSA.new(2048).to_pem).private_key_pem
    end
  end
end
