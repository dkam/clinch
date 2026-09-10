class AddAccessTokenFormatToApplications < ActiveRecord::Migration[8.1]
  # Per-client choice of access token format (ADR 0007). "opaque" keeps the
  # existing reference-token behaviour — the default, so every existing client
  # is unaffected. "jwt" issues an RFC 9068 signed token that a resource server
  # verifies offline against the JWKS, trading instant revocation for
  # independence from clinch on the request path.
  def change
    add_column :applications, :access_token_format, :string, default: "opaque", null: false
  end
end
