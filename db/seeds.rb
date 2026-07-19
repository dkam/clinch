# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# Example:
#
#   ["Action", "Comedy", "Drama", "Horror"].each do |genre_name|
#     MovieGenre.find_or_create_by!(name: genre_name)
#   end

# --- OAuth clients for CLI / agent access and token introspection ---------------
#
# These support the Device Authorization Grant (RFC 8628) and RFC 7662 token
# introspection. See docs/decisions/0002-device-authorization-grant.md.

admins = Group.find_by(admin: true)

# Public client (no secret, PKCE) used by CLIs and agents via the device flow.
# Ships with a well-known client_id so tools can hard-code it.
cli = Application.find_or_create_by!(client_id: "clinch-cli") do |app|
  app.name = "Clinch CLI"
  app.slug = "clinch-cli"
  app.app_type = "oidc"
  app.is_public_client = true
  app.active = true
end

# Grant the CLI to the admins group by default (device flow enforces
# Application#user_allowed?). Adjust to taste.
if admins && cli.allowed_groups.exclude?(admins)
  cli.allowed_groups << admins
  puts "Seeded 'clinch-cli' public client (allowed group: #{admins.name})."
end

# Confidential client that resource servers (e.g. c2a2) use to authenticate to
# the introspection endpoint. The secret is only shown once, on creation.
unless Application.exists?(client_id: "c2a2-introspection")
  secret = SecureRandom.urlsafe_base64(48)
  Application.create!(
    name: "c2a2 (introspection caller)",
    slug: "c2a2-introspection",
    client_id: "c2a2-introspection",
    client_secret: secret,
    app_type: "oidc",
    active: true
  )
  puts "Seeded 'c2a2-introspection' confidential client:"
  puts "  client_id:     c2a2-introspection"
  puts "  client_secret: #{secret}"
  puts "  Store these in c2a2 now — the secret is hashed and cannot be recovered."
end
