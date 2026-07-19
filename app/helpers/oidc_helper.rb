module OidcHelper
  # Single source of truth for the human-readable description of what each OAuth
  # scope grants. Shown on both the browser consent screen (oidc/consent) and the
  # device authorization screen (device_authorizations/show) via the shared
  # shared/_scope_list partial. Unknown scopes fall back to their raw name.
  def scope_description(scope, user: Current.user)
    case scope
    when "openid" then "Verify your identity"
    when "email" then "Access your email address (#{user&.email_address})"
    when "profile" then "Access your profile information"
    when "groups" then "Access your group memberships"
    when "offline_access" then "Stay signed in (refresh access)"
    else scope
    end
  end
end
