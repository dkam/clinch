module ClaimsHelper
  include ClaimsMerger

  # Preview final merged claims for a user accessing an application
  def preview_user_claims(user, application)
    claims = {
      # Standard OIDC claims
      email: user.email_address,
      email_verified: true,
      preferred_username: user.username.presence || user.email_address,
      name: user.name.presence || user.email_address
    }

    # Add groups
    if user.groups.any?
      claims[:groups] = user.groups.pluck(:name)
    end

    # Merge group custom claims (arrays are combined, not overwritten)
    user.groups.each do |group|
      claims = deep_merge_claims(claims, group.parsed_custom_claims)
    end

    # Merge user custom claims (arrays are combined, other values override)
    claims = deep_merge_claims(claims, user.parsed_custom_claims)

    # Merge app-specific claims (arrays are combined)
    claims = deep_merge_claims(claims, application.custom_claims_for_user(user))

    claims
  end

  # Get claim sources breakdown for display
  def claim_sources(user, application)
    sources = []

    # Group claims
    user.groups.each do |group|
      if group.parsed_custom_claims.any?
        sources << {
          type: :group,
          name: group.name,
          claims: group.parsed_custom_claims
        }
      end
    end

    # User claims
    if user.parsed_custom_claims.any?
      sources << {
        type: :user,
        name: "User Override",
        claims: user.parsed_custom_claims
      }
    end

    # App-specific claims
    app_claims = application.custom_claims_for_user(user)
    if app_claims.any?
      sources << {
        type: :application,
        name: "App-Specific (#{application.name})",
        claims: app_claims
      }
    end

    sources
  end
end
