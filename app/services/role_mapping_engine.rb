class RoleMappingEngine
  class << self
    # Sync user roles from OIDC claims
    def sync_user_roles!(user, application, claims)
      return unless application.role_mapping_enabled?

      # Extract roles from claims
      external_roles = extract_roles_from_claims(application, claims)

      case application.role_mapping_mode
      when 'oidc_managed'
        sync_oidc_managed_roles!(user, application, external_roles)
      when 'hybrid'
        sync_hybrid_roles!(user, application, external_roles)
      end
    end

    # Check if user is allowed based on roles
    def user_allowed_with_roles?(user, application, claims = nil)
      return application.user_allowed_with_roles?(user) unless claims

      if application.oidc_managed_roles?
        external_roles = extract_roles_from_claims(application, claims)
        return false if external_roles.empty?

        # Check if any external role matches configured application roles
        application.application_roles.active.exists?(name: external_roles)
      elsif application.hybrid_roles?
        # Allow access if either group-based or role-based access works
        application.user_allowed?(user) ||
        (external_roles.present? &&
         application.application_roles.active.exists?(name: external_roles))
      else
        application.user_allowed?(user)
      end
    end

    # Get available roles for a user in an application
    def user_available_roles(user, application)
      return [] unless application.role_mapping_enabled?

      application.application_roles.active
    end

    # Map external roles to internal roles
    def map_external_to_internal_roles(application, external_roles)
      return [] if external_roles.empty?

      configured_roles = application.application_roles.active.pluck(:name)

      # Apply role prefix filtering
      if application.role_prefix.present?
        external_roles = external_roles.select { |role| role.start_with?(application.role_prefix) }
      end

      # Find matching internal roles
      external_roles & configured_roles
    end

    private

    # Extract roles from various claim sources
    def extract_roles_from_claims(application, claims)
      claim_name = application.role_claim_name.presence || 'roles'

      # Try the configured claim name first
      roles = claims[claim_name]

      # Fallback to common claim names if not found
      roles ||= claims['roles']
      roles ||= claims['groups']
      roles ||= claims['http://schemas.microsoft.com/ws/2008/06/identity/claims/role']

      # Ensure roles is an array
      case roles
      when String
        [roles]
      when Array
        roles
      else
        []
      end
    end

    # Sync roles for OIDC managed mode (replace existing roles)
    def sync_oidc_managed_roles!(user, application, external_roles)
      # Map external roles to internal roles
      internal_roles = map_external_to_internal_roles(application, external_roles)

      # Get current OIDC-managed roles
      current_assignments = user.user_role_assignments
                           .joins(:application_role)
                           .where(application_role: { application: application })
                           .oidc_managed
                           .includes(:application_role)

      current_role_names = current_assignments.map { |assignment| assignment.application_role.name }

      # Remove roles that are no longer in external roles
      roles_to_remove = current_role_names - internal_roles
      roles_to_remove.each do |role_name|
        application.remove_role_from_user!(user, role_name)
      end

      # Add new roles
      roles_to_add = internal_roles - current_role_names
      roles_to_add.each do |role_name|
        application.assign_role_to_user!(user, role_name, source: 'oidc',
                                       metadata: { synced_at: Time.current })
      end
    end

    # Sync roles for hybrid mode (merge with existing roles)
    def sync_hybrid_roles!(user, application, external_roles)
      # Map external roles to internal roles
      internal_roles = map_external_to_internal_roles(application, external_roles)

      # Only add new roles, don't remove manually assigned ones
      internal_roles.each do |role_name|
        next if application.user_has_role?(user, role_name)

        application.assign_role_to_user!(user, role_name, source: 'oidc',
                                       metadata: { synced_at: Time.current })
      end
    end
  end
end