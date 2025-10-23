module Api
  class ForwardAuthController < ApplicationController
    # ForwardAuth endpoints don't use sessions or CSRF
    allow_unauthenticated_access
    skip_before_action :verify_authenticity_token

    # GET /api/verify
    # This endpoint is called by reverse proxies (Traefik, Caddy, nginx)
    # to verify if a user is authenticated and authorized to access an application
    def verify
      # Get the application slug from query params or X-Forwarded-Host header
      app_slug = params[:app] || extract_app_from_headers

      # Get the session from cookie
      session_id = extract_session_id
      unless session_id
        # No session cookie - user is not authenticated
        return render_unauthorized("No session cookie")
      end

      # Find the session
      session = Session.find_by(id: session_id)
      unless session
        # Invalid session
        return render_unauthorized("Invalid session")
      end

      # Check if session is expired
      if session.expired?
        session.destroy
        return render_unauthorized("Session expired")
      end

      # Update last activity
      session.update_column(:last_activity_at, Time.current)

      # Get the user
      user = session.user
      unless user.active?
        return render_unauthorized("User account is not active")
      end

      # If an application is specified, check authorization
      if app_slug.present?
        application = Application.find_by(slug: app_slug, app_type: "trusted_header", active: true)

        unless application
          Rails.logger.warn "ForwardAuth: Application not found or not configured for trusted_header: #{app_slug}"
          return render_forbidden("Application not found or not configured")
        end

        # Check if user is allowed to access this application
        unless application.user_allowed?(user)
          Rails.logger.info "ForwardAuth: User #{user.email_address} denied access to #{app_slug}"
          return render_forbidden("You do not have permission to access this application")
        end

        Rails.logger.info "ForwardAuth: User #{user.email_address} granted access to #{app_slug}"
      else
        Rails.logger.info "ForwardAuth: User #{user.email_address} authenticated (no app specified)"
      end

      # User is authenticated and authorized
      # Return 200 with user information headers
      response.headers["Remote-User"] = user.email_address
      response.headers["Remote-Email"] = user.email_address
      response.headers["Remote-Name"] = user.email_address

      # Add groups if user has any
      if user.groups.any?
        response.headers["Remote-Groups"] = user.groups.pluck(:name).join(",")
      end

      # Add admin flag
      response.headers["Remote-Admin"] = user.admin? ? "true" : "false"

      # Return 200 OK with no body
      head :ok
    end

    private

    def extract_session_id
      # Extract session ID from cookie
      # Rails uses signed cookies by default
      cookies.signed[:session_id]
    end

    def extract_app_from_headers
      # Try to extract application slug from forwarded headers
      # This is useful when the proxy doesn't pass ?app= param

      # X-Forwarded-Host might contain the hostname
      host = request.headers["X-Forwarded-Host"] || request.headers["Host"]

      # Try to match hostname to application
      # Format: app-slug.domain.com -> app-slug
      if host.present?
        # Extract subdomain as potential app slug
        parts = host.split(".")
        if parts.length >= 2
          return parts.first if parts.first != "www"
        end
      end

      nil
    end

    def render_unauthorized(reason = nil)
      Rails.logger.info "ForwardAuth: Unauthorized - #{reason}"

      # Set header to help with debugging
      response.headers["X-Auth-Reason"] = reason if reason

      # Return 401 Unauthorized
      # The reverse proxy should redirect to login
      head :unauthorized
    end

    def render_forbidden(reason = nil)
      Rails.logger.info "ForwardAuth: Forbidden - #{reason}"

      # Set header to help with debugging
      response.headers["X-Auth-Reason"] = reason if reason

      # Return 403 Forbidden
      head :forbidden
    end
  end
end
