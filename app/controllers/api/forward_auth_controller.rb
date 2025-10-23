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

      # Get the redirect URL from query params or construct default
      base_url = params[:rd] || "https://clinch.aapamilne.com"

      # Set the original URL that user was trying to access
      # This will be used after authentication
      original_host = request.headers["X-Forwarded-Host"]
      original_uri = request.headers["X-Forwarded-Uri"] || request.headers["X-Forwarded-Path"] || "/"

      # Debug logging to see what headers we're getting
      Rails.logger.info "ForwardAuth Headers: Host=#{request.headers['Host']}, X-Forwarded-Host=#{original_host}, X-Forwarded-Uri=#{request.headers['X-Forwarded-Uri']}, X-Forwarded-Path=#{request.headers['X-Forwarded-Path']}"

      original_url = if original_host
        # Use the forwarded host and URI
        "https://#{original_host}#{original_uri}"
      else
        # Fallback: just redirect to the root of the original host
        "https://#{request.headers['Host']}"
      end

      # Debug: log what we're redirecting to after login
      Rails.logger.info "ForwardAuth: Will redirect to after login: #{original_url}"

      session[:return_to_after_authenticating] = original_url

      # Build login URL with redirect parameters like Authelia
      login_url = URI.parse("#{base_url}/signin")
      login_url.query_params = {
        rd: original_url,
        rm: request.method
      }.to_query

      # Return 302 Found directly to login page (matching Authelia)
      # This is the same as Authelia's StatusFound response
      Rails.logger.info "Setting 302 redirect to: #{login_url}"
      redirect_to login_url.to_s, allow_other_host: true, status: :found
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
