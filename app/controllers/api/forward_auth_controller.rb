module Api
  class ForwardAuthController < ApplicationController
    # ForwardAuth endpoints need session storage for return URL
    allow_unauthenticated_access
    skip_before_action :verify_authenticity_token
    rate_limit to: 100, within: 1.minute, only: :verify, with: -> { head :too_many_requests }

    # GET /api/verify
    # This endpoint is called by reverse proxies (Traefik, Caddy, nginx)
    # to verify if a user is authenticated and authorized to access a domain
    def verify
      # Note: app_slug parameter is no longer used - we match domains directly with ForwardAuthRule

      # Check for one-time forward auth token first (to handle race condition)
      session_id = check_forward_auth_token

      # If no token found, try to get session from cookie
      session_id ||= extract_session_id

      unless session_id
        # No session cookie or token - user is not authenticated
        return render_unauthorized("No session cookie")
      end

      # Find the session with user association (eager loading for performance)
      session = Session.includes(:user).find_by(id: session_id)
      unless session
        # Invalid session
        return render_unauthorized("Invalid session")
      end

      # Check if session is expired
      if session.expired?
        session.destroy
        return render_unauthorized("Session expired")
      end

      # Update last activity (skip validations for performance)
      session.update_column(:last_activity_at, Time.current)

      # Get the user (already loaded via includes(:user))
      user = session.user
      unless user.active?
        return render_unauthorized("User account is not active")
      end

      # Check for forward auth rule authorization
      # Get the forwarded host for domain matching
      forwarded_host = request.headers["X-Forwarded-Host"] || request.headers["Host"]

      if forwarded_host.present?
        # Load active rules with their associations for better performance
        # Preload groups to avoid N+1 queries in user_allowed? checks
        rules = ForwardAuthRule.includes(:allowed_groups).active

        # Find matching forward auth rule for this domain
        rule = rules.find { |r| r.matches_domain?(forwarded_host) }

        if rule
          # Check if user is allowed by this rule
          unless rule.user_allowed?(user)
            Rails.logger.info "ForwardAuth: User #{user.email_address} denied access to #{forwarded_host} by rule #{rule.domain_pattern}"
            return render_forbidden("You do not have permission to access this domain")
          end

          Rails.logger.info "ForwardAuth: User #{user.email_address} granted access to #{forwarded_host} by rule #{rule.domain_pattern} (policy: #{rule.policy_for_user(user)})"
        else
          # No rule found - allow access with default headers (original behavior)
          Rails.logger.info "ForwardAuth: No rule found for domain: #{forwarded_host}, allowing with default headers"
        end
      else
        Rails.logger.info "ForwardAuth: User #{user.email_address} authenticated (no domain specified)"
      end

      # User is authenticated and authorized
      # Return 200 with user information headers using rule-specific configuration
      headers = rule ? rule.headers_for_user(user) : ForwardAuthRule::DEFAULT_HEADERS.map { |key, header_name|
        case key
        when :user, :email, :name
          [header_name, user.email_address]
        when :groups
          user.groups.any? ? [header_name, user.groups.pluck(:name).join(",")] : nil
        when :admin
          [header_name, user.admin? ? "true" : "false"]
        end
      }.compact.to_h

      headers.each { |key, value| response.headers[key] = value }

      # Log what headers we're sending (helpful for debugging)
      if headers.any?
        Rails.logger.debug "ForwardAuth: Headers sent: #{headers.keys.join(', ')}"
      else
        Rails.logger.debug "ForwardAuth: No headers sent (access only)"
      end

      # Return 200 OK with no body
      head :ok
    end

    private

    def check_forward_auth_token
      # Check for one-time token in query parameters (for race condition handling)
      token = params[:fa_token]
      return nil unless token.present?

      # Try to get session ID from cache
      session_id = Rails.cache.read("forward_auth_token:#{token}")
      return nil unless session_id

      # Verify the session exists and is valid
      session = Session.find_by(id: session_id)
      return nil unless session && !session.expired?

      # Delete the token immediately (one-time use)
      Rails.cache.delete("forward_auth_token:#{token}")

            session_id
    end

    def extract_session_id
      # Extract session ID from cookie
      # Rails uses signed cookies by default
      session_id = cookies.signed[:session_id]
            session_id
    end

    def extract_app_from_headers
      # This method is deprecated since we now use ForwardAuthRule domain matching
      # Keeping it for backward compatibility but it's no longer used
      nil
    end

    def render_unauthorized(reason = nil)
      Rails.logger.info "ForwardAuth: Unauthorized - #{reason}"

      # Set header to help with debugging
      response.headers["X-Auth-Reason"] = reason if reason

      # Get the redirect URL from query params or construct default
      redirect_url = validate_redirect_url(params[:rd])
      base_url = redirect_url || "https://clinch.aapamilne.com"

      # Set the original URL that user was trying to access
      # This will be used after authentication
      original_host = request.headers["X-Forwarded-Host"]
      original_uri = request.headers["X-Forwarded-Uri"] || request.headers["X-Forwarded-Path"] || "/"

      # Debug logging to see what headers we're getting
      Rails.logger.info "ForwardAuth Headers: Host=#{request.headers['Host']}, X-Forwarded-Host=#{original_host}, X-Forwarded-Uri=#{request.headers['X-Forwarded-Uri']}, X-Forwarded-Path=#{request.headers['X-Forwarded-Path']}"

      original_url = if original_host
        # Use the forwarded host and URI (original behavior)
        "https://#{original_host}#{original_uri}"
      else
        # Fallback: use the validated redirect URL or default
        redirect_url || "https://clinch.aapamilne.com"
      end

      # Debug: log what we're redirecting to after login
      Rails.logger.info "ForwardAuth: Will redirect to after login: #{original_url}"

      session[:return_to_after_authenticating] = original_url

      # Build login URL with redirect parameters like Authelia
      login_params = {
        rd: original_url,
        rm: request.method
      }
      login_url = "#{base_url}/signin?#{login_params.to_query}"

      # Return 302 Found directly to login page (matching Authelia)
      # This is the same as Authelia's StatusFound response
      Rails.logger.info "Setting 302 redirect to: #{login_url}"
      redirect_to login_url, allow_other_host: true, status: :found
    end

    def render_forbidden(reason = nil)
      Rails.logger.info "ForwardAuth: Forbidden - #{reason}"

      # Set header to help with debugging
      response.headers["X-Auth-Reason"] = reason if reason

      # Return 403 Forbidden
      head :forbidden
    end

    def validate_redirect_url(url)
      return nil unless url.present?

      begin
        uri = URI.parse(url)

        # Only allow HTTP/HTTPS schemes
        return nil unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

        # Only allow HTTPS in production
        return nil unless Rails.env.development? || uri.scheme == 'https'

        redirect_domain = uri.host.downcase
        return nil unless redirect_domain.present?

        # Check against our ForwardAuthRules
        matching_rule = ForwardAuthRule.active.find do |rule|
          rule.matches_domain?(redirect_domain)
        end

        matching_rule ? url : nil

      rescue URI::InvalidURIError
        nil
      end
    end

    def domain_has_forward_auth_rule?(domain)
      return false if domain.blank?

      ForwardAuthRule.active.any? do |rule|
        rule.matches_domain?(domain.downcase)
      end
    end
  end
end
