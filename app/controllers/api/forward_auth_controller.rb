module Api
  class ForwardAuthController < ApplicationController
    allow_unauthenticated_access
    skip_before_action :verify_authenticity_token

    before_action :check_forward_auth_rate_limit
    after_action :track_failed_forward_auth_attempt

    # GET /api/verify
    # Called by reverse proxies (Traefik, Caddy, nginx) to verify authentication and authorization.
    def verify
      bearer_result = authenticate_bearer_token
      return bearer_result if bearer_result

      session_id = check_forward_auth_token
      session_id ||= extract_session_id

      unless session_id
        return render_unauthorized("No session cookie")
      end

      session = Session.includes(user: :groups).find_by(id: session_id)
      unless session
        return render_unauthorized("Invalid session")
      end

      if session.expired?
        session.destroy
        return render_unauthorized("Session expired")
      end

      # Debounce last_activity_at updates (at most once per minute)
      if session.last_activity_at.nil? || session.last_activity_at < 1.minute.ago
        session.update_column(:last_activity_at, Time.current)
      end

      user = session.user
      unless user.active?
        return render_unauthorized("User account is not active")
      end

      forwarded_host = request.headers["X-Forwarded-Host"] || request.headers["Host"]
      app = nil

      if forwarded_host.present?
        apps = cached_forward_auth_apps

        app = apps.find { |a| a.matches_domain?(forwarded_host) }

        if app
          unless app.active?
            Rails.logger.info "ForwardAuth: Access denied to #{forwarded_host} - application is inactive"
            return render_forbidden("No authentication rule configured for this domain")
          end

          unless app.user_allowed?(user)
            Rails.logger.info "ForwardAuth: User #{user.email_address} denied access to #{forwarded_host} by app #{app.domain_pattern}"
            return render_forbidden("You do not have permission to access this domain")
          end

          Rails.logger.info "ForwardAuth: User #{user.email_address} granted access to #{forwarded_host} by app #{app.domain_pattern} (policy: #{app.policy_for_user(user)})"
        else
          Rails.logger.info "ForwardAuth: Access denied to #{forwarded_host} - no authentication rule configured"
          return render_forbidden("No authentication rule configured for this domain")
        end
      else
        # Fail closed: with no host we cannot resolve an application or evaluate its
        # group policy. Emitting identity headers here would bypass all per-domain
        # access control, so reject instead.
        Rails.logger.info "ForwardAuth: Access denied - no host header present"
        return render_forbidden("No host header present")
      end

      # Reaching here implies a matching, active application was resolved above
      # (every other path returns forbidden), so headers are always scoped to it.
      headers = app.headers_for_user(user)
      headers.each { |key, value| response.headers[key] = value }
      Rails.logger.debug "ForwardAuth: Headers sent: #{headers.keys.join(", ")}" if headers.any?

      head :ok
    end

    private

    def fa_cache
      Rails.application.config.forward_auth_cache
    end

    def cached_forward_auth_apps
      fa_cache.fetch("fa_apps", expires_in: 5.minutes) do
        Application.forward_auth.includes(:allowed_groups).to_a
      end
    end

    RATE_LIMIT_MAX_FAILURES = 50
    RATE_LIMIT_WINDOW = 1.minute

    def check_forward_auth_rate_limit
      count = fa_cache.read("fa_fail:#{request.remote_ip}")
      return unless count && count >= RATE_LIMIT_MAX_FAILURES

      response.headers["Retry-After"] = "60"
      head :too_many_requests
    end

    def track_failed_forward_auth_attempt
      return unless response.status.in?([401, 403, 302])
      return if response.status == 302 && !response.headers["X-Auth-Reason"]

      cache_key = "fa_fail:#{request.remote_ip}"
      # Use increment to avoid resetting TTL on each failure (fixed window)
      unless fa_cache.increment(cache_key)
        fa_cache.write(cache_key, 1, expires_in: RATE_LIMIT_WINDOW)
      end
    end

    def authenticate_bearer_token
      auth_header = request.headers["Authorization"]
      return nil unless auth_header&.start_with?("Bearer ")

      token = auth_header.delete_prefix("Bearer ").strip
      return render_bearer_error("Missing token") if token.blank?

      api_key = ApiKey.find_by_token(token)
      return render_bearer_error("Invalid or expired API key") unless api_key&.active?

      user = api_key.user
      return render_bearer_error("User account is not active") unless user.active?

      forwarded_host = request.headers["X-Forwarded-Host"] || request.headers["Host"]
      app = api_key.application

      if forwarded_host.present? && !app.matches_domain?(forwarded_host)
        return render_bearer_error("API key not valid for this domain")
      end

      unless app.active?
        return render_bearer_error("Application is inactive")
      end

      # Re-check group membership at use-time. The ApiKey model only validates
      # access on creation, so a user removed from the app's allowed groups
      # afterwards must not keep access via an existing key.
      unless app.user_allowed?(user)
        Rails.logger.info "ForwardAuth: API key '#{api_key.name}' denied - user #{user.email_address} lacks group access to #{app.domain_pattern}"
        return render_bearer_error("Access denied: insufficient group membership")
      end

      api_key.touch_last_used!

      headers = app.headers_for_user(user)
      headers.each { |key, value| response.headers[key] = value }

      Rails.logger.info "ForwardAuth: API key '#{api_key.name}' authenticated user #{user.email_address} for #{forwarded_host}"
      head :ok
    end

    def render_bearer_error(message)
      render json: { error: message }, status: :unauthorized
    end

    def check_forward_auth_token
      token = params[:fa_token]
      return nil if token.blank?

      cached = Rails.cache.read("forward_auth_token:#{token}")
      return nil unless cached.is_a?(Hash)

      # The token is bound to the host that created it. If the request is
      # arriving at a different host, refuse — and do NOT burn the cache
      # entry, so that the legitimate destination can still redeem within
      # the 60s TTL.
      request_host = (request.headers["X-Forwarded-Host"] || request.headers["Host"])
        .to_s.sub(/:\d+\z/, "").downcase
      return nil if request_host.blank?
      return nil unless cached[:host] == request_host

      session = Session.find_by(id: cached[:session_id])
      return nil unless session && !session.expired?

      Rails.cache.delete("forward_auth_token:#{token}")
      cached[:session_id]
    end

    def extract_session_id
      cookies.signed[:session_id]
    end

    def render_unauthorized(reason = nil)
      Rails.logger.info "ForwardAuth: Unauthorized - #{reason}"
      response.headers["X-Auth-Reason"] = reason if reason.present?

      redirect_url = validate_redirect_url(params[:rd])
      base_url = determine_base_url(redirect_url)

      original_host = request.headers["X-Forwarded-Host"]
      original_uri = request.headers["X-Forwarded-Uri"] || request.headers["X-Forwarded-Path"] || "/"

      original_url = if original_host
        "https://#{original_host}#{original_uri}"
      else
        redirect_url || base_url
      end

      session[:return_to_after_authenticating] = original_url

      login_params = { rd: original_url, rm: request.method }
      login_url = "#{base_url}/signin?#{login_params.to_query}"

      redirect_to login_url, allow_other_host: true, status: :found
    end

    def render_forbidden(reason = nil)
      Rails.logger.info "ForwardAuth: Forbidden - #{reason}"
      response.headers["X-Auth-Reason"] = reason if reason.present?
      head :forbidden
    end

    def validate_redirect_url(url)
      return nil unless url.present?

      begin
        uri = URI.parse(url)
        return nil unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        return nil unless Rails.env.development? || uri.scheme == "https"

        redirect_domain = uri.host.downcase
        return nil unless redirect_domain.present?

        matching_app = cached_forward_auth_apps.find do |app|
          app.active? && app.matches_domain?(redirect_domain)
        end

        matching_app ? url : nil
      rescue URI::InvalidURIError
        nil
      end
    end

    def determine_base_url(redirect_url)
      return redirect_url if redirect_url.present?

      if ENV["CLINCH_HOST"].present?
        host = ENV["CLINCH_HOST"]
        host.match?(/^https?:\/\//) ? host : "https://#{host}"
      else
        request_host = request.host || request.headers["X-Forwarded-Host"]
        if request_host.present?
          Rails.logger.warn "ForwardAuth: CLINCH_HOST not set, using request host: #{request_host}"
          "https://#{request_host}"
        else
          raise StandardError, "ForwardAuth: CLINCH_HOST environment variable not set and no request host available."
        end
      end
    end
  end
end
