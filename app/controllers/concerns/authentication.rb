require 'uri'
require 'public_suffix'
require 'ipaddr'

module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :authenticated?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  private
    def authenticated?
      resume_session
    end

    def require_authentication
      resume_session || request_authentication
    end

    def resume_session
      Current.session ||= find_session_by_cookie
    end

    def find_session_by_cookie
      Session.find_by(id: cookies.signed[:session_id]) if cookies.signed[:session_id]
    end

    def request_authentication
      session[:return_to_after_authenticating] = request.url
      redirect_to signin_path
    end

    def after_authentication_url
      return_url = session[:return_to_after_authenticating]
      final_url = session.delete(:return_to_after_authenticating) || root_url
      final_url
    end

    def start_new_session_for(user)
      user.update!(last_sign_in_at: Time.current)
      user.sessions.create!(user_agent: request.user_agent, ip_address: request.remote_ip).tap do |session|
        Current.session = session

        # Store auth_time in session for OIDC max_age support
        session[:auth_time] = Time.now.to_i

        # Extract root domain for cross-subdomain cookies (required for forward auth)
        domain = extract_root_domain(request.host)

        cookie_options = {
          value: session.id,
          httponly: true,
          same_site: :lax,
          secure: Rails.env.production?
        }

        # Set domain for cross-subdomain authentication if we can extract it
        cookie_options[:domain] = domain if domain.present?

        cookies.signed.permanent[:session_id] = cookie_options

        # Create a one-time token for immediate forward auth after authentication
        # This solves the race condition where browser hasn't processed cookie yet
        create_forward_auth_token(session)
      end
    end

    def terminate_session
      Current.session.destroy
      cookies.delete(:session_id)
    end

    # Extract root domain for cross-subdomain cookies in SSO forward_auth system.
    #
    # PURPOSE: Enables a single authentication session to work across multiple subdomains
    # by setting cookies with the domain parameter (e.g., .example.com allows access from
    # both app.example.com and api.example.com).
    #
    # CRITICAL: Returns nil for IP addresses (IPv4 and IPv6) and localhost - this is intentional!
    # When accessing services by IP, there are no subdomains to share cookies with,
    # and setting a domain cookie would break authentication.
    #
    # Uses the Public Suffix List (industry standard maintained by Mozilla) to
    # correctly handle complex domain patterns like co.uk, com.au, appspot.com, etc.
    #
    # Examples:
    # - app.example.com -> .example.com (enables cross-subdomain SSO)
    # - api.example.co.uk -> .example.co.uk (handles complex TLDs)
    # - myapp.appspot.com -> .myapp.appspot.com (handles platform domains)
    # - localhost -> nil (local development, no domain cookie)
    # - 192.168.1.1 -> nil (IP access, no domain cookie - prevents SSO breakage)
    #
    # @param host [String] The request host (may include port)
    # @return [String, nil] Root domain with leading dot for cookies, or nil for no domain setting
    def extract_root_domain(host)
      return nil if host.blank? || host.match?(/^(localhost|127\.0\.0\.1|::1)$/)

      # Strip port number for domain parsing
      host_without_port = host.split(':').first

      # Check if it's an IP address (IPv4 or IPv6) - if so, don't set domain cookie
      return nil if IPAddr.new(host_without_port) rescue false

      # Use Public Suffix List for accurate domain parsing
      domain = PublicSuffix.parse(host_without_port)
      ".#{domain.domain}"
    rescue PublicSuffix::DomainInvalid
      # Fallback for invalid domains or IPs
      nil
    end

    # Create a one-time token for forward auth to handle the race condition
    # where the browser hasn't processed the session cookie yet
    def create_forward_auth_token(session_obj)
      # Generate a secure random token
      token = SecureRandom.urlsafe_base64(32)

      # Store it with an expiry of 60 seconds
      Rails.cache.write(
        "forward_auth_token:#{token}",
        session_obj.id,
        expires_in: 60.seconds
      )

      # Set the token as a query parameter on the redirect URL
      # We need to store this in the controller's session
      controller_session = session
      if controller_session[:return_to_after_authenticating].present?
        original_url = controller_session[:return_to_after_authenticating]
        uri = URI.parse(original_url)

        # Skip adding fa_token for OAuth URLs (OAuth flow should not have forward auth tokens)
        unless uri.path&.start_with?("/oauth/")
          # Add token as query parameter
          query_params = URI.decode_www_form(uri.query || "").to_h
          query_params['fa_token'] = token
          uri.query = URI.encode_www_form(query_params)

          # Update the session with the tokenized URL
          controller_session[:return_to_after_authenticating] = uri.to_s
        end
      end
    end
end
