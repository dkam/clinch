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
      Rails.logger.info "Authentication: after_authentication_url - session[:return_to_after_authenticating] = #{return_url.inspect}"
      final_url = session.delete(:return_to_after_authenticating) || root_url
      Rails.logger.info "Authentication: Final redirect URL: #{final_url}"
      final_url
    end

    def start_new_session_for(user)
      user.update!(last_sign_in_at: Time.current)
      user.sessions.create!(user_agent: request.user_agent, ip_address: request.remote_ip).tap do |session|
        Current.session = session

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

        Rails.logger.info "Authentication: Setting session cookie with options: #{cookie_options.except(:value).merge(value: cookie_options[:value]&.to_s&.first(10) + '...')}"
        Rails.logger.info "Authentication: Extracted domain from #{request.host}: #{domain.inspect}"
        cookies.signed.permanent[:session_id] = cookie_options
      end
    end

    def terminate_session
      Current.session.destroy
      cookies.delete(:session_id)
    end

    # Extract root domain for cross-subdomain cookies
    # Examples:
    # - clinch.aapamilne.com -> .aapamilne.com
    # - app.example.co.uk -> .example.co.uk
    # - localhost -> nil (no domain setting for local development)
    def extract_root_domain(host)
      return nil if host.blank? || host.match?(/^(localhost|127\.0\.0\.1|::1)$/)

      # Split hostname into parts
      parts = host.split('.')

      # For normal domains like example.com, we need at least 2 parts
      # For complex domains like co.uk, we need at least 3 parts
      return nil if parts.length < 2

      # Extract root domain with leading dot for cross-subdomain cookies
      if parts.length >= 3
        # Check if it's a known complex TLD
        complex_tlds = %w[co.uk com.au co.nz co.za co.jp]
        second_level = "#{parts[-2]}.#{parts[-1]}"

        if complex_tlds.include?(second_level)
          # For complex TLDs, include more parts: app.example.co.uk -> .example.co.uk
          root_parts = parts[-3..-1]
          return ".#{root_parts.join('.')}"
        end
      end

      # For regular domains: app.example.com -> .example.com
      root_parts = parts[-2..-1]
      ".#{root_parts.join('.')}"
    end
end
