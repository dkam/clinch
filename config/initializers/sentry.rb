# Sentry configuration for error tracking and performance monitoring
# Only initializes if SENTRY_DSN environment variable is set

return unless ENV["SENTRY_DSN"].present?

Rails.application.configure do
  config.sentry.dsn = ENV["SENTRY_DSN"]

  # Set environment (defaults to Rails.env)
  config.sentry.environment = ENV["SENTRY_ENVIRONMENT"] || Rails.env

  # Set release version from Git or environment variable
  config.sentry.release = ENV["SENTRY_RELEASE"] || `git rev-parse HEAD 2>/dev/null`.strip.presence || nil

  # Sample rate for performance monitoring (0.0 to 1.0)
  config.sentry.traces_sample_rate = ENV.fetch("SENTRY_TRACES_SAMPLE_RATE", 0.1).to_f

  # Enable profiling in development/staging, disable in production unless explicitly enabled
  config.sentry.profiles_sample_rate = if Rails.env.production?
    ENV.fetch("SENTRY_PROFILES_SAMPLE_RATE", 0.0).to_f
  else
    ENV.fetch("SENTRY_PROFILES_SAMPLE_RATE", 0.5).to_f
  end

  # Include additional context
  config.sentry.before_send = lambda do |event, hint|
    # Filter out sensitive information
    if event.context[:extra]
      event.context[:extra].reject! { |key, value|
        key.to_s.match?(/password|secret|token|key/i) || value.to_s.match?(/password|secret/i)
      }
    end

    # Filter sensitive parameters
    if event.context[:request]
      event.context[:request].reject! { |key, value|
        key.to_s.match?(/password|secret|token|key|authorization/i)
      }
    end

    event
  end

  # Include breadcrumbs for debugging
  config.sentry.breadcrumbs_logger = [:active_support_logger, :http_logger]

  # Send session data for user context
  config.sentry.user_context = lambda do
    if Current.user.present?
      {
        id: Current.user.id,
        email: Current.user.email_address,
        admin: Current.user.admin?
      }
    end
  end

  # Ignore common non-critical exceptions
  config.sentry.excluded_exceptions += [
    "ActionController::RoutingError",
    "ActionController::InvalidAuthenticityToken",
    "ActionController::UnknownFormat",
    "ActionDispatch::Http::Parameters::ParseError",
    "Rack::QueryParser::InvalidParameterError",
    "Rack::Timeout::RequestTimeoutException",
    "ActiveRecord::RecordNotFound"
  ]

  # Add CSP-specific tags for security events
  config.sentry.tags = lambda do
    {
      # Add application context
      app_name: "clinch",
      app_environment: Rails.env,
      # Add CSP policy status
      csp_enabled: defined?(Rails.application.config.content_security_policy) &&
                   Rails.application.config.content_security_policy.present?
    }
  end

  # Enhance before_send to handle CSP events properly
  config.sentry.before_send = lambda do |event, hint|
    # Filter out sensitive information
    if event.context[:extra]
      event.context[:extra].reject! { |key, value|
        key.to_s.match?(/password|secret|token|key/i) || value.to_s.match?(/password|secret/i)
      }
    end

    # Filter sensitive parameters
    if event.context[:request]
      event.context[:request].reject! { |key, value|
        key.to_s.match?(/password|secret|token|key|authorization/i)
      }
    end

    # Special handling for CSP violations
    if event.tags&.dig(:csp_violation)
      # Ensure CSP violations have proper security context
      event.context[:server] = event.context[:server] || {}
      event.context[:server][:name] = "clinch-auth-service"
      event.context[:server][:environment] = Rails.env

      # Add additional security context
      event.context[:extra] ||= {}
      event.context[:extra][:security_context] = {
        csp_reporting: true,
        user_authenticated: event.context[:user].present?,
        request_origin: event.context[:request]&.dig(:headers, "Origin"),
        request_referer: event.context[:request]&.dig(:headers, "Referer")
      }
    end

    event
  end

  # Add CSP-specific breadcrumbs for security events
  config.sentry.before_breadcrumb = lambda do |breadcrumb, hint|
    # Filter out sensitive breadcrumb data
    if breadcrumb[:data]
      breadcrumb[:data].reject! { |key, value|
        key.to_s.match?(/password|secret|token|key|authorization/i) ||
        value.to_s.match?(/password|secret/i)
      }
    end

    # Mark CSP-related events
    if breadcrumb[:message]&.include?("CSP Violation") ||
       breadcrumb[:category]&.include?("csp")
      breadcrumb[:data] ||= {}
      breadcrumb[:data][:security_event] = true
      breadcrumb[:data][:csp_violation] = true
    end

    breadcrumb
  end

  # Only send errors in production unless explicitly enabled
  config.sentry.enabled = Rails.env.production? || ENV["SENTRY_ENABLED_IN_DEVELOPMENT"] == "true"
end