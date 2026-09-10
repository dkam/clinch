# Sentry configuration for error tracking and performance monitoring.
# Only initializes if the SENTRY_DSN environment variable is set.

return unless ENV["SENTRY_DSN"].present?

Sentry.init do |config|
  config.dsn = ENV["SENTRY_DSN"]

  # Environment label (defaults to Rails.env)
  config.environment = ENV["SENTRY_ENVIRONMENT"] || Rails.env

  # Both numbers, because a release wants a name and a build wants a proof:
  # Clinch::VERSION says which release this is, config.x.revision says which
  # commit it was built from (see config/initializers/revision.rb).
  #
  # This used to shell out to `git rev-parse HEAD`, which always came back empty
  # in a deployed container — .dockerignore excludes /.git/ — so `.presence` made
  # it nil and every event arrived with no release at all. Nothing in Splat could
  # be filtered or grouped by version, which is the one question a release string
  # exists to answer.
  config.release = ENV["SENTRY_RELEASE"].presence ||
    "#{Clinch::VERSION}+#{Rails.application.config.x.revision}"

  # Bridge-networked containers get a random container ID as their hostname, so
  # server_name would otherwise report that rather than the host.
  config.server_name = ENV["SENTRY_SERVER_NAME"] if ENV["SENTRY_SERVER_NAME"].present?

  # Release health — crash-free session rates — is a Sentry feature Splat does
  # not implement. Left on, the session flusher ships one envelope per process
  # per minute carrying only aggregate counters, which Splat receives, finds no
  # event_id in, and drops. Pure waste on both ends.
  config.auto_session_tracking = false

  # Only report from production unless explicitly enabled elsewhere.
  config.enabled_environments =
    if ENV["SENTRY_ENABLED_IN_DEVELOPMENT"] == "true"
      %w[production development]
    else
      %w[production]
    end

  # Don't send cookies, request bodies, or user IPs by default.
  config.send_default_pii = false

  # Breadcrumbs for debugging
  config.breadcrumbs_logger = [:active_support_logger, :http_logger]

  # Performance monitoring sample rate (0.0 to 1.0)
  config.traces_sample_rate = ENV.fetch("SENTRY_TRACES_SAMPLE_RATE", 0.1).to_f

  # Profiling: disabled in production by default due to cost.
  config.profiles_sample_rate =
    if Rails.env.production?
      ENV.fetch("SENTRY_PROFILES_SAMPLE_RATE", 0.0).to_f
    else
      ENV.fetch("SENTRY_PROFILES_SAMPLE_RATE", 0.5).to_f
    end

  # Ignore common non-critical exceptions
  config.excluded_exceptions += [
    "ActionController::RoutingError",
    "ActionController::InvalidAuthenticityToken",
    "ActionController::UnknownFormat",
    "ActionDispatch::Http::Parameters::ParseError",
    "Rack::QueryParser::InvalidParameterError",
    "Rack::Timeout::RequestTimeoutException",
    "ActiveRecord::RecordNotFound"
  ]

  # Attach application/user context and scrub anything sensitive before sending.
  config.before_send = lambda do |event, _hint|
    event.tags = (event.tags || {}).merge(
      app_name: "clinch",
      app_environment: Rails.env
    )

    if defined?(Current) && Current.respond_to?(:user) && Current.user
      event.user = (event.user || {}).merge(
        id: Current.user.id,
        email: Current.user.email_address,
        admin: Current.user.admin?
      )
    end

    if event.extra.is_a?(Hash)
      event.extra.reject! do |key, value|
        key.to_s.match?(/password|secret|token|key/i) || value.to_s.match?(/password|secret/i)
      end
    end

    event
  end

  # Scrub sensitive data out of breadcrumbs.
  config.before_breadcrumb = lambda do |breadcrumb, _hint|
    if breadcrumb.data.is_a?(Hash)
      breadcrumb.data.reject! do |key, value|
        key.to_s.match?(/password|secret|token|key|authorization/i) || value.to_s.match?(/password|secret/i)
      end
    end

    breadcrumb
  end
end

# Promote host and release to searchable tags. Both are already sent as
# top-level event attributes (server_name / release), but only tags are
# filterable in Splat's issue and tag views — so without this, "show me
# everything from 0.18.0-dev" has no way to be asked.
if Sentry.initialized?
  Sentry.configure_scope do |scope|
    scope.set_tags(
      host: Sentry.configuration.server_name,
      release: Sentry.configuration.release
    )
  end
end
