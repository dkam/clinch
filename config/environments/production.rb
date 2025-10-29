require "active_support/core_ext/integer/time"

Rails.application.configure do
  # Settings specified here will take precedence over those in config/application.rb.

  # Code is not reloaded between requests.
  config.enable_reloading = false

  # Eager load code on boot for better performance and memory savings (ignored by Rake tasks).
  config.eager_load = true

  # Full error reports are disabled.
  config.consider_all_requests_local = false

  # Turn on fragment caching in view templates.
  config.action_controller.perform_caching = true

  # Cache assets for far-future expiry since they are all digest stamped.
  config.public_file_server.headers = { "cache-control" => "public, max-age=#{1.year.to_i}" }

  # Enable serving of images, stylesheets, and JavaScripts from an asset server.
  # config.asset_host = "http://assets.example.com"

  # Store uploaded files on the local file system (see config/storage.yml for options).
  config.active_storage.service = :local

  # Assume all access to the app is happening through a SSL-terminating reverse proxy.
  config.assume_ssl = true

  # Force all access to the app over SSL, use Strict-Transport-Security, and use secure cookies.
  config.force_ssl = true

  # Skip http-to-https redirect for the default health check endpoint.
  # config.ssl_options = { redirect: { exclude: ->(request) { request.path == "/up" } } }

  # Log to STDOUT with the current request id as a default log tag.
  config.log_tags = [ :request_id ]
  config.logger   = ActiveSupport::TaggedLogging.logger(STDOUT)

  # Change to "debug" to log everything (including potentially personally-identifiable information!).
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")

  # Prevent health checks from clogging up the logs.
  config.silence_healthcheck_path = "/up"

  # Don't log any deprecations.
  config.active_support.report_deprecations = false

  # Replace the default in-process memory cache store with a durable alternative.
  config.cache_store = :solid_cache_store

  # Use async processor for background jobs (modify as needed for production)
  config.active_job.queue_adapter = :async

  # Ignore bad email addresses and do not raise email delivery errors.
  # Set this to true and configure the email server for immediate delivery to raise delivery errors.
  # config.action_mailer.raise_delivery_errors = false

  # Set host to be used by links generated in mailer templates.
  config.action_mailer.default_url_options = {
    host: ENV.fetch('CLINCH_HOST', 'example.com')
  }

  # Specify outgoing SMTP server. Remember to add smtp/* credentials via bin/rails credentials:edit.
  # config.action_mailer.smtp_settings = {
  #   user_name: Rails.application.credentials.dig(:smtp, :user_name),
  #   password: Rails.application.credentials.dig(:smtp, :password),
  #   address: "smtp.example.com",
  #   port: 587,
  #   authentication: :plain
  # }

  # Enable locale fallbacks for I18n (makes lookups for any locale fall back to
  # the I18n.default_locale when a translation cannot be found).
  config.i18n.fallbacks = true

  # Do not dump schema after migrations.
  config.active_record.dump_schema_after_migration = false

  # Only use :id for inspections in production.
  config.active_record.attributes_for_inspect = [ :id ]

  # Enable DNS rebinding protection and other `Host` header attacks.
  # Configure allowed hosts based on deployment scenario
  allowed_hosts = [
    ENV.fetch('CLINCH_HOST', 'auth.aapamilne.com'),  # External domain
    /.*#{ENV.fetch('CLINCH_HOST', 'aapamilne\.com').gsub('.', '\.')}/  # Subdomains
  ]

  # Allow Docker service names if running in same compose
  if ENV['CLINCH_DOCKER_SERVICE_NAME']
    allowed_hosts << ENV['CLINCH_DOCKER_SERVICE_NAME']
  end

  # Allow internal IP access for cross-compose or host networking
  if ENV['CLINCH_ALLOW_INTERNAL_IPS'] == 'true'
    # Specific host IP
    allowed_hosts << '192.168.2.246'

    # Private IP ranges for internal network access
    allowed_hosts += [
      /192\.168\.\d+\.\d+/,    # 192.168.0.0/16 private network
      /10\.\d+\.\d+\.\d+/,     # 10.0.0.0/8 private network
      /172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/  # 172.16.0.0/12 private network
    ]
  end

  # Local development fallbacks
  if ENV['CLINCH_ALLOW_LOCALHOST'] == 'true'
    allowed_hosts += ['localhost', '127.0.0.1', '0.0.0.0']
  end

  config.hosts = allowed_hosts

  # Skip DNS rebinding protection for the default health check endpoint.
  config.host_authorization = { exclude: ->(request) { request.path == "/up" } }
end
