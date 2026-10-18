require_relative "boot"
# Loaded here rather than as an initializer so Clinch::VERSION exists before
# config/initializers/* run — sentry.rb needs it, and initializers load
# alphabetically, so "version" would otherwise arrive too late.
require_relative "version"

require "rails/all"
require_relative "../lib/clinch/smtp_settings"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module Clinch
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    # `clinch` is excluded from autoloading because config/environments/*.rb needs
    # it at boot, before Zeitwerk is set up, so those files require it directly.
    # Leaving it autoloadable too would let a development reload unload the
    # constant that `require` will not re-establish.
    config.autoload_lib(ignore: %w[assets tasks clinch])

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Configure SMTP settings using environment variables
    config.action_mailer.delivery_method = :smtp
    config.action_mailer.smtp_settings = Clinch::SmtpSettings.from_env
  end
end
