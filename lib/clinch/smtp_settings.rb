module Clinch
  # Action Mailer's SMTP settings, from the SMTP_* environment variables. An
  # empty variable counts as unset, since compose.yaml passes them all through.
  module SmtpSettings
    def self.from_env(env = ENV)
      value = ->(key, default = nil) { env[key].presence || default }

      settings = {
        address: value.call("SMTP_ADDRESS", "localhost"),
        port: value.call("SMTP_PORT", 587),
        domain: value.call("SMTP_DOMAIN", "localhost"),
        enable_starttls_auto: value.call("SMTP_STARTTLS_AUTO", "true") == "true",
        openssl_verify_mode: OpenSSL::SSL::VERIFY_PEER
      }

      # SMTP AUTH only with a username. The mail gem refuses to send when
      # authentication is set without one, which ruled out unauthenticated relays.
      if (user_name = value.call("SMTP_USERNAME"))
        settings.merge!(
          user_name: user_name,
          password: value.call("SMTP_PASSWORD"),
          authentication: value.call("SMTP_AUTHENTICATION", "plain").to_sym
        )
      end

      settings
    end
  end
end
