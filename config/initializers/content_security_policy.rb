# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  config.content_security_policy do |policy|
    # Default to self for everything, plus blob: for file downloads
    policy.default_src :self, "blob:"

    # Scripts: Allow self, importmaps, unsafe-inline for Turbo/StimulusJS, and blob: for downloads
    # Note: unsafe_inline is needed for Stimulus controllers and Turbo navigation
    policy.script_src :self, :unsafe_inline, :unsafe_eval, "blob:"

    # Styles: Allow self and unsafe_inline for TailwindCSS dynamic classes
    # and Stimulus controller style manipulations
    policy.style_src :self, :unsafe_inline

    # Images: Allow self, data URLs, and https for external images
    policy.img_src :self, :data, :https

    # Fonts: Allow self and data URLs
    policy.font_src :self, :data

    # Connect: Allow self for API calls, WebAuthn, and ActionCable if needed
    # WebAuthn endpoints are on the same domain, so self is sufficient
    policy.connect_src :self, "wss:"

    # Media: Allow self
    policy.media_src :self

    # Object and embed sources: Disallow for security (no Flash/etc)
    policy.object_src :none
    policy.frame_src :none
    policy.frame_ancestors :none

    # Base URI: Restricted to self
    policy.base_uri :self

    # Form actions: Allow self for all form submissions
    policy.form_action :self

    # Manifest sources: Allow self for PWA manifest
    policy.manifest_src :self

    # Worker sources: Allow self for potential Web Workers
    policy.worker_src :self

    # Child sources: Allow self for any future iframes
    policy.child_src :self

    # Additional security headers for WebAuthn
    # Required for WebAuthn to work properly
    policy.require_trusted_types_for :none
    policy.report_uri  "/api/csp-violation-report"
  end

  # Start with CSP in report-only mode for testing
  # Set to false after verifying everything works in production
  config.content_security_policy_report_only = Rails.env.development?

  # Report CSP violations (optional - uncomment to enable)
  # config.content_security_policy_report_uri = "/csp-violations"
end