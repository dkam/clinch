# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  config.content_security_policy do |policy|
    # Default to self for everything, plus blob: for file downloads
    policy.default_src :self, "blob:"

    # Scripts: self + per-response nonce (see nonce config below) + blob: for
    # downloads. No unsafe-inline — importmap/Turbo/Stimulus inline tags carry the
    # nonce automatically, and the one hand-written inline script is nonced.
    policy.script_src :self, "blob:"

    # Styles: self + per-response nonce. No unsafe-inline — Tailwind ships as an
    # external stylesheet, Turbo's injected <style> carries the nonce, and Stimulus
    # sets styles via the CSSOM (not governed by CSP).
    policy.style_src :self

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
    # Note: OAuth redirects will be handled dynamically in the consent page
    policy.form_action :self

    # Manifest sources: Allow self for PWA manifest
    policy.manifest_src :self

    # Worker sources: Allow self for potential Web Workers
    policy.worker_src :self

    # Child sources: Allow self for any future iframes
    policy.child_src :self

    # Do not enforce Trusted Types. The only valid value for
    # require-trusted-types-for is 'script'; there is no 'none' token, so
    # emitting it produces an invalid directive that browsers reject. To leave
    # Trusted Types unenforced (needed for WebAuthn), omit the directive entirely.

    # CSP reporting using report_uri (supported method)
    policy.report_uri "/api/csp-violation-report"
  end

  # Per-response random nonce applied to script-src and style-src. The app does
  # not page-cache HTML, so a fresh random nonce per response is the most secure
  # choice (no reuse across responses). csp_meta_tag (in the layout) and
  # importmap-rails read this nonce automatically.
  config.content_security_policy_nonce_generator = ->(_request) { SecureRandom.base64(16) }
  config.content_security_policy_nonce_directives = %w[script-src style-src]

  # Start with CSP in report-only mode for testing
  # Set to false after verifying everything works in production
  config.content_security_policy_report_only = Rails.env.development?

  # Report CSP violations (optional - uncomment to enable)
  # config.content_security_policy_report_uri = "/csp-violations"
end
