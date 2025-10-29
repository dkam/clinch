# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  config.content_security_policy do |policy|
    # Default policy: only allow resources from same origin and HTTPS
    policy.default_src :self, :https

    # Scripts: strict security with nonce support for dynamic content
    policy.script_src :self, :https, :strict_dynamic

    # Styles: allow inline styles for CSS frameworks, but require HTTPS
    policy.style_src :self, :https, :unsafe_inline

    # Images: allow data URIs for inline images and HTTPS sources
    policy.img_src :self, :https, :data

    # Fonts: allow self-hosted and HTTPS fonts, plus data URIs
    policy.font_src :self, :https, :data

    # Media: allow self and HTTPS media sources
    policy.media_src :self, :https

    # Objects: block potentially dangerous plugins
    policy.object_src :none

    # Base URI: restrict base tag to same origin
    policy.base_uri :self

    # Form actions: only allow forms to submit to same origin
    policy.form_action :self

    # Frame ancestors: prevent clickjacking by disallowing framing
    policy.frame_ancestors :none

    # Frame sources: block iframes unless explicitly needed
    policy.frame_src :none

    # Connect sources: control where XHR/Fetch can connect
    policy.connect_src :self, :https

    # Manifest: only allow same-origin manifest files
    policy.manifest_src :self

    # Worker sources: control web worker origins
    policy.worker_src :self, :https

    # Report URI: send violation reports to our monitoring endpoint
    if Rails.env.production?
      policy.report_uri "/api/csp-violation-report"
    end
  end

  # Generate session nonces for permitted inline scripts and styles
  config.content_security_policy_nonce_generator = ->(request) {
    # Use a secure random nonce instead of session ID for better security
    SecureRandom.base64(16)
  }

  # Apply nonces to script and style directives
  config.content_security_policy_nonce_directives = %w(script-src style-src)

  # Automatically add `nonce` attributes to script/style tags
  config.content_security_policy_nonce_auto = true

  # Enforce CSP in production, but use report-only in development for debugging
  if Rails.env.production?
    # Enforce the policy in production
    config.content_security_policy_report_only = false
  else
    # Report violations only in development (helps with debugging)
    config.content_security_policy_report_only = true
  end
end
