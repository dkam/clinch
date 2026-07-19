# User-facing side of the OAuth 2.0 Device Authorization Grant (RFC 8628 §3.3).
#
# The CLI/agent sends the human here (GET /device) with the short user_code it
# was issued. This controller is authenticated, so an unauthenticated visitor is
# bounced through /signin (with their passkey) and returned here afterwards via
# session[:return_to_after_authenticating]. On POST /device the signed-in user
# approves or denies; approval attaches them to the device code and records
# consent so the token endpoint can mint tokens.
class DeviceAuthorizationsController < ApplicationController
  # Browser form endpoint — keep CSRF protection on (do NOT skip it).

  # RFC 8628 §5.1: rate-limit user_code entry so a signed-in user cannot brute
  # force the short code space to deny or hijack another user's pending
  # authorization during its ~10 minute window. Covers both the lookup (show) and
  # the state-changing submit (verify).
  rate_limit to: 10, within: 1.minute, only: [:show, :verify], with: -> {
    render plain: "Too many attempts. Try again later.", status: :too_many_requests
  }

  # GET /device?user_code=WDJB-MJHT
  def show
    @user_code = params[:user_code].to_s
    if @user_code.blank?
      @state = :prompt
      return render :show
    end

    @device_code = OidcDeviceCode.find_by_user_code(@user_code)
    @state = device_code_state(@device_code)
    if @state == :ok
      @state = :confirm
      @application = @device_code.application
      @scopes = granted_scopes(@device_code)
    end

    render :show
  end

  # POST /device
  def verify
    @device_code = OidcDeviceCode.find_by_user_code(params[:user_code].to_s)
    @state = device_code_state(@device_code)
    return render :result unless @state == :ok

    @application = @device_code.application

    if params[:deny].present?
      @device_code.deny!
      @state = :denied
      return render :result
    end

    # Enforce the same group-based access control as the OIDC authorize flow.
    unless @application.user_allowed?(Current.user)
      @state = :not_allowed
      return render :result
    end

    record_consent(@device_code, Current.user)
    @device_code.approve!(
      user: Current.user,
      acr: Current.session.acr,
      auth_time: Current.session.created_at.to_i
    )
    @state = :approved
    render :result
  end

  private

  # Single resolver for the shared terminal-state cascade. Returns :not_found,
  # :expired, :already_handled, or :ok (the code is live and actionable). Both
  # show and verify branch on this so the cascade lives in one place, and the
  # terminal states render through the shared _terminal_state partial.
  def device_code_state(device_code)
    return :not_found if device_code.nil?
    return :expired if device_code.expired?
    return :already_handled unless device_code.pending?
    :ok
  end

  def granted_scopes(device_code)
    device_code.scope.to_s.split & OidcScopes::SUPPORTED
  end

  def record_consent(device_code, user)
    # merge: true — the consent record is shared with the browser flow, so a
    # narrower device request must not shrink previously granted scopes or wipe
    # stored claims.
    OidcUserConsent.record!(
      user: user,
      application: device_code.application,
      scopes: granted_scopes(device_code),
      merge: true
    )
  end
end
