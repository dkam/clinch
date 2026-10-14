# Adding a way into an account (an API key, a passkey, an authenticator) asks
# for the password again unless the user signed in, or confirmed it, within
# REAUTHENTICATION_WINDOW. The session cookie is scoped to the parent domain
# for ForwardAuth (CLN-10), so any app under it could replay the cookie; this
# keeps a replayed cookie from turning into access that outlives the session.
#
# The time is kept in the Rails session, whose cookie is host-only, and not on
# the Session record: someone replaying session_id gets a fresh Rails session
# without it.
module RecentAuthentication
  extend ActiveSupport::Concern

  REAUTHENTICATION_WINDOW = 15.minutes

  class_methods do
    def require_recent_authentication(**options)
      before_action :require_recent_authentication, **options
    end
  end

  private

  def note_authentication
    session[:authenticated_at] = Time.current.to_i
  end

  def recently_authenticated?
    authenticated_at = session[:authenticated_at]
    authenticated_at.present? && Time.at(authenticated_at.to_i) > REAUTHENTICATION_WINDOW.ago
  end

  def require_recent_authentication
    return if recently_authenticated?

    session[:return_to_after_reauthenticating] = request.get? ? request.fullpath : local_referer_path

    if request.format.json? || request.media_type == "application/json"
      render json: {error: "Confirm your password to continue", reauthenticate_url: new_reauthentication_path}, status: :forbidden
    else
      redirect_to new_reauthentication_path
    end
  end

  # Where a form or script was submitted from, so the user lands back there,
  # but only if it's a page on this host.
  def local_referer_path
    uri = URI.parse(request.referer.to_s)
    uri.path if uri.host == request.host && uri.path.to_s.start_with?("/")
  rescue URI::InvalidURIError
    nil
  end
end
