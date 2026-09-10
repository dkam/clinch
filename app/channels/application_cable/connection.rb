module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :current_user

    def connect
      set_current_user || reject_unauthorized_connection
    end

    private

    # Use the same scoped lookup as the HTTP path (see Authentication concern):
    # an expired session, or one whose user has since been disabled, must not
    # establish a cable connection either.
    def set_current_user
      if (session = Session.active.for_active_user.find_by(id: cookies.signed[:session_id]))
        self.current_user = session.user
      end
    end
  end
end
