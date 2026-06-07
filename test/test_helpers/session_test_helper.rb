module SessionTestHelper
  def sign_in_as(user)
    Current.session = user.sessions.create!

    ActionDispatch::TestRequest.create.cookie_jar.tap do |cookie_jar|
      cookie_jar.signed[:session_id] = Current.session.id
      cookies["session_id"] = cookie_jar[:session_id]
    end
  end

  def sign_out
    Current.session&.destroy!
    cookies.delete("session_id")
  end

  # Attach the auto-assign "everyone" group to the given app so existing tests
  # written under the old "empty allowed_groups = public" rule keep working.
  # New tests should attach groups explicitly to model real access intent.
  def grant_everyone_access(app)
    everyone = (groups(:everyone) rescue Group.find_by(auto_assign: true))
    app.allowed_groups << everyone unless app.allowed_groups.include?(everyone)
    app
  end
end

ActiveSupport.on_load(:action_dispatch_integration_test) do
  include SessionTestHelper
end
