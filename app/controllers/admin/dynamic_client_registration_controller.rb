module Admin
  # Toggles the RFC 7591 dynamic client registration window on/off at runtime.
  class DynamicClientRegistrationController < BaseController
    def update
      enabled = ActiveModel::Type::Boolean.new.cast(params[:enabled])
      Setting.set(Application::DCR_SETTING_KEY, enabled)

      notice = if enabled
        "Dynamic client registration enabled. New clients can self-register — attach them to a group, then disable this again."
      else
        "Dynamic client registration disabled."
      end
      redirect_to admin_applications_path, notice: notice
    end
  end
end
