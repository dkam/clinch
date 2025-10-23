module Admin
  class BaseController < ApplicationController
    before_action :require_admin

    private

    def require_admin
      user = Current.session&.user
      unless user&.admin?
        redirect_to root_path, alert: "You must be an administrator to access this page."
      end
    end
  end
end
