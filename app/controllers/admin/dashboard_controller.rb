module Admin
  class DashboardController < BaseController
    def index
      @user_count = User.count
      @active_user_count = User.active.count
      @application_count = Application.count
      @active_application_count = Application.active.count
      @group_count = Group.count
      @recent_users = User.order(created_at: :desc).limit(5)
    end
  end
end
