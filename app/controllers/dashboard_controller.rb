class DashboardController < ApplicationController
  def index
    # First run: redirect to signup
    if User.count.zero?
      redirect_to signup_path
      return
    end

    # User must be authenticated
    @user = Current.session.user
  end
end
