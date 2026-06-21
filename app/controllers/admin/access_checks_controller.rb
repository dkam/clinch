module Admin
  class AccessChecksController < BaseController
    def new
      load_options
      @user = User.find_by(id: params[:user_id])
      @application = Application.find_by(id: params[:application_id])
      return unless @user && @application

      @allowed = @application.user_allowed?(@user)
      @via = @user.groups & @application.allowed_groups
    end

    private

    def load_options
      @users = User.order(:email_address)
      @applications = Application.order(:name)
    end
  end
end
