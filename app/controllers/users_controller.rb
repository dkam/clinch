class UsersController < ApplicationController
  allow_unauthenticated_access only: %i[new create]
  before_action :ensure_first_run, only: %i[new create]

  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)

    # First user becomes admin automatically
    @user.admin = true if User.count.zero?
    @user.status = "active"

    if @user.save
      start_new_session_for @user
      redirect_to root_path, notice: "Welcome to Clinch! Your account has been created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.require(:user).permit(:email_address, :password, :password_confirmation)
  end

  def ensure_first_run
    # Only allow signup if there are no users (first-run scenario)
    if User.exists?
      redirect_to signin_path, alert: "Registration is closed. Please sign in."
    end
  end
end
