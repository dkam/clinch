class UsersController < ApplicationController
  allow_unauthenticated_access only: %i[new create]
  before_action :ensure_first_run, only: %i[new create]
  rate_limit to: 10, within: 10.minutes, only: :create, with: -> { redirect_to signup_path, alert: "Too many attempts. Try again later." }

  def new
    @user = User.new
  end

  # Signup only exists until the first account does, and the setup code from
  # the server's log is what keeps it from going to whoever reaches a fresh
  # deploy first. See Setup.
  def create
    return wrong_setup_code unless Setup.correct?(params[:setup_code])

    @user = Setup.create_admin(user_params)

    if @user.persisted?
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
    unless Setup.open?
      redirect_to signin_path, alert: "Registration is closed. Please sign in."
    end
  end

  # Keeps the email they typed; the password fields never echo back anyway.
  def wrong_setup_code
    @user = User.new(email_address: user_params[:email_address])
    @user.errors.add(:base, "That setup code doesn't match the one in the server's log.")
    render :new, status: :unprocessable_entity
  end
end
