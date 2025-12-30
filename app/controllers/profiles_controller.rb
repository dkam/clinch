class ProfilesController < ApplicationController
  def show
    @user = Current.session.user
  end

  def update
    @user = Current.session.user

    if params[:user][:password].present?
      # Updating password - requires current password
      unless @user.authenticate(params[:user][:current_password])
        @user.errors.add(:current_password, "is incorrect")
        render :show, status: :unprocessable_entity
        return
      end

      if @user.update(password_params)
        redirect_to profile_path, notice: "Password updated successfully."
      else
        render :show, status: :unprocessable_entity
      end
    elsif params[:user][:email_address].present?
      # Updating email - requires current password (security: prevents account takeover)
      unless @user.authenticate(params[:user][:current_password])
        @user.errors.add(:current_password, "is required to change email")
        render :show, status: :unprocessable_entity
        return
      end

      if @user.update(email_params)
        redirect_to profile_path, notice: "Email updated successfully."
      else
        render :show, status: :unprocessable_entity
      end
    else
      render :show, status: :unprocessable_entity
    end
  end

  private

  def email_params
    params.require(:user).permit(:email_address)
  end

  def password_params
    params.require(:user).permit(:password, :password_confirmation)
  end
end
