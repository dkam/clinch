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
        SecurityMailer.password_changed(@user, **security_event_context).deliver_later
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

      old_email = @user.email_address
      if @user.update(email_params)
        new_email = @user.email_address
        if old_email != new_email
          context = security_event_context
          [old_email, new_email].uniq.each do |recipient|
            SecurityMailer.email_address_changed(@user, recipient: recipient, old_email: old_email, new_email: new_email, **context).deliver_later
          end
        end
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
