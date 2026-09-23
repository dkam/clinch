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
        # Changing a password is what a user does after noticing something
        # suspicious, so it must cut off any session they do not control.
        # Password reset by email already does this; keep the two consistent.
        # The current session survives so the user is not signed out of the page
        # they are standing on.
        @user.sessions.where.not(id: Current.session.id).destroy_all
        redirect_to profile_path, notice: "Password updated successfully. Other devices have been signed out."
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

      # The new address has to prove it receives mail before it replaces the
      # current one (CLN-07). Both addresses are told once it does — see
      # EmailConfirmationsController#update.
      if @user.request_email_change(email_params[:email_address])
        EmailConfirmationsMailer.confirm(@user).deliver_later
        redirect_to profile_path, notice: "We sent a confirmation link to #{@user.unconfirmed_email}. Your address changes once you follow it."
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
