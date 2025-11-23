module Admin
  class UsersController < BaseController
    before_action :set_user, only: [:show, :edit, :update, :destroy, :resend_invitation]

    def index
      @users = User.order(created_at: :desc)
    end

    def show
    end

    def new
      @user = User.new
    end

    def create
      @user = User.new(user_params)
      @user.password = SecureRandom.alphanumeric(16) if user_params[:password].blank?
      @user.status = :pending_invitation

      if @user.save
        InvitationsMailer.invite_user(@user).deliver_later
        redirect_to admin_users_path, notice: "User created successfully. Invitation email sent to #{@user.email_address}."
      else
        render :new, status: :unprocessable_entity
      end
    end

    def edit
    end

    def update
      update_params = user_params

      # Only update password if provided
      update_params.delete(:password) if update_params[:password].blank?

      if @user.update(update_params)
        redirect_to admin_users_path, notice: "User updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    def resend_invitation
      unless @user.pending_invitation?
        redirect_to admin_users_path, alert: "Cannot send invitation. User is not pending invitation."
        return
      end

      InvitationsMailer.invite_user(@user).deliver_later
      redirect_to admin_users_path, notice: "Invitation email resent to #{@user.email_address}."
    end

    def destroy
      # Prevent admin from deleting themselves
      if @user == Current.session.user
        redirect_to admin_users_path, alert: "You cannot delete your own account."
        return
      end

      @user.destroy
      redirect_to admin_users_path, notice: "User deleted successfully."
    end

    private

    def set_user
      @user = User.find(params[:id])
    end

    def user_params
      # Base attributes that all admins can modify
      base_params = params.require(:user).permit(:email_address, :name, :password, :status, :totp_required, custom_claims: {})

      # Only allow modifying admin status when editing other users (prevent self-demotion)
      if params[:id] != Current.session.user.id.to_s
        base_params[:admin] = params[:user][:admin] if params[:user][:admin].present?
      end

      base_params
    end
  end
end
