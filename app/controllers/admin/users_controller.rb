module Admin
  class UsersController < BaseController
    before_action :set_user, only: [:show, :edit, :update, :destroy, :resend_invitation, :update_application_claims, :delete_application_claims]

    def index
      @users = User.order(created_at: :desc)
    end

    def show
      @accessible_applications = Application.where(active: true)
        .joins(:allowed_groups)
        .where(groups: {id: @user.groups})
        .distinct
        .includes(:allowed_groups)
        .order(:name)
    end

    def new
      @user = User.new
      @available_groups = Group.order(:name)
    end

    def create
      @user = User.new(user_params)
      @user.password = SecureRandom.alphanumeric(16) if user_params[:password].blank?
      @user.status = :pending_invitation
      @user.skip_auto_assign = true if params[:auto_assign] == "0"

      if @user.save
        assign_groups_from_params(@user)
        InvitationsMailer.invite_user(@user).deliver_later
        redirect_to admin_users_path, notice: "User created successfully. Invitation email sent to #{@user.email_address}."
      else
        @available_groups = Group.order(:name)
        render :new, status: :unprocessable_entity
      end
    end

    def edit
      @applications = Application.active.order(:name)
      @available_groups = Group.order(:name)
    end

    def update
      update_params = user_params

      # Only update password if provided
      update_params.delete(:password) if update_params[:password].blank?

      # Parse custom_claims JSON if provided
      if update_params[:custom_claims].present?
        begin
          update_params[:custom_claims] = JSON.parse(update_params[:custom_claims])
        rescue JSON::ParserError
          @user.errors.add(:custom_claims, "must be valid JSON")
          @applications = Application.active.order(:name)
          @available_groups = Group.order(:name)
          render :edit, status: :unprocessable_entity
          return
        end
      else
        # If empty or blank, set to empty hash (NOT NULL constraint)
        update_params[:custom_claims] = {}
      end

      if @user.update(update_params)
        unless assign_groups_from_params(@user)
          @applications = Application.active.order(:name)
          @available_groups = Group.order(:name)
          render :edit, status: :unprocessable_entity
          return
        end
        redirect_to admin_users_path, notice: "User updated successfully."
      else
        @applications = Application.active.order(:name)
        @available_groups = Group.order(:name)
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

    # POST /admin/users/:id/update_application_claims
    def update_application_claims
      application = Application.find(params[:application_id])

      claims_json = params[:custom_claims].presence || "{}"
      begin
        claims = JSON.parse(claims_json)
      rescue JSON::ParserError
        redirect_to edit_admin_user_path(@user), alert: "Invalid JSON format for claims."
        return
      end

      app_claim = @user.application_user_claims.find_or_initialize_by(application: application)
      app_claim.custom_claims = claims

      if app_claim.save
        redirect_to edit_admin_user_path(@user), notice: "App-specific claims updated for #{application.name}."
      else
        error_message = app_claim.errors.full_messages.join(", ")
        redirect_to edit_admin_user_path(@user), alert: "Failed to update claims: #{error_message}"
      end
    end

    # DELETE /admin/users/:id/delete_application_claims
    def delete_application_claims
      application = Application.find(params[:application_id])
      app_claim = @user.application_user_claims.find_by(application: application)

      if app_claim&.destroy
        redirect_to edit_admin_user_path(@user), notice: "App-specific claims removed for #{application.name}."
      else
        redirect_to edit_admin_user_path(@user), alert: "No claims found to remove."
      end
    end

    private

    def set_user
      @user = User.find(params[:id])
    end

    def user_params
      params.require(:user).permit(:email_address, :username, :name, :password, :status, :totp_required, :custom_claims)
    end

    # Apply group_ids from the form, with a guard preventing self-demotion when
    # the user is the last member of the last admin group. Returns true on
    # success, false if a guard fired (caller should re-render).
    def assign_groups_from_params(user)
      return true unless params[:user].key?(:group_ids)

      raw_ids = Array(params[:user][:group_ids]).reject(&:blank?).map(&:to_i)
      new_groups = Group.where(id: raw_ids)

      if user == Current.session.user
        losing_admin = user.groups.where(admin: true).any? && new_groups.none?(&:admin?)
        if losing_admin
          user.errors.add(:base, "you cannot remove yourself from all administrator groups")
          return false
        end
      end

      user.groups = new_groups
      true
    end
  end
end
