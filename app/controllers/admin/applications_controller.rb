module Admin
  class ApplicationsController < BaseController
    before_action :set_application, only: [:show, :edit, :update, :destroy, :regenerate_credentials, :roles, :create_role, :update_role, :assign_role, :remove_role]

    def index
      @applications = Application.order(created_at: :desc)
    end

    def show
      @allowed_groups = @application.allowed_groups
    end

    def new
      @application = Application.new
      @available_groups = Group.order(:name)
    end

    def create
      @application = Application.new(application_params)
      @available_groups = Group.order(:name)

      if @application.save
        # Handle group assignments
        if params[:application][:group_ids].present?
          group_ids = params[:application][:group_ids].reject(&:blank?)
          @application.allowed_groups = Group.where(id: group_ids)
        end

        # Get the plain text client secret to show one time
        client_secret = nil
        if @application.oidc?
          client_secret = @application.generate_new_client_secret!
        end

        if @application.oidc? && client_secret
          flash[:notice] = "Application created successfully."
          flash[:client_id] = @application.client_id
          flash[:client_secret] = client_secret
        else
          flash[:notice] = "Application created successfully."
        end

        redirect_to admin_application_path(@application)
      else
        render :new, status: :unprocessable_entity
      end
    end

    def edit
      @available_groups = Group.order(:name)
    end

    def update
      if @application.update(application_params)
        # Handle group assignments
        if params[:application][:group_ids].present?
          group_ids = params[:application][:group_ids].reject(&:blank?)
          @application.allowed_groups = Group.where(id: group_ids)
        else
          @application.allowed_groups = []
        end

        redirect_to admin_application_path(@application), notice: "Application updated successfully."
      else
        @available_groups = Group.order(:name)
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      @application.destroy
      redirect_to admin_applications_path, notice: "Application deleted successfully."
    end

    def regenerate_credentials
      if @application.oidc?
        # Generate new client ID and secret
        new_client_id = SecureRandom.urlsafe_base64(32)
        client_secret = @application.generate_new_client_secret!

        @application.update!(client_id: new_client_id)

        flash[:notice] = "Credentials regenerated successfully."
        flash[:client_id] = @application.client_id
        flash[:client_secret] = client_secret

        redirect_to admin_application_path(@application)
      else
        redirect_to admin_application_path(@application), alert: "Only OIDC applications have credentials."
      end
    end

    def roles
      @application_roles = @application.application_roles.includes(:user_role_assignments)
      @available_users = User.active.order(:email_address)
    end

    def create_role
      @role = @application.application_roles.build(role_params)

      if @role.save
        redirect_to roles_admin_application_path(@application), notice: "Role created successfully."
      else
        @application_roles = @application.application_roles.includes(:user_role_assignments)
        @available_users = User.active.order(:email_address)
        render :roles, status: :unprocessable_entity
      end
    end

    def update_role
      @role = @application.application_roles.find(params[:role_id])

      if @role.update(role_params)
        redirect_to roles_admin_application_path(@application), notice: "Role updated successfully."
      else
        @application_roles = @application.application_roles.includes(:user_role_assignments)
        @available_users = User.active.order(:email_address)
        render :roles, status: :unprocessable_entity
      end
    end

    def assign_role
      user = User.find(params[:user_id])
      role = @application.application_roles.find(params[:role_id])

      @application.assign_role_to_user!(user, role.name, source: 'manual')

      redirect_to roles_admin_application_path(@application), notice: "Role assigned successfully."
    end

    def remove_role
      user = User.find(params[:user_id])
      role = @application.application_roles.find(params[:role_id])

      @application.remove_role_from_user!(user, role.name)

      redirect_to roles_admin_application_path(@application), notice: "Role removed successfully."
    end

    private

    def set_application
      @application = Application.find(params[:id])
    end

    def application_params
      params.require(:application).permit(
        :name, :slug, :app_type, :active, :redirect_uris, :description, :metadata,
        :role_mapping_mode, :role_prefix, :role_claim_name, managed_permissions: {}
      )
    end

    def role_params
      params.require(:application_role).permit(:name, :display_name, :description, :active, permissions: {})
    end
  end
end
