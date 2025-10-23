module Admin
  class ApplicationsController < BaseController
    before_action :set_application, only: [:show, :edit, :update, :destroy, :regenerate_credentials]

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

      if @application.save
        # Handle group assignments
        if params[:application][:group_ids].present?
          group_ids = params[:application][:group_ids].reject(&:blank?)
          @application.allowed_groups = Group.where(id: group_ids)
        end

        redirect_to admin_application_path(@application), notice: "Application created successfully."
      else
        @available_groups = Group.order(:name)
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
        @application.update!(
          client_id: SecureRandom.urlsafe_base64(32),
          client_secret: SecureRandom.urlsafe_base64(48)
        )
        redirect_to admin_application_path(@application), notice: "Credentials regenerated successfully. Make sure to update your application configuration."
      else
        redirect_to admin_application_path(@application), alert: "Only OIDC applications have credentials."
      end
    end

    private

    def set_application
      @application = Application.find(params[:id])
    end

    def application_params
      params.require(:application).permit(:name, :slug, :app_type, :active, :redirect_uris, :description, :metadata)
    end
  end
end
