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
      @available_groups = Group.order(:name)

      if @application.save
        # Handle group assignments
        if params[:application][:group_ids].present?
          group_ids = params[:application][:group_ids].reject(&:blank?)
          @application.allowed_groups = Group.where(id: group_ids)
        end

        # Get the plain text client secret to show one time (confidential clients only)
        client_secret = nil
        if @application.oidc? && @application.confidential_client?
          client_secret = @application.generate_new_client_secret!
        end

        flash[:notice] = "Application created successfully."
        if @application.oidc?
          flash[:client_id] = @application.client_id
          flash[:client_secret] = client_secret if client_secret
          flash[:public_client] = true if @application.public_client?
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
        # Generate new client ID (always)
        new_client_id = SecureRandom.urlsafe_base64(32)
        @application.update!(client_id: new_client_id)

        flash[:notice] = "Credentials regenerated successfully."
        flash[:client_id] = @application.client_id

        # Generate new client secret only for confidential clients
        if @application.confidential_client?
          client_secret = @application.generate_new_client_secret!
          flash[:client_secret] = client_secret
        else
          flash[:public_client] = true
        end

        redirect_to admin_application_path(@application)
      else
        redirect_to admin_application_path(@application), alert: "Only OIDC applications have credentials."
      end
    end

    private

    def set_application
      @application = Application.find(params[:id])
    end

    def application_params
      permitted = params.require(:application).permit(
        :name, :slug, :app_type, :active, :redirect_uris, :description, :metadata,
        :domain_pattern, :landing_url, :access_token_ttl, :refresh_token_ttl, :id_token_ttl,
        :icon, :backchannel_logout_uri, :is_public_client, :require_pkce
      )

      # Handle headers_config - it comes as a JSON string from the text area
      if params[:application][:headers_config].present?
        begin
          permitted[:headers_config] = JSON.parse(params[:application][:headers_config])
        rescue JSON::ParserError
          permitted[:headers_config] = {}
        end
      end

      # Remove client_secret from params if present (shouldn't be updated via form)
      permitted.delete(:client_secret)
      permitted
    end
  end
end
