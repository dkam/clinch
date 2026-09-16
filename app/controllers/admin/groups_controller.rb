module Admin
  class GroupsController < BaseController
    before_action :set_group, only: [:show, :edit, :update, :destroy]

    def index
      @groups = Group.order(:name)
    end

    def show
      @members = @group.users.order(:email_address)
      @applications = @group.applications.order(:name)
      @available_users = User.where.not(id: @members.pluck(:id)).order(:email_address)
    end

    def new
      @group = Group.new
      @available_users = User.order(:email_address)
      @available_applications = Application.order(:name)
    end

    def create
      create_params = group_params

      # Parse custom_claims JSON if provided
      if create_params[:custom_claims].present?
        begin
          create_params[:custom_claims] = JSON.parse(create_params[:custom_claims])
        rescue JSON::ParserError
          @group = Group.new
          @group.errors.add(:custom_claims, "must be valid JSON")
          @available_users = User.order(:email_address)
          @available_applications = Application.order(:name)
          render :new, status: :unprocessable_entity
          return
        end
      else
        # If empty or blank, set to empty hash (NOT NULL constraint)
        create_params[:custom_claims] = {}
      end

      @group = Group.new(create_params)
      admin_before = admin_user_ids

      if @group.save
        # Handle user assignments
        if params[:group][:user_ids].present?
          user_ids = params[:group][:user_ids].reject(&:blank?)
          @group.users = User.where(id: user_ids)
        end

        # Handle application assignments
        if params[:group][:application_ids].present?
          application_ids = params[:group][:application_ids].reject(&:blank?)
          @group.applications = Application.where(id: application_ids)
        end

        notify_admin_access_delta(admin_before, fallback_group: @group)
        log_admin_action("created group", @group, admin: @group.admin?)
        redirect_to admin_group_path(@group), notice: "Group created successfully."
      else
        @available_users = User.order(:email_address)
        @available_applications = Application.order(:name)
        render :new, status: :unprocessable_entity
      end
    end

    def edit
      @available_users = User.order(:email_address)
      @available_applications = Application.order(:name)
    end

    def update
      update_params = group_params
      admin_before = admin_user_ids

      # Parse custom_claims JSON if provided
      if update_params[:custom_claims].present?
        begin
          update_params[:custom_claims] = JSON.parse(update_params[:custom_claims])
        rescue JSON::ParserError
          @group.errors.add(:custom_claims, "must be valid JSON")
          @available_users = User.order(:email_address)
          @available_applications = Application.order(:name)
          render :edit, status: :unprocessable_entity
          return
        end
      else
        # If empty or blank, set to empty hash (NOT NULL constraint)
        update_params[:custom_claims] = {}
      end

      if @group.update(update_params)
        # Handle user assignments
        if params[:group][:user_ids].present?
          user_ids = params[:group][:user_ids].reject(&:blank?)
          @group.users = User.where(id: user_ids)
        else
          @group.users = []
        end

        # Handle application assignments
        if params[:group][:application_ids].present?
          application_ids = params[:group][:application_ids].reject(&:blank?)
          @group.applications = Application.where(id: application_ids)
        else
          @group.applications = []
        end

        notify_admin_access_delta(admin_before, fallback_group: @group)
        log_admin_action("updated group", @group, admin: @group.admin?)
        redirect_to admin_group_path(@group), notice: "Group updated successfully."
      else
        @available_users = User.order(:email_address)
        @available_applications = Application.order(:name)
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      admin_before = admin_user_ids
      @group.destroy
      notify_admin_access_delta(admin_before, fallback_group: @group)
      log_admin_action("deleted group", @group, admin: @group.admin?)
      redirect_to admin_groups_path, notice: "Group deleted successfully."
    end

    private

    def set_group
      @group = Group.find(params[:id])
    end

    def group_params
      params.require(:group).permit(:name, :description, :custom_claims, :auto_assign, :admin)
    end
  end
end
