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
          render :new, status: :unprocessable_entity
          return
        end
      else
        # If empty or blank, set to empty hash (NOT NULL constraint)
        create_params[:custom_claims] = {}
      end

      @group = Group.new(create_params)

      if @group.save
        # Handle user assignments
        if params[:group][:user_ids].present?
          user_ids = params[:group][:user_ids].reject(&:blank?)
          @group.users = User.where(id: user_ids)
        end

        redirect_to admin_group_path(@group), notice: "Group created successfully."
      else
        @available_users = User.order(:email_address)
        render :new, status: :unprocessable_entity
      end
    end

    def edit
      @available_users = User.order(:email_address)
    end

    def update
      update_params = group_params

      # Parse custom_claims JSON if provided
      if update_params[:custom_claims].present?
        begin
          update_params[:custom_claims] = JSON.parse(update_params[:custom_claims])
        rescue JSON::ParserError
          @group.errors.add(:custom_claims, "must be valid JSON")
          @available_users = User.order(:email_address)
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

        redirect_to admin_group_path(@group), notice: "Group updated successfully."
      else
        @available_users = User.order(:email_address)
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      @group.destroy
      redirect_to admin_groups_path, notice: "Group deleted successfully."
    end

    private

    def set_group
      @group = Group.find(params[:id])
    end

    def group_params
      params.require(:group).permit(:name, :description, :custom_claims)
    end
  end
end
