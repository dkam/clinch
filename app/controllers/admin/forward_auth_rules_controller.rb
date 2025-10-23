module Admin
  class ForwardAuthRulesController < BaseController
    before_action :set_forward_auth_rule, only: [:show, :edit, :update, :destroy]

    def index
      @forward_auth_rules = ForwardAuthRule.ordered
    end

    def show
      @allowed_groups = @forward_auth_rule.allowed_groups
    end

    def new
      @forward_auth_rule = ForwardAuthRule.new
      @available_groups = Group.order(:name)
    end

    def create
      @forward_auth_rule = ForwardAuthRule.new(forward_auth_rule_params)

      if @forward_auth_rule.save
        # Handle group assignments
        if params[:forward_auth_rule][:group_ids].present?
          group_ids = params[:forward_auth_rule][:group_ids].reject(&:blank?)
          @forward_auth_rule.allowed_groups = Group.where(id: group_ids)
        end

        redirect_to admin_forward_auth_rule_path(@forward_auth_rule), notice: "Forward auth rule created successfully."
      else
        @available_groups = Group.order(:name)
        render :new, status: :unprocessable_entity
      end
    end

    def edit
      @available_groups = Group.order(:name)
    end

    def update
      if @forward_auth_rule.update(forward_auth_rule_params)
        # Handle group assignments
        if params[:forward_auth_rule][:group_ids].present?
          group_ids = params[:forward_auth_rule][:group_ids].reject(&:blank?)
          @forward_auth_rule.allowed_groups = Group.where(id: group_ids)
        else
          @forward_auth_rule.allowed_groups = []
        end

        redirect_to admin_forward_auth_rule_path(@forward_auth_rule), notice: "Forward auth rule updated successfully."
      else
        @available_groups = Group.order(:name)
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      @forward_auth_rule.destroy
      redirect_to admin_forward_auth_rules_path, notice: "Forward auth rule deleted successfully."
    end

    private

    def set_forward_auth_rule
      @forward_auth_rule = ForwardAuthRule.find(params[:id])
    end

    def forward_auth_rule_params
      params.require(:forward_auth_rule).permit(:domain_pattern, :active)
    end
  end
end