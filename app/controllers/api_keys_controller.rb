class ApiKeysController < ApplicationController
  before_action :set_api_key, only: :destroy

  def index
    @api_keys = Current.session.user.api_keys.includes(:application).order(created_at: :desc)
  end

  def new
    @api_key = ApiKey.new
    @applications = forward_auth_apps_for_user
  end

  def create
    @api_key = Current.session.user.api_keys.build(api_key_params)

    if @api_key.save
      flash[:api_key_token] = @api_key.plaintext_token
      redirect_to api_key_path(@api_key)
    else
      @applications = forward_auth_apps_for_user
      render :new, status: :unprocessable_entity
    end
  end

  def show
    @api_key = Current.session.user.api_keys.find(params[:id])
    @plaintext_token = flash[:api_key_token]

    redirect_to api_keys_path unless @plaintext_token
  end

  def destroy
    @api_key.revoke!
    redirect_to api_keys_path, notice: "API key revoked."
  end

  private

  def set_api_key
    @api_key = Current.session.user.api_keys.find(params[:id])
  end

  def api_key_params
    params.require(:api_key).permit(:name, :application_id, :expires_at)
  end

  def forward_auth_apps_for_user
    user = Current.session.user
    Application.forward_auth.active.select { |app| app.user_allowed?(user) }
  end
end
