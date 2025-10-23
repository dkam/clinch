class TotpController < ApplicationController
  before_action :set_user
  before_action :redirect_if_totp_enabled, only: [:new, :create]
  before_action :require_totp_enabled, only: [:backup_codes, :verify_password, :destroy]

  # GET /totp/new - Show QR code to set up TOTP
  def new
    # Generate TOTP secret but don't save yet
    @totp_secret = ROTP::Base32.random
    @provisioning_uri = ROTP::TOTP.new(@totp_secret, issuer: "Clinch").provisioning_uri(@user.email_address)

    # Generate QR code
    require "rqrcode"
    @qr_code = RQRCode::QRCode.new(@provisioning_uri)
  end

  # POST /totp - Verify TOTP code and enable 2FA
  def create
    totp_secret = params[:totp_secret]
    code = params[:code]

    # Verify the code works
    totp = ROTP::TOTP.new(totp_secret)
    if totp.verify(code, drift_behind: 30, drift_ahead: 30)
      # Save the secret and generate backup codes
      @user.totp_secret = totp_secret
      @user.backup_codes = generate_backup_codes
      @user.save!

      # Redirect to backup codes page with success message
      redirect_to backup_codes_totp_path, notice: "Two-factor authentication has been enabled successfully! Save these backup codes now."
    else
      redirect_to new_totp_path, alert: "Invalid verification code. Please try again."
    end
  end

  # GET /totp/backup_codes - Show backup codes (requires password)
  def backup_codes
    # This will be shown after password verification
    @backup_codes = @user.parsed_backup_codes
  end

  # POST /totp/verify_password - Verify password before showing backup codes
  def verify_password
    if @user.authenticate(params[:password])
      redirect_to backup_codes_totp_path
    else
      redirect_to profile_path, alert: "Incorrect password."
    end
  end

  # DELETE /totp - Disable TOTP (requires password)
  def destroy
    unless @user.authenticate(params[:password])
      redirect_to profile_path, alert: "Incorrect password. Could not disable 2FA."
      return
    end

    @user.disable_totp!
    redirect_to profile_path, notice: "Two-factor authentication has been disabled."
  end

  private

  def set_user
    @user = Current.session.user
  end

  def redirect_if_totp_enabled
    if @user.totp_enabled?
      redirect_to profile_path, alert: "Two-factor authentication is already enabled."
    end
  end

  def require_totp_enabled
    unless @user.totp_enabled?
      redirect_to profile_path, alert: "Two-factor authentication is not enabled."
    end
  end

  def generate_backup_codes
    Array.new(10) { SecureRandom.alphanumeric(8).upcase }.to_json
  end
end
