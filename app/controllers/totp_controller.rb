class TotpController < ApplicationController
  before_action :set_user
  before_action :redirect_if_totp_enabled, only: [:new, :create]
  before_action :require_totp_enabled, only: [:backup_codes, :verify_password, :destroy]

  # GET /totp/new - Show QR code to set up TOTP
  def new
    # Check if user is being forced to set up TOTP by admin
    @totp_setup_required = session[:pending_totp_setup_user_id].present?

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
      plain_codes = @user.send(:generate_backup_codes) # Use private method from User model
      @user.save!

      # Store plain codes temporarily in session for display after redirect
      session[:temp_backup_codes] = plain_codes

      # Check if this was a required setup from login
      if session[:pending_totp_setup_user_id].present?
        session.delete(:pending_totp_setup_user_id)
        # Mark that user should be auto-signed in after viewing backup codes
        session[:auto_signin_after_forced_totp] = true
        redirect_to backup_codes_totp_path, notice: "Two-factor authentication has been enabled successfully! Save these backup codes, then you'll be signed in."
      else
        # Regular setup from profile
        redirect_to backup_codes_totp_path, notice: "Two-factor authentication has been enabled successfully! Save these backup codes now."
      end
    else
      redirect_to new_totp_path, alert: "Invalid verification code. Please try again."
    end
  end

  # GET /totp/backup_codes - Show backup codes (requires password)
  def backup_codes
    # Check if we have temporary codes from TOTP setup
    if session[:temp_backup_codes].present?
      @backup_codes = session[:temp_backup_codes]
      session.delete(:temp_backup_codes) # Clear after use

      # Check if this was a forced TOTP setup during login
      @auto_signin_pending = session[:auto_signin_after_forced_totp].present?
      if @auto_signin_pending
        session.delete(:auto_signin_after_forced_totp)
      end
    else
      # This will be shown after password verification for existing users
      # Since we can't display BCrypt hashes, redirect to regenerate
      redirect_to regenerate_backup_codes_totp_path
    end
  end

  # POST /totp/verify_password - Verify password before showing backup codes
  def verify_password
    if @user.authenticate(params[:password])
      redirect_to backup_codes_totp_path
    else
      redirect_to profile_path, alert: "Incorrect password."
    end
  end

  # GET /totp/regenerate_backup_codes - Regenerate backup codes (requires password)
  def regenerate_backup_codes
    # This will be shown after password verification
  end

  # POST /totp/regenerate_backup_codes - Actually regenerate backup codes
  def create_new_backup_codes
    unless @user.authenticate(params[:password])
      redirect_to regenerate_backup_codes_totp_path, alert: "Incorrect password."
      return
    end

    # Generate new backup codes and store BCrypt hashes
    plain_codes = @user.send(:generate_backup_codes)
    @user.save!

    # Store plain codes temporarily in session for display
    session[:temp_backup_codes] = plain_codes

    redirect_to backup_codes_totp_path, notice: "New backup codes have been generated. Save them now!"
  end

  # POST /totp/complete_setup - Complete forced TOTP setup and sign in
  def complete_setup
    # Sign in the user after they've saved their backup codes
    # This is only used when admin requires TOTP and user just set it up during login
    if session[:totp_redirect_url].present?
      session[:return_to_after_authenticating] = session.delete(:totp_redirect_url)
    end

    start_new_session_for @user
    redirect_to after_authentication_url, notice: "Two-factor authentication enabled. Signed in successfully.", allow_other_host: true
  end

  # DELETE /totp - Disable TOTP (requires password)
  def destroy
    unless @user.authenticate(params[:password])
      redirect_to profile_path, alert: "Incorrect password. Could not disable 2FA."
      return
    end

    # Prevent disabling if admin requires TOTP
    if @user.totp_required?
      redirect_to profile_path, alert: "Two-factor authentication is required by your administrator and cannot be disabled."
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
    # Allow setup if admin requires it, even if already enabled (for regeneration)
    if @user.totp_enabled? && !session[:pending_totp_setup_user_id].present?
      redirect_to profile_path, alert: "Two-factor authentication is already enabled."
    end
  end

  def require_totp_enabled
    unless @user.totp_enabled?
      redirect_to profile_path, alert: "Two-factor authentication is not enabled."
    end
  end
end
