# CLN-07: an address is only reported to relying parties as verified once it
# has followed a link sent to it. show/update work without a session, because
# the link may be opened on a device the person is not signed in on — the token
# is the proof. The GET only renders a button, so a mail scanner prefetching
# the link does not confirm anything.
class EmailConfirmationsController < ApplicationController
  allow_unauthenticated_access only: %i[show update]
  before_action :set_user_by_token, only: %i[show update]
  rate_limit to: 5, within: 10.minutes, only: :create, with: -> { redirect_to profile_path, alert: "Too many confirmation emails. Try again later." }
  rate_limit to: 10, within: 10.minutes, only: :update, with: -> { redirect_to signin_path, alert: "Too many attempts. Try again later." }

  # Resend: a link for the pending change, or for the current address while it
  # is unverified.
  def create
    user = Current.session.user
    address = user.email_awaiting_confirmation

    if address
      EmailConfirmationsMailer.confirm(user).deliver_later
      redirect_to profile_path, notice: "Confirmation link sent to #{address}."
    else
      redirect_to profile_path, notice: "Your email address is already verified."
    end
  end

  def show
    @address = @user.email_awaiting_confirmation
  end

  def update
    old_email = @user.email_address

    if @user.confirm_email
      notify_email_change(old_email)
      redirect_to (authenticated? ? profile_path : signin_path), notice: "#{@user.email_address} is confirmed."
    else
      redirect_to (authenticated? ? profile_path : signin_path),
        alert: "That address could not be confirmed: #{@user.errors.full_messages.to_sentence}."
    end
  end

  private

  def set_user_by_token
    @user = User.find_by_token_for(:email_confirmation, params[:token])
    redirect_to signin_path, alert: "Confirmation link is invalid or has expired." if @user.nil?
  rescue ActiveSupport::MessageVerifier::InvalidSignature
    redirect_to signin_path, alert: "Confirmation link is invalid or has expired."
  end

  def notify_email_change(old_email)
    new_email = @user.email_address
    return if old_email == new_email

    context = security_event_context
    [old_email, new_email].each do |recipient|
      SecurityMailer.email_address_changed(@user, recipient: recipient, old_email: old_email, new_email: new_email, **context).deliver_later
    end
  end
end
