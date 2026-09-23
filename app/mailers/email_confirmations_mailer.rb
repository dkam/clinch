class EmailConfirmationsMailer < ApplicationMailer
  # Sent to the address being proven — never to the account's current address
  # when a change is pending, since the point is to show the new one receives mail.
  def confirm(user)
    @user = user
    @address = user.email_awaiting_confirmation
    return if @address.nil?

    @token = user.generate_token_for(:email_confirmation)
    mail subject: "Confirm your email address", to: @address
  end
end
