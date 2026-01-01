class InvitationsMailer < ApplicationMailer
  def invite_user(user)
    @user = user
    mail subject: "You're invited to join Clinch", to: user.email_address
  end
end
