class TotpMailer < ApplicationMailer
  def enabled(user)
    @user = user
    mail subject: "Two-factor authentication enabled on your account",
         to: user.email_address
  end
end
