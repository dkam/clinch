module ApplicationHelper
  def smtp_configured?
    return true if Rails.env.test?

    smtp_address = ENV["SMTP_ADDRESS"]
    smtp_port = ENV["SMTP_PORT"]

    smtp_address.present? &&
    smtp_port.present? &&
    smtp_address != "localhost" &&
    !smtp_address.start_with?("127.0.0.1") &&
    !smtp_address.start_with?("localhost")
  end

  def email_delivery_method
    if Rails.env.development?
      ActionMailer::Base.delivery_method
    else
      :smtp
    end
  end
end
