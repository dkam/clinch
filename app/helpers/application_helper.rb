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

  def border_class_for(type)
    case type.to_s
    when 'notice' then 'border-green-200'
    when 'alert', 'error' then 'border-red-200'
    when 'warning' then 'border-yellow-200'
    when 'info' then 'border-blue-200'
    else 'border-gray-200'
    end
  end
end
