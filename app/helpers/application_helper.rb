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

  def oidc_env_lines(application, client_secret: nil)
    lines = ["OIDC_CLIENT_ID=#{application.client_id}"]
    lines << if client_secret
      "OIDC_CLIENT_SECRET=#{client_secret}"
    elsif application.public_client?
      "OIDC_CLIENT_SECRET="
    else
      "OIDC_CLIENT_SECRET=<your-client-secret>"
    end
    lines << "OIDC_DISCOVERY_URL=#{OidcJwtService.issuer_url}"
    lines << "OIDC_PROVIDER_NAME='Clinch'"
    lines << "OIDC_REQUIRE_PKCE=#{application.requires_pkce? ? 'true' : 'false'}"
    lines
  end

  def border_class_for(type)
    case type.to_s
    when "notice" then "border-green-200 dark:border-green-700"
    when "alert", "error" then "border-red-200 dark:border-red-700"
    when "warning" then "border-yellow-200 dark:border-yellow-700"
    when "info" then "border-blue-200 dark:border-blue-700"
    else "border-gray-200 dark:border-gray-700"
    end
  end
end
