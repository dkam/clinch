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

  # Picks 1-2 character initials for a monogram fallback when an Application
  # has no icon. Prefers capital letters (ShelfLife -> SL); falls back to the
  # first two letters of the name (Audiobookshelf -> AU).
  MONOGRAM_PALETTE = %w[
    #4f46e5 #0891b2 #16a34a #ca8a04
    #db2777 #9333ea #ea580c #475569
  ].freeze

  def monogram_initials(name)
    return "?" if name.blank?
    caps = name.scan(/[A-Z]/)
    initials = if caps.size >= 2
      caps.first(2).join
    else
      name.upcase.gsub(/[^A-Z0-9]/, "").first(2)
    end
    initials.presence || "?"
  end

  def monogram_color(name)
    return MONOGRAM_PALETTE.first if name.blank?
    index = Digest::MD5.hexdigest(name).to_i(16) % MONOGRAM_PALETTE.size
    MONOGRAM_PALETTE[index]
  end

  # Renders an application icon as a <picture> that swaps based on the user's
  # color-scheme preference. If only `icon` is attached, the same image is used
  # in both modes. Caller is responsible for ensuring at least app.icon is
  # attached; the monogram fallback handles the no-icon case separately.
  def app_icon_picture(app, class:, alt: nil)
    img_class = binding.local_variable_get(:class)
    alt ||= "#{app.name} icon"
    light = url_for(app.icon)
    dark = app.icon_dark.attached? ? url_for(app.icon_dark) : nil
    tag.picture do
      sources = []
      sources << tag.source(media: "(prefers-color-scheme: dark)", srcset: dark) if dark
      safe_join(sources + [image_tag(app.icon, class: img_class, alt: alt)])
    end
  end
end
