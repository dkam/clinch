class BackchannelLogoutJob < ApplicationJob
  queue_as :default

  # Retry with exponential backoff: 1s, 5s, 25s
  retry_on StandardError, wait: :exponentially_longer, attempts: 3

  def perform(user_id:, application_id:, consent_sid:)
    # Find the records
    user = User.find_by(id: user_id)
    application = Application.find_by(id: application_id)
    consent = OidcUserConsent.find_by(sid: consent_sid)

    # Validate we have all required data
    unless user && application && consent
      Rails.logger.warn "BackchannelLogout: Missing data - user: #{user.present?}, app: #{application.present?}, consent: #{consent.present?}"
      return
    end

    # Skip if application doesn't support backchannel logout
    unless application.supports_backchannel_logout?
      Rails.logger.debug "BackchannelLogout: Application #{application.name} doesn't support backchannel logout"
      return
    end

    # Generate the logout token
    logout_token = OidcJwtService.generate_logout_token(user, application, consent)

    # Send HTTP POST to the application's backchannel logout URI
    uri = URI.parse(application.backchannel_logout_uri)

    # SSRF guard: re-check at request time (with DNS resolution) in case the URI
    # predates the validation, or a public hostname now resolves to an internal
    # address. Abort without retrying — retries would not change the outcome.
    if PrivateAddressCheck.internal_host?(uri.host) || PrivateAddressCheck.resolves_to_internal?(uri.host)
      Rails.logger.error "BackchannelLogout: Refusing to send logout to #{application.name} - #{uri.host} is or resolves to a non-public address (SSRF guard)"
      return
    end

    begin
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 5, read_timeout: 5) do |http|
        request = Net::HTTP::Post.new(uri.path.presence || "/")
        request["Content-Type"] = "application/x-www-form-urlencoded"
        request.set_form_data({logout_token: logout_token})
        http.request(request)
      end

      if response.code.to_i == 200
        Rails.logger.info "BackchannelLogout: Successfully sent logout notification to #{application.name} (#{application.backchannel_logout_uri})"
      else
        Rails.logger.warn "BackchannelLogout: Application #{application.name} returned HTTP #{response.code} from #{application.backchannel_logout_uri}"
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      Rails.logger.warn "BackchannelLogout: Timeout sending logout to #{application.name} (#{application.backchannel_logout_uri}): #{e.message}"
      raise # Retry on timeout
    rescue => e
      Rails.logger.error "BackchannelLogout: Failed to send logout to #{application.name} (#{application.backchannel_logout_uri}): #{e.class} - #{e.message}"
      raise # Retry on error
    end
  end
end
