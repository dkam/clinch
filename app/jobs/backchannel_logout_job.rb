class BackchannelLogoutJob < ApplicationJob
  queue_as :default

  # Network failures are retried after about 3s, then about 18s. (Rails 7.2
  # dropped :exponentially_longer, so the first failure used to crash the job
  # instead of retrying.)
  retry_on StandardError, wait: :polynomially_longer, attempts: 3

  # Everything the logout needs is passed in, not looked up: the consent, the
  # user or the application may be gone by the time this runs. See
  # OidcUserConsent#send_backchannel_logout.
  def perform(client_id:, logout_uri:, subject:, sid:)
    logout_token = OidcJwtService.generate_logout_token(client_id: client_id, subject: subject, sid: sid)

    uri = URI.parse(logout_uri)

    # SSRF guard: re-check at request time (with DNS resolution) in case the URI
    # predates the validation, or a public hostname now resolves to an internal
    # address. Abort without retrying — retries would not change the outcome.
    if PrivateAddressCheck.internal_host?(uri.host) || PrivateAddressCheck.resolves_to_internal?(uri.host)
      Rails.logger.error "BackchannelLogout: Refusing to send logout to #{logout_uri} - #{uri.host} is or resolves to a non-public address (SSRF guard)"
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
        Rails.logger.info "BackchannelLogout: Successfully sent logout notification to #{logout_uri}"
      else
        Rails.logger.warn "BackchannelLogout: #{logout_uri} returned HTTP #{response.code}"
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      Rails.logger.warn "BackchannelLogout: Timeout sending logout to #{logout_uri}: #{e.message}"
      raise # Retry on timeout
    rescue => e
      Rails.logger.error "BackchannelLogout: Failed to send logout to #{logout_uri}: #{e.class} - #{e.message}"
      raise # Retry on error
    end
  end
end
