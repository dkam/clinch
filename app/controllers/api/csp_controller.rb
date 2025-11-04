module Api
  class CspController < ApplicationController
    # CSP violation reports don't need authentication
    skip_before_action :verify_authenticity_token
    allow_unauthenticated_access

    # POST /api/csp-violation-report
    def violation_report
      # Parse CSP violation report
      report_data = JSON.parse(request.body.read)
      csp_report = report_data['csp-report']

      # Log the violation for security monitoring
      Rails.logger.warn "CSP Violation Report:"
      Rails.logger.warn "  Blocked URI: #{csp_report['blocked-uri']}"
      Rails.logger.warn "  Document URI: #{csp_report['document-uri']}"
      Rails.logger.warn "  Referrer: #{csp_report['referrer']}"
      Rails.logger.warn "  Violated Directive: #{csp_report['violated-directive']}"
      Rails.logger.warn "  Original Policy: #{csp_report['original-policy']}"
      Rails.logger.warn "  User Agent: #{request.user_agent}"
      Rails.logger.warn "  IP Address: #{request.remote_ip}"

      # Emit structured event for CSP violation
      # This allows multiple subscribers to process the event (Sentry, local logging, etc.)
      Rails.event.notify("csp.violation", {
        blocked_uri: csp_report['blocked-uri'],
        document_uri: csp_report['document-uri'],
        referrer: csp_report['referrer'],
        violated_directive: csp_report['violated-directive'],
        original_policy: csp_report['original-policy'],
        disposition: csp_report['disposition'],
        effective_directive: csp_report['effective-directive'],
        source_file: csp_report['source-file'],
        line_number: csp_report['line-number'],
        column_number: csp_report['column-number'],
        status_code: csp_report['status-code'],
        user_agent: request.user_agent,
        ip_address: request.remote_ip,
        current_user_id: Current.user&.id,
        timestamp: Time.current,
        session_id: Current.session&.id
      })

      head :no_content
    rescue JSON::ParserError => e
      Rails.logger.error "Invalid CSP violation report: #{e.message}"
      head :bad_request
    end
  end
end