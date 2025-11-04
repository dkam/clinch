module Api
  class CspController < ApplicationController
    # CSP violation reports don't need authentication
    skip_before_action :verify_authenticity_token
    allow_unauthenticated_access

    # POST /api/csp-violation-report
    def violation_report
      # Parse CSP violation report
      report_data = JSON.parse(request.body.read)

      # Log the violation for security monitoring
      Rails.logger.warn "CSP Violation Report:"
      Rails.logger.warn "  Blocked URI: #{report_data.dig('csp-report', 'blocked-uri')}"
      Rails.logger.warn "  Document URI: #{report_data.dig('csp-report', 'document-uri')}"
      Rails.logger.warn "  Referrer: #{report_data.dig('csp-report', 'referrer')}"
      Rails.logger.warn "  Violated Directive: #{report_data.dig('csp-report', 'violated-directive')}"
      Rails.logger.warn "  Original Policy: #{report_data.dig('csp-report', 'original-policy')}"
      Rails.logger.warn "  User Agent: #{request.user_agent}"
      Rails.logger.warn "  IP Address: #{request.remote_ip}"

      # In production, you might want to send this to a security monitoring service
      # For now, we'll just log it and return a success response

      head :no_content
    rescue JSON::ParserError => e
      Rails.logger.error "Invalid CSP violation report: #{e.message}"
      head :bad_request
    end
  end
end