# Sentry subscriber for CSP violations via Structured Event Reporting
# This subscriber only sends events to Sentry if Sentry is properly initialized

Rails.application.config.after_initialize do
  # Only register the subscriber if Sentry is available and configured
  if defined?(Sentry) && Sentry.initialized?

    module CspViolationSentrySubscriber
      def self.emit(event)
        # Extract relevant CSP violation data
        csp_data = event[:payload] || {}

        # Build a descriptive message for Sentry
        violated_directive = csp_data[:violated_directive]
        blocked_uri = csp_data[:blocked_uri]
        document_uri = csp_data[:document_uri]

        message = "CSP Violation: #{violated_directive}"
        message += " - Blocked: #{blocked_uri}" if blocked_uri.present?
        message += " - On: #{document_uri}" if document_uri.present?

        # Extract domain from blocked_uri for better classification
        blocked_domain = extract_domain(blocked_uri) if blocked_uri.present?

        # Determine severity based on violation type
        level = determine_severity(violated_directive, blocked_uri)

        # Send to Sentry with rich context
        Sentry.capture_message(
          message,
          level: level,
          tags: {
            csp_violation: true,
            violated_directive: violated_directive,
            blocked_domain: blocked_domain,
            document_domain: extract_domain(document_uri),
            user_authenticated: csp_data[:current_user_id].present?
          },
          extra: {
            # Full CSP report data
            csp_violation_details: csp_data,
            # Additional context for security analysis
            request_context: {
              user_agent: csp_data[:user_agent],
              ip_address: csp_data[:ip_address],
              session_id: csp_data[:session_id],
              timestamp: csp_data[:timestamp]
            }
          },
          user: csp_data[:current_user_id] ? { id: csp_data[:current_user_id] } : nil
        )

        # Log to Rails logger for redundancy
        Rails.logger.info "CSP violation sent to Sentry: #{message}"
      rescue => e
        # Ensure subscriber errors don't break the CSP reporting flow
        Rails.logger.error "Failed to send CSP violation to Sentry: #{e.message}"
        Rails.logger.error e.backtrace.join("\n") if Rails.env.development?
      end

      private

      # Extract domain from URI for better analysis
      def self.extract_domain(uri)
        return nil if uri.blank?

        begin
          parsed = URI.parse(uri)
          parsed.host
        rescue URI::InvalidURIError
          # Handle cases where URI might be malformed or just a path
          if uri.start_with?('/')
            nil  # It's a relative path, no domain
          else
            uri.split('/').first  # Best effort extraction
          end
        end
      end

      # Determine severity level based on violation type
      def self.determine_severity(violated_directive, blocked_uri)
        return :warning unless violated_directive.present?

        case violated_directive.to_sym
        when :script_src, :script_src_elem, :script_src_attr
          # Script violations are highest priority (XSS risk)
          :error
        when :style_src, :style_src_elem, :style_src_attr
          # Style violations are moderate risk
          :warning
        when :img_src
          # Image violations are typically lower priority
          :info
        when :connect_src
          # Network violations are important
          :warning
        when :font_src, :media_src
          # Font/media violations are lower priority
          :info
        when :frame_src, :child_src
          # Frame violations can be security critical
          :error
        when :default_src
          # Default src violations are important
          :warning
        else
          # Unknown or custom directives
          :warning
        end
      end
    end

    # Register the subscriber for CSP violation events
    Rails.event.subscribe(CspViolationSentrySubscriber)

    Rails.logger.info "CSP violation Sentry subscriber registered"
  else
    Rails.logger.info "Sentry not initialized - CSP violations will only be logged locally"
  end
end