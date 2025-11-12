# Local file logger for CSP violations
# Provides local logging even when Sentry is not configured

Rails.application.config.after_initialize do
  # Create a dedicated logger for CSP violations
  csp_log_path = Rails.root.join("log", "csp_violations.log")

  # Configure log rotation
  csp_logger = Logger.new(
    csp_log_path,
    'daily',  # Rotate daily
    30        # Keep 30 old log files
  )

  csp_logger.level = Logger::INFO

  # Format: [TIMESTAMP] LEVEL MESSAGE
  csp_logger.formatter = proc do |severity, datetime, progname, msg|
    "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity} #{msg}\n"
  end

  module CspViolationLocalLogger
    def self.emit(event)
      csp_data = event[:payload] || {}

      # Skip logging if there's no meaningful violation data
      return if csp_data.empty? ||
                (csp_data[:violated_directive].nil? &&
                 csp_data[:blocked_uri].nil? &&
                 csp_data[:document_uri].nil?)

      # Build a structured log message
      violated_directive = csp_data[:violated_directive] || "unknown"
      blocked_uri = csp_data[:blocked_uri] || "unknown"
      document_uri = csp_data[:document_uri] || "unknown"

      # Create a comprehensive log entry
      log_message = "CSP VIOLATION DETECTED\n"
      log_message += "  Directive: #{violated_directive}\n"
      log_message += "  Blocked URI: #{blocked_uri}\n"
      log_message += "  Document URI: #{document_uri}\n"
      log_message += "  User Agent: #{csp_data[:user_agent]}\n"
      log_message += "  IP Address: #{csp_data[:ip_address]}\n"
      log_message += "  Timestamp: #{csp_data[:timestamp]}\n"

      if csp_data[:current_user_id].present?
        log_message += "  Authenticated User ID: #{csp_data[:current_user_id]}\n"
        log_message += "  Session ID: #{csp_data[:session_id]}\n"
      else
        log_message += "  User: Anonymous\n"
      end

      # Add additional details if available
      if csp_data[:source_file].present?
        log_message += "  Source File: #{csp_data[:source_file]}"
        log_message += ":#{csp_data[:line_number]}" if csp_data[:line_number].present?
        log_message += ":#{csp_data[:column_number]}" if csp_data[:column_number].present?
        log_message += "\n"
      end

      if csp_data[:referrer].present?
        log_message += "  Referrer: #{csp_data[:referrer]}\n"
      end

      # Determine severity for log level
      level = determine_log_level(csp_data[:violated_directive])

      self.csp_logger.log(level, log_message)

      # Also log to main Rails logger for visibility
      Rails.logger.info "CSP violation logged to csp_violations.log: #{violated_directive} - #{blocked_uri}"

    rescue => e
      # Ensure logger errors don't break the CSP reporting flow
      Rails.logger.error "Failed to log CSP violation to file: #{e.message}"
      Rails.logger.error e.backtrace.join("\n") if Rails.env.development?
    end

    def self.csp_logger
      @csp_logger ||= begin
        csp_log_path = Rails.root.join("log", "csp_violations.log")
        logger = Logger.new(
          csp_log_path,
          'daily',  # Rotate daily
          30        # Keep 30 old log files
        )
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity} #{msg}\n"
        end
        logger
      end
    end

    private

    def self.determine_log_level(violated_directive)
      return Logger::INFO unless violated_directive.present?

      case violated_directive.to_sym
      when :script_src, :script_src_elem, :script_src_attr, :frame_src, :child_src
        Logger::WARN  # Higher priority violations
      when :connect_src, :default_src, :style_src, :style_src_elem, :style_src_attr
        Logger::INFO   # Medium priority violations
      else
        Logger::DEBUG  # Lower priority violations
      end
    end
  end

  # Register the local logger subscriber
  Rails.event.subscribe(CspViolationLocalLogger)

  Rails.logger.info "CSP violation local logger registered - logging to: #{csp_log_path}"

  # Ensure the log file is created and writable
  begin
    # Create log file if it doesn't exist
    FileUtils.touch(csp_log_path) unless File.exist?(csp_log_path)

    # Test write to ensure permissions are correct
    csp_logger.info "CSP Logger initialized at #{Time.current}"

  rescue => e
    Rails.logger.error "Failed to initialize CSP local logger: #{e.message}"
    Rails.logger.error "CSP violations will only be sent to Sentry (if configured)"
  end
end