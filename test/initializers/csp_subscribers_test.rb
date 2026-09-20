require "test_helper"
require "minitest/mock"

# Rails 8.1 emits structured events for every request, query and render
# (controller.request_started, active_record.sql, ...) as soon as Rails.event
# has any subscriber. The CSP subscribers must only act on "csp.violation",
# otherwise every health check turns into a "CSP Violation: " report.
class CspSubscribersTest < ActiveSupport::TestCase
  FRAMEWORK_EVENT = {
    name: "controller.request_started",
    payload: {controller: "Rails::HealthController", action: "show", format: :html},
    tags: {},
    context: {}
  }.freeze

  CSP_EVENT = {
    name: "csp.violation",
    payload: {
      violated_directive: "script-src",
      blocked_uri: "https://evil.example.com/x.js",
      document_uri: "https://clinch.example.com/signin"
    },
    tags: {},
    context: {}
  }.freeze

  test "Sentry subscriber ignores events that are not CSP violations" do
    captured = []
    Sentry.stub(:capture_message, ->(message, **) { captured << message }) do
      CspViolationSentrySubscriber.emit(FRAMEWORK_EVENT)
    end
    assert_empty captured, "a framework event must not be reported to Sentry"
  end

  test "Sentry subscriber reports CSP violation events" do
    captured = []
    Sentry.stub(:capture_message, ->(message, **) { captured << message }) do
      CspViolationSentrySubscriber.emit(CSP_EVENT)
    end
    assert_equal ["CSP Violation: script-src - Blocked: https://evil.example.com/x.js - On: https://clinch.example.com/signin"], captured
  end

  test "local logger ignores events that are not CSP violations" do
    logged = []
    fake_logger = Object.new
    fake_logger.define_singleton_method(:log) { |level, msg| logged << msg }

    CspViolationLocalLogger.stub(:csp_logger, fake_logger) do
      # Same name as a real CSP event's payload keys, but the wrong event name:
      # the name, not the payload shape, decides whether it is a violation.
      CspViolationLocalLogger.emit(FRAMEWORK_EVENT.merge(payload: {document_uri: "/up"}))
    end
    assert_empty logged, "a framework event must not be written to csp_violations.log"
  end

  test "local logger writes CSP violation events" do
    logged = []
    fake_logger = Object.new
    fake_logger.define_singleton_method(:log) { |level, msg| logged << msg }

    CspViolationLocalLogger.stub(:csp_logger, fake_logger) do
      CspViolationLocalLogger.emit(CSP_EVENT)
    end
    assert_equal 1, logged.size
    assert_match(/Directive: script-src/, logged.first)
  end

  test "subscribers registered on Rails.event only receive csp.violation" do
    Rails.event.subscribers.each do |entry|
      next unless [CspViolationSentrySubscriber, CspViolationLocalLogger].include?(entry[:subscriber])
      filter = entry[:filter]
      assert filter, "#{entry[:subscriber]} is subscribed without a filter"
      assert filter.call(CSP_EVENT)
      refute filter.call(FRAMEWORK_EVENT)
    end
  end
end
