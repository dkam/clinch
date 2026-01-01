# Code coverage must be started before loading application code
if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start "rails" do
    add_filter "/test/"
    add_filter "/config/"
    add_filter "/vendor/"

    add_group "Models", "app/models"
    add_group "Controllers", "app/controllers"
    add_group "Services", "app/services"
    add_group "Jobs", "app/jobs"
    add_group "Mailers", "app/mailers"

    # Minimum coverage thresholds (can be adjusted)
    # minimum_coverage 90
  end
end

ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require_relative "test_helpers/session_test_helper"

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    # Disable parallelization when running coverage (SimpleCov incompatible with parallel tests)
    parallelize(workers: :number_of_processors) unless ENV["COVERAGE"]

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...
  end
end
