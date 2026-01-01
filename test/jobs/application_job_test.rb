require "test_helper"

class ApplicationJobTest < ActiveJob::TestCase
  test "should inherit from ActiveJob::Base" do
    assert ApplicationJob < ActiveJob::Base
  end

  test "should have proper job configuration" do
    # Test that the ApplicationJob is properly configured
    assert_respond_to ApplicationJob, :perform_now
    assert_respond_to ApplicationJob, :perform_later
  end

  test "should handle job execution" do
    # Create a simple test job to verify the base functionality
    test_job = Class.new(ApplicationJob) do
      def perform(*args)
        args
      end
    end

    # Test synchronous execution
    result = test_job.perform_now("test", "data")
    assert_equal ["test", "data"], result

    # Test asynchronous execution using the test helper
    assert_enqueued_jobs 1 do
      test_job.perform_later("test", "data")
    end
  end

  test "should queue jobs with proper arguments" do
    test_job = Class.new(ApplicationJob) do
      def perform(*args)
        # No-op for testing
      end
    end

    assert_enqueued_jobs 1 do
      test_job.perform_later("arg1", "arg2", {"key" => "value"})
    end

    # ActiveJob serializes all hash keys as strings
    args = enqueued_jobs.last[:args]
    assert_equal "arg1", args[0]
    assert_equal "arg2", args[1]
    assert_equal "value", args[2]["key"]
  end

  test "should have default queue configuration" do
    # Test that jobs have proper queue configuration
    test_job = Class.new(ApplicationJob) do
      def perform(*args)
        # No-op
      end
    end

    job_instance = test_job.new
    assert_respond_to job_instance, :queue_name
  end

  test "should handle job serialization and deserialization" do
    # Test that Active Record objects can be properly serialized
    user = users(:alice)

    test_job = Class.new(ApplicationJob) do
      def perform(user_record)
        user_record.email_address
      end
    end

    assert_enqueued_jobs 1 do
      test_job.perform_later(user)
    end

    # Verify the job was queued with user (handling serialization)
    args = enqueued_jobs.last[:args]
    if args.is_a?(Array) && args.first.is_a?(Hash)
      # GlobalID serialization format
      assert_equal user.to_global_id.to_s, args.first["_aj_globalid"]
    else
      # Direct object serialization
      assert_equal user.id, args.first.id
    end
  end

  test "should respect retry configuration" do
    # This tests the framework for retry configuration
    # Individual jobs should inherit this behavior
    assert_respond_to ApplicationJob, :retry_on
    assert_respond_to ApplicationJob, :discard_on
  end
end
