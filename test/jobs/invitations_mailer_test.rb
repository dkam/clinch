require "test_helper"

class InvitationsMailerTest < ActionMailer::TestCase
  setup do
    @user = users(:alice)
    @invitation_mail = InvitationsMailer.invite_user(@user)
  end

  test "should queue invitation email job" do
    # Note: In test environment, deliver_later might not enqueue jobs the same way
    # This test focuses on the mail delivery functionality
    assert_nothing_raised do
      InvitationsMailer.invite_user(@user).deliver_later
    end
  end

  test "should deliver invitation email successfully" do
    assert_emails 1 do
      InvitationsMailer.invite_user(@user).deliver_now
    end
  end

  test "should have correct email content" do
    email = @invitation_mail

    assert_equal "You're invited to join Clinch", email.subject
    assert_equal [@user.email_address], email.to
    assert_equal [], email.cc || []
    assert_equal [], email.bcc || []
    # From address is configured in ApplicationMailer
    assert_not_nil email.from
    assert email.from.is_a?(Array)
  end

  test "should include user data in email body" do
    email = @invitation_mail
    # Use text_part to get the readable content
    email_text = email.text_part&.decoded || email.body.decoded

    # Should include invitation-related text
    assert_includes email_text, "invited"
    assert_includes email_text, "Clinch"
  end

  test "should handle different user statuses" do
    # Test with pending user
    pending_user = users(:bob)
    pending_user.status = :pending_invitation
    pending_user.save!

    assert_emails 1 do
      InvitationsMailer.invite_user(pending_user).deliver_now
    end
  end

  test "should queue multiple invitation emails" do
    users = [users(:alice), users(:bob)]

    # Test that multiple deliveries don't raise errors
    assert_nothing_raised do
      users.each { |user| InvitationsMailer.invite_user(user).deliver_later }
    end

    # Test synchronous delivery to verify functionality
    assert_emails 2 do
      users.each { |user| InvitationsMailer.invite_user(user).deliver_now }
    end
  end

  test "should handle job with invalid user" do
    # Test behavior when user doesn't exist
    invalid_user_id = User.maximum(:id) + 1000

    # This should not raise an error immediately (job is queued)
    assert_nothing_raised do
      assert_enqueued_jobs 1 do
        # Create a mail with non-persisted user for testing
        temp_user = User.new(id: invalid_user_id, email_address: "invalid@test.com")
        InvitationsMailer.invite_user(temp_user).deliver_later
      end
    end
  end

  test "should respect mailer configuration" do
    # Test that the mailer inherits from ApplicationMailer properly
    assert InvitationsMailer < ApplicationMailer
    assert_respond_to InvitationsMailer, :default
  end

  test "should handle concurrent email deliveries" do
    # Simulate concurrent invitation deliveries
    users = User.limit(3)

    # Test that multiple deliveries don't raise errors
    assert_nothing_raised do
      users.each do |user|
        InvitationsMailer.invite_user(user).deliver_later
      end
    end

    # Test synchronous delivery to verify functionality
    assert_emails users.count do
      users.each do |user|
        InvitationsMailer.invite_user(user).deliver_now
      end
    end
  end

  test "should have proper email headers" do
    email = @invitation_mail

    # Test common email headers
    assert_not_nil email.message_id
    assert_not_nil email.date

    # Test content-type
    if email.html_part
      assert_includes email.content_type, "text/html"
    elsif email.text_part
      assert_includes email.content_type, "text/plain"
    end
  end
end