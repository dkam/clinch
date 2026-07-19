require "test_helper"

class OidcTokenCleanupJobTest < ActiveJob::TestCase
  include ActiveSupport::Testing::TimeHelpers

  # Regression: deleting an old authorization code while a descendant token
  # still references it must not blow up on the FK. We rely on ON DELETE
  # SET NULL so the token row survives (audit trail) with a NULL FK.
  test "deletes old authorization codes whose descendant tokens still reference them" do
    user = User.create!(email_address: "cleanup_test@example.com", password: "password123")
    application = Application.create!(
      name: "Cleanup Test App",
      slug: "cleanup-test-app",
      app_type: "oidc",
      redirect_uris: ["http://localhost/cb"].to_json,
      active: true
    )

    auth_code = nil
    travel_to(10.days.ago) do
      auth_code = OidcAuthorizationCode.create!(
        application: application,
        user: user,
        redirect_uri: "http://localhost/cb",
        scope: "openid"
      )
    end

    token = OidcAccessToken.create!(
      application: application,
      user: user,
      scope: "openid",
      oidc_authorization_code: auth_code
    )

    OidcTokenCleanupJob.new.perform

    assert_not OidcAuthorizationCode.exists?(auth_code.id),
      "old authorization code should be deleted"
    assert OidcAccessToken.exists?(token.id),
      "token row should survive for audit trail"
    assert_nil token.reload.oidc_authorization_code_id,
      "token FK should be nullified by ON DELETE SET NULL"
  ensure
    OidcRefreshToken.where(application: application).delete_all if application
    OidcAccessToken.where(application: application).delete_all if application
    OidcAuthorizationCode.where(application: application).delete_all if application
    user&.destroy
    application&.destroy
  end

  # Device codes (RFC 8628) are created by anonymous callers and would grow the
  # table without bound; the cleanup job must purge expired ones (pending, denied,
  # or abandoned) while leaving live codes alone.
  test "deletes expired device codes and keeps live ones" do
    application = Application.create!(
      name: "Device Cleanup App",
      slug: "device-cleanup-app",
      app_type: "oidc",
      is_public_client: true,
      active: true
    )

    expired_pending = nil
    expired_denied = nil
    travel_to(2.hours.ago) do
      expired_pending = OidcDeviceCode.create!(application: application, scope: "openid")
      expired_denied = OidcDeviceCode.create!(application: application, scope: "openid")
      expired_denied.deny!
    end
    live = OidcDeviceCode.create!(application: application, scope: "openid")

    OidcTokenCleanupJob.new.perform

    assert_not OidcDeviceCode.exists?(expired_pending.id), "expired pending code should be deleted"
    assert_not OidcDeviceCode.exists?(expired_denied.id), "expired denied code should be deleted"
    assert OidcDeviceCode.exists?(live.id), "live code should be kept"
  ensure
    OidcDeviceCode.where(application: application).delete_all if application
    application&.destroy
  end
end
