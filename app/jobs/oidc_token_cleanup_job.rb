class OidcTokenCleanupJob < ApplicationJob
  queue_as :default

  def perform
    # Delete expired access tokens (keep revoked ones for audit trail)
    expired_access_tokens = OidcAccessToken.where("expires_at < ?", 7.days.ago)
    deleted_count = expired_access_tokens.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} expired access tokens"

    # Delete expired refresh tokens (keep revoked ones for audit trail)
    expired_refresh_tokens = OidcRefreshToken.where("expires_at < ?", 7.days.ago)
    deleted_count = expired_refresh_tokens.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} expired refresh tokens"

    # Delete old revoked tokens (after 30 days for audit trail)
    old_revoked_access_tokens = OidcAccessToken.where("revoked_at < ?", 30.days.ago)
    deleted_count = old_revoked_access_tokens.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} old revoked access tokens"

    old_revoked_refresh_tokens = OidcRefreshToken.where("revoked_at < ?", 30.days.ago)
    deleted_count = old_revoked_refresh_tokens.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} old revoked refresh tokens"

    # Delete old used authorization codes (after 7 days)
    old_auth_codes = OidcAuthorizationCode.where("created_at < ?", 7.days.ago)
    deleted_count = old_auth_codes.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} old authorization codes"

    # Delete expired device codes (RFC 8628). They have a ~10 minute TTL and no
    # audit value; a redeemed code is already destroyed at token issuance. Once
    # expired a code can never be redeemed, so this single expiry sweep clears the
    # expired, denied, and abandoned rows that would otherwise accumulate forever
    # (anonymous callers can create them via /oauth/device_authorization). The
    # short grace keeps this clear of any in-flight redemption near expiry.
    expired_device_codes = OidcDeviceCode.where("expires_at < ?", 1.hour.ago)
    deleted_count = expired_device_codes.delete_all
    Rails.logger.info "OIDC Token Cleanup: Deleted #{deleted_count} expired device codes"
  end
end
