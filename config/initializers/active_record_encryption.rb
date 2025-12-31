# ActiveRecord Encryption Configuration
# Encryption keys derived from SECRET_KEY_BASE (no separate key storage needed)
# Used for encrypting sensitive columns (currently: TOTP secrets)
#
# Optional: Override with env vars (for key rotation or explicit key management):
#   - ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
#   - ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
#   - ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT

# Use env vars if set, otherwise derive from SECRET_KEY_BASE (deterministic)
primary_key = ENV.fetch('ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY') do
  Rails.application.key_generator.generate_key('active_record_encryption_primary', 32)
end
deterministic_key = ENV.fetch('ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY') do
  Rails.application.key_generator.generate_key('active_record_encryption_deterministic', 32)
end
key_derivation_salt = ENV.fetch('ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT') do
  Rails.application.key_generator.generate_key('active_record_encryption_salt', 32)
end

# Configure Rails 7.1+ ActiveRecord encryption
Rails.application.config.active_record.encryption.primary_key = primary_key
Rails.application.config.active_record.encryption.deterministic_key = deterministic_key
Rails.application.config.active_record.encryption.key_derivation_salt = key_derivation_salt

# Allow unencrypted data for existing records (new/updated records will be encrypted)
# Set to false after all existing encrypted columns have been migrated
Rails.application.config.active_record.encryption.support_unencrypted_data = true
