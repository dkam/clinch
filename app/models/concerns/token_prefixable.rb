module TokenPrefixable
  extend ActiveSupport::Concern

  class_methods do
    # Compute HMAC prefix from plaintext token
    # Returns first 8 chars of Base64url-encoded HMAC
    # Does NOT reveal anything about the token
    def compute_token_prefix(plaintext_token)
      return nil if plaintext_token.blank?

      hmac = OpenSSL::HMAC.digest('SHA256', TokenHmac::KEY, plaintext_token)
      Base64.urlsafe_encode64(hmac)[0..7]
    end

    # Find token using HMAC prefix lookup (fast, indexed)
    def find_by_token(plaintext_token)
      return nil if plaintext_token.blank?

      prefix = compute_token_prefix(plaintext_token)

      # Fast indexed lookup by HMAC prefix
      where(token_prefix: prefix).find_each do |token|
        return token if token.token_matches?(plaintext_token)
      end

      nil
    end
  end

  # Check if a plaintext token matches the hashed token
  def token_matches?(plaintext_token)
    return false if plaintext_token.blank? || token_digest.blank?

    BCrypt::Password.new(token_digest) == plaintext_token
  rescue BCrypt::Errors::InvalidHash
    false
  end

  # Generate new token with HMAC prefix
  # Sets both virtual attribute (for returning to client) and digest (for storage)
  def generate_token_with_prefix
    plaintext = SecureRandom.urlsafe_base64(48)
    self.token_prefix = self.class.compute_token_prefix(plaintext)
    self.token_digest = BCrypt::Password.create(plaintext)

    # Set the virtual attribute - different models use different names
    if respond_to?(:plaintext_token=)
      self.plaintext_token = plaintext  # OidcAccessToken
    elsif respond_to?(:token=)
      self.token = plaintext  # OidcRefreshToken
    end
  end
end
