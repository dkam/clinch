# Per-account failure counting for the sign-in steps (CLN-03). The controller
# rate limits key on IP, which an attacker holding a phished password walks
# past by rotating addresses; these key on the account being guessed at.
#
# Once an account is over its limit even a correct answer is refused until the
# window ends, otherwise the limit would not bound guessing at all. The
# trade-off is that someone can hold an account's sign-in shut for an hour by
# failing at it, which is the lesser harm for a self-hosted IdP.
class SignInThrottle
  LIMITS = {
    password: 10, # per email address, whether or not an account has it
    totp: 5       # per user; the same budget backup codes already have
  }.freeze
  WINDOW = 1.hour

  def self.blocked?(step, key)
    Rails.cache.read(cache_key(step, key)).to_i >= LIMITS.fetch(step)
  end

  def self.record_failure(step, key)
    Rails.cache.increment(cache_key(step, key), 1, expires_in: WINDOW)
  end

  def self.clear(step, key)
    Rails.cache.delete(cache_key(step, key))
  end

  # Addresses are digested so the cache holds no one's email.
  def self.cache_key(step, key)
    "sign_in_throttle:#{step}:#{OpenSSL::Digest::SHA256.hexdigest(key.to_s.strip.downcase)}"
  end
  private_class_method :cache_key
end
