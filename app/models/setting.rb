# Small persisted key/value store for runtime-togglable configuration that an
# admin can flip from the UI without a redeploy (e.g. the dynamic client
# registration window). Values are stored as strings; use the typed helpers.
class Setting < ApplicationRecord
  validates :key, presence: true, uniqueness: true

  def self.get(key)
    find_by(key: key.to_s)&.value
  end

  def self.set(key, value)
    record = find_or_initialize_by(key: key.to_s)
    record.value = value.to_s
    record.save!
    value
  end

  # Returns nil if the key has never been set, so callers can distinguish
  # "unset" (fall back to a default) from an explicit false.
  def self.boolean(key)
    raw = get(key)
    return nil if raw.nil?
    ActiveModel::Type::Boolean.new.cast(raw)
  end
end
