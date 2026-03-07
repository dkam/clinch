Rails.application.config.forward_auth_cache =
  ActiveSupport::Cache::MemoryStore.new(size: 8.megabytes)
