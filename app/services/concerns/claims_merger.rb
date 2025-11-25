module ClaimsMerger
  extend ActiveSupport::Concern

  # Deep merge claims, combining arrays instead of overwriting them
  # This ensures that array values (like roles) are combined across group/user/app claims
  #
  # Example:
  #   base = { "roles" => ["user"], "level" => 1 }
  #   incoming = { "roles" => ["admin"], "department" => "IT" }
  #   deep_merge_claims(base, incoming)
  #   # => { "roles" => ["user", "admin"], "level" => 1, "department" => "IT" }
  def deep_merge_claims(base, incoming)
    result = base.dup

    incoming.each do |key, value|
      if result.key?(key)
        # If both values are arrays, combine them (union to avoid duplicates)
        if result[key].is_a?(Array) && value.is_a?(Array)
          result[key] = (result[key] + value).uniq
        # If both values are hashes, recursively merge them
        elsif result[key].is_a?(Hash) && value.is_a?(Hash)
          result[key] = deep_merge_claims(result[key], value)
        else
          # Otherwise, incoming value wins (override)
          result[key] = value
        end
      else
        # New key, just add it
        result[key] = value
      end
    end

    result
  end
end
