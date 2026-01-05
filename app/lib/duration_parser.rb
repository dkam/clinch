class DurationParser
  UNITS = {
    "s" => 1,          # seconds
    "m" => 60,         # minutes
    "h" => 3600,       # hours
    "d" => 86400,      # days
    "w" => 604800,     # weeks
    "M" => 2592000,    # months (30 days)
    "y" => 31536000    # years (365 days)
  }

  # Parse a duration string into seconds
  # Accepts formats: "1h", "30m", "1d", "1M" (month), "3600" (plain number)
  # Returns integer seconds or nil if invalid
  # Case-sensitive: 1s, 1m, 1h, 1d, 1w, 1M (month), 1y
  def self.parse(input)
    # Handle integers directly
    return input if input.is_a?(Integer)

    # Convert to string and strip whitespace
    str = input.to_s.strip

    # Return nil for blank input
    return nil if str.blank?

    # Try to parse as plain number (already in seconds)
    if str.match?(/^\d+$/)
      return str.to_i
    end

    # Try to parse with unit (e.g., "1h", "30m", "1M")
    # Allow optional space between number and unit
    # Case-sensitive to avoid confusion (1m = minute, 1M = month)
    match = str.match(/^(\d+)\s*([smhdwMy])$/)
    return nil unless match

    number = match[1].to_i
    unit = match[2]

    multiplier = UNITS[unit]
    return nil unless multiplier

    number * multiplier
  end
end
