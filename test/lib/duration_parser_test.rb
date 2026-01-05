require "test_helper"

class DurationParserTest < ActiveSupport::TestCase
  # Valid formats
  test "parses seconds" do
    assert_equal 1, DurationParser.parse("1s")
    assert_equal 30, DurationParser.parse("30s")
    assert_equal 3600, DurationParser.parse("3600s")
  end

  test "parses minutes" do
    assert_equal 60, DurationParser.parse("1m")
    assert_equal 300, DurationParser.parse("5m")
    assert_equal 1800, DurationParser.parse("30m")
  end

  test "parses hours" do
    assert_equal 3600, DurationParser.parse("1h")
    assert_equal 7200, DurationParser.parse("2h")
    assert_equal 86400, DurationParser.parse("24h")
  end

  test "parses days" do
    assert_equal 86400, DurationParser.parse("1d")
    assert_equal 172800, DurationParser.parse("2d")
    assert_equal 2592000, DurationParser.parse("30d")
  end

  test "parses weeks" do
    assert_equal 604800, DurationParser.parse("1w")
    assert_equal 1209600, DurationParser.parse("2w")
  end

  test "parses months (30 days)" do
    assert_equal 2592000, DurationParser.parse("1M")
    assert_equal 5184000, DurationParser.parse("2M")
  end

  test "parses years (365 days)" do
    assert_equal 31536000, DurationParser.parse("1y")
    assert_equal 63072000, DurationParser.parse("2y")
  end

  # Plain numbers
  test "parses plain integer as seconds" do
    assert_equal 3600, DurationParser.parse(3600)
    assert_equal 300, DurationParser.parse(300)
    assert_equal 0, DurationParser.parse(0)
  end

  test "parses plain numeric string as seconds" do
    assert_equal 3600, DurationParser.parse("3600")
    assert_equal 300, DurationParser.parse("300")
    assert_equal 0, DurationParser.parse("0")
  end

  # Whitespace handling
  test "handles leading and trailing whitespace" do
    assert_equal 3600, DurationParser.parse(" 1h ")
    assert_equal 300, DurationParser.parse("  5m  ")
    assert_equal 86400, DurationParser.parse("\t1d\n")
  end

  test "handles space between number and unit" do
    assert_equal 3600, DurationParser.parse("1 h")
    assert_equal 300, DurationParser.parse("5 m")
    assert_equal 86400, DurationParser.parse("1 d")
  end

  # Case sensitivity - only lowercase units work (except M for months)
  test "lowercase units work" do
    assert_equal 1, DurationParser.parse("1s")
    assert_equal 60, DurationParser.parse("1m")  # minute (lowercase)
    assert_equal 3600, DurationParser.parse("1h")
    assert_equal 86400, DurationParser.parse("1d")
    assert_equal 604800, DurationParser.parse("1w")
    assert_equal 31536000, DurationParser.parse("1y")
  end

  test "uppercase M for months works" do
    assert_equal 2592000, DurationParser.parse("1M")  # month (uppercase)
  end

  test "returns nil for wrong case" do
    assert_nil DurationParser.parse("1S")  # Should be 1s
    assert_nil DurationParser.parse("1H")  # Should be 1h
    assert_nil DurationParser.parse("1D")  # Should be 1d
    assert_nil DurationParser.parse("1W")  # Should be 1w
    assert_nil DurationParser.parse("1Y")  # Should be 1y
  end

  # Edge cases
  test "handles zero duration" do
    assert_equal 0, DurationParser.parse("0s")
    assert_equal 0, DurationParser.parse("0m")
    assert_equal 0, DurationParser.parse("0h")
  end

  test "handles large numbers" do
    assert_equal 86400000, DurationParser.parse("1000d")
    assert_equal 360000, DurationParser.parse("100h")
  end

  # Invalid formats - should return nil (not raise)
  test "returns nil for invalid format" do
    assert_nil DurationParser.parse("invalid")
    assert_nil DurationParser.parse("1x")
    assert_nil DurationParser.parse("abc")
    assert_nil DurationParser.parse("1.5h")  # No decimals
    assert_nil DurationParser.parse("-1h")    # No negatives
    assert_nil DurationParser.parse("h1")     # Wrong order
  end

  test "returns nil for blank input" do
    assert_nil DurationParser.parse("")
    assert_nil DurationParser.parse(nil)
    assert_nil DurationParser.parse("   ")
  end

  test "returns nil for multiple units" do
    assert_nil DurationParser.parse("1h30m")  # Keep it simple, don't support this
    assert_nil DurationParser.parse("1d2h")
  end

  # String coercion
  test "handles string input" do
    assert_equal 3600, DurationParser.parse("1h")
    assert_equal 3600, DurationParser.parse(:"1h")  # Symbol
  end

  # Boundary validation (not parser's job, but good to know)
  test "parses values outside typical TTL ranges without error" do
    assert_equal 1, DurationParser.parse("1s")      # Below min access_token_ttl
    assert_equal 315360000, DurationParser.parse("10y") # Above max refresh_token_ttl
  end
end
