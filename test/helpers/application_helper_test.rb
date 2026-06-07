require "test_helper"

class ApplicationHelperTest < ActionView::TestCase
  test "monogram_initials picks capitals from camelCase" do
    assert_equal "SL", monogram_initials("ShelfLife")
    assert_equal "KR", monogram_initials("KavitaReader")
    assert_equal "AB", monogram_initials("AudioBookShelf") # first two of 4 capitals
  end

  test "monogram_initials falls back to first two letters when fewer than two capitals" do
    assert_equal "AU", monogram_initials("Audiobookshelf")
    assert_equal "ME", monogram_initials("metube")
    assert_equal "GI", monogram_initials("git")
  end

  test "monogram_initials handles single-character and unusual names" do
    assert_equal "X", monogram_initials("X")
    assert_equal "X1", monogram_initials("X1")
    assert_equal "?", monogram_initials("")
    assert_equal "?", monogram_initials(nil)
  end

  test "monogram_color is deterministic for the same name" do
    a = monogram_color("ShelfLife")
    b = monogram_color("ShelfLife")
    assert_equal a, b
    assert_match(/\A#[0-9a-f]{6}\z/i, a)
  end

  test "monogram_color differs for different names" do
    # not a guarantee for all pairs, but should hold for at least one pair
    assert_not_equal monogram_color("Kavita"), monogram_color("Navidrome")
  end
end
