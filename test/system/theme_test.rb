require "application_system_test_case"

class ThemeTest < ApplicationSystemTestCase
  test "system is the default mode and the toggle cycles light, dark, system" do
    visit signin_path

    # System is the default: nothing is pinned in storage, the mode buttons
    # follow the OS preference, and the system icon is shown.
    assert_equal "system", page.evaluate_script("localStorage.getItem('theme') || 'system'")
    assert page.has_css?("svg[data-dark-mode-target='icon'][data-mode='system']:not(.hidden)"),
      "a first-time visitor must be in System Mode"

    # Clicking the current state cycles to the next: system -> dark.
    find("button[data-action='click->dark-mode#toggle']").click
    assert_equal "dark", page.evaluate_script("localStorage.getItem('theme')")
    assert page.has_css?("html.dark"), "dark mode applies the .dark class"
    assert_selector "svg[data-dark-mode-target='icon'][data-mode='dark']:not(.hidden)"

    # dark -> light.
    find("button[data-action='click->dark-mode#toggle']").click
    assert_equal "light", page.evaluate_script("localStorage.getItem('theme')")
    refute page.has_css?("html.dark"), "light mode removes the .dark class"
    assert_selector "svg[data-dark-mode-target='icon'][data-mode='light']:not(.hidden)"

    # light -> system.
    find("button[data-action='click->dark-mode#toggle']").click
    assert_equal "system", page.evaluate_script("localStorage.getItem('theme')")
    assert page.has_css?("svg[data-dark-mode-target='icon'][data-mode='system']:not(.hidden)"),
      "the third click must return to System Mode rather than bounce back to dark"

    # The cycle wraps around to dark.
    find("button[data-action='click->dark-mode#toggle']").click
    assert_equal "dark", page.evaluate_script("localStorage.getItem('theme')")
    assert page.has_css?("html.dark"), "the cycle wraps around to dark"
  end
end
