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

  # The OS preference is emulated over CDP. It is a browser-wide setting that
  # outlives the session, so every test pins it to light before visiting and
  # teardown puts it back -- otherwise a leaked "dark" makes the next test pass
  # for the wrong reason.
  test "an explicit light choice survives the OS flipping to dark" do
    emulate_os_theme "light"
    visit signin_path

    click_toggle 2   # system -> dark -> light
    assert_equal "light", page.evaluate_script("localStorage.getItem('theme')")
    refute dark?

    emulate_os_theme "dark"

    refute dark?, "an explicit light choice must not be overridden when the OS goes dark"
    assert_selector "svg[data-dark-mode-target='icon'][data-mode='light']:not(.hidden)"
  end

  test "system mode follows the OS on a fresh visit" do
    emulate_os_theme "light"
    visit signin_path
    refute dark?

    emulate_os_theme "dark"

    assert dark?, "system mode must track the OS preference live"
  end

  test "system mode follows the OS after being re-selected on a page loaded with light pinned" do
    emulate_os_theme "light"
    visit signin_path
    page.execute_script("localStorage.setItem('theme', 'light')")
    visit signin_path

    click_toggle 1   # light -> system
    assert_equal "system", page.evaluate_script("localStorage.getItem('theme')")

    emulate_os_theme "dark"

    assert dark?, "returning to system mode must start following the OS without a reload"
  end

  test "the system-mode icon draws a whole circle" do
    visit signin_path

    # A full circle is as wide as it is tall. The half-filled version alone is
    # half as wide, which is what an arc with identical endpoints degrades to.
    box = page.evaluate_script(<<~JS)
      (function() {
        var b = document.querySelector("svg[data-mode='system']").getBBox();
        return [b.width, b.height];
      })()
    JS
    assert_operator box[0], :>, 0, "the system icon must render something"
    assert_in_delta box[0], box[1], 0.5,
      "the system icon must be a whole circle, not just the filled half"
  end

  private

  def dark?
    page.has_css?("html.dark", wait: 1)
  end

  def click_toggle(times)
    times.times { find("button[data-action='click->dark-mode#toggle']").click }
  end

  def emulate_os_theme(value)
    page.driver.browser.execute_cdp("Emulation.setEmulatedMedia",
      features: [{name: "prefers-color-scheme", value: value}])
    @os_theme_emulated = true
  end

  def teardown
    emulate_os_theme "light" if @os_theme_emulated
    super
  end
end
