import { Controller } from "@hotwired/stimulus"

const MODES = ["system", "dark", "light"]

export default class extends Controller {
  static targets = ["icon"]

  connect() {
    // The layout's inline script paints the first frame; from here on this
    // controller owns the OS preference, so that following it live can stay
    // conditional on still being in system mode.
    this.media = window.matchMedia("(prefers-color-scheme: dark)")
    this.applySystemPreference = () => this.applyTheme()
    this.media.addEventListener("change", this.applySystemPreference)

    this.applyTheme()
    this.updateIcon()
  }

  disconnect() {
    this.media.removeEventListener("change", this.applySystemPreference)
  }

  toggle() {
    const current = this.currentMode()
    const next = MODES[(MODES.indexOf(current) + 1) % MODES.length]
    localStorage.setItem("theme", next)
    this.applyTheme()
    this.updateIcon()
  }

  currentMode() {
    const stored = localStorage.getItem("theme")
    return MODES.includes(stored) ? stored : "system"
  }

  applyTheme() {
    const mode = this.currentMode()
    const dark = mode === "dark" || (mode === "system" && this.media.matches)
    document.documentElement.classList.toggle("dark", dark)
  }

  updateIcon() {
    const mode = this.currentMode()
    this.iconTargets.forEach(icon => {
      icon.classList.toggle("hidden", icon.dataset.mode !== mode)
    })
  }
}
