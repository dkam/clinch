import { Controller } from "@hotwired/stimulus"

const MODES = ["system", "dark", "light"]

export default class extends Controller {
  static targets = ["icon"]

  connect() {
    this.applyTheme()
    this.updateIcon()
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
    const dark = mode === "dark" || (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches)
    document.documentElement.classList.toggle("dark", dark)
  }

  updateIcon() {
    const mode = this.currentMode()
    this.iconTargets.forEach(icon => {
      icon.classList.toggle("hidden", icon.dataset.mode !== mode)
    })
  }
}
