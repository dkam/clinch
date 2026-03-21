import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["icon"]

  connect() {
    this.updateIcon()
  }

  toggle() {
    document.documentElement.classList.toggle("dark")
    const isDark = document.documentElement.classList.contains("dark")
    localStorage.setItem("theme", isDark ? "dark" : "light")
    this.updateIcon()
  }

  updateIcon() {
    const isDark = document.documentElement.classList.contains("dark")
    this.iconTargets.forEach(icon => {
      if (icon.dataset.mode === "dark") {
        icon.classList.toggle("hidden", !isDark)
      } else {
        icon.classList.toggle("hidden", isDark)
      }
    })
  }
}
