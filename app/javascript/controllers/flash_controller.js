import { Controller } from "@hotwired/stimulus"

/**
 * Manages flash message display, auto-dismissal, and user interactions
 * Supports different flash types with appropriate styling and behavior
 */
export default class extends Controller {
  static values = {
    autoDismiss: String, // "false" or delay in milliseconds
    type: String
  }

  connect() {
    // Auto-dismiss if enabled
    if (this.autoDismissValue && this.autoDismissValue !== "false") {
      this.scheduleAutoDismiss()
    }

    // Smooth entrance animation
    this.element.classList.add('transition-all', 'duration-300', 'ease-out')
    this.element.style.opacity = '0'
    this.element.style.transform = 'translateY(-10px)'

    // Animate in
    requestAnimationFrame(() => {
      this.element.style.opacity = '1'
      this.element.style.transform = 'translateY(0)'
    })
  }

  /**
   * Dismisses the flash message with smooth animation
   */
  dismiss() {
    // Add dismiss animation
    this.element.classList.add('transition-all', 'duration-300', 'ease-in')
    this.element.style.opacity = '0'
    this.element.style.transform = 'translateY(-10px)'

    // Remove from DOM after animation
    setTimeout(() => {
      this.element.remove()
    }, 300)
  }

  /**
   * Schedules auto-dismissal based on the configured delay
   */
  scheduleAutoDismiss() {
    const delay = parseInt(this.autoDismissValue)
    if (delay > 0) {
      setTimeout(() => {
        this.dismiss()
      }, delay)
    }
  }

  /**
   * Pause auto-dismissal on hover (for user reading)
   */
  mouseEnter() {
    if (this.autoDismissTimer) {
      clearTimeout(this.autoDismissTimer)
      this.autoDismissTimer = null
    }
  }

  /**
   * Resume auto-dismissal when hover ends
   */
  mouseLeave() {
    if (this.autoDismissValue && this.autoDismissValue !== "false") {
      this.scheduleAutoDismiss()
    }
  }

  /**
   * Handle keyboard interactions
   */
  keydown(event) {
    if (event.key === 'Escape' || event.key === 'Enter') {
      this.dismiss()
    }
  }
}