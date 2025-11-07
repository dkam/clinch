import { Controller } from "@hotwired/stimulus"

/**
 * Manages form error display and dismissal
 * Provides consistent error handling across all forms
 */
export default class extends Controller {
  static targets = ["container"]

  /**
   * Dismisses the error container with a smooth fade-out animation
   */
  dismiss() {
    if (!this.hasContainerTarget) return

    // Add transition classes
    this.containerTarget.classList.add('transition-all', 'duration-300', 'opacity-0', 'transform', 'scale-95')

    // Remove from DOM after animation completes
    setTimeout(() => {
      this.containerTarget.remove()
    }, 300)
  }

  /**
   * Shows server-side validation errors after form submission
   * Auto-focuses the first error field for better accessibility
   */
  connect() {
    // Auto-focus first error field if errors exist
    this.focusFirstErrorField()

    // Scroll to errors if needed
    this.scrollToErrors()
  }

  /**
   * Focuses the first field with validation errors
   */
  focusFirstErrorField() {
    if (!this.hasContainerTarget) return

    // Find first form field with errors (look for error classes or aria-invalid)
    const form = this.element.closest('form')
    if (!form) return

    const errorField = form.querySelector('[aria-invalid="true"], .border-red-500, .ring-red-500')
    if (errorField) {
      setTimeout(() => {
        errorField.focus()
        errorField.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }, 100)
    }
  }

  /**
   * Scrolls error container into view if it's not visible
   */
  scrollToErrors() {
    if (!this.hasContainerTarget) return

    const rect = this.containerTarget.getBoundingClientRect()
    const isInViewport = rect.top >= 0 && rect.left >= 0 &&
                        rect.bottom <= window.innerHeight &&
                        rect.right <= window.innerWidth

    if (!isInViewport) {
      setTimeout(() => {
        this.containerTarget.scrollIntoView({
          behavior: 'smooth',
          block: 'start',
          inline: 'nearest'
        })
      }, 100)
    }
  }

  /**
   * Auto-dismisses success messages after a delay
   * Can be called from other controllers
   */
  autoDismiss(delay = 5000) {
    if (!this.hasContainerTarget) return

    setTimeout(() => {
      this.dismiss()
    }, delay)
  }
}