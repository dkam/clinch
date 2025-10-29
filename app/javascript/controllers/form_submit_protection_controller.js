import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = [ "submit" ]

  connect() {
    // Prevent form auto-submission when browser autofills TOTP
    this.preventAutoSubmit()

    // Add double-click protection
    this.submitTarget.addEventListener('dblclick', (e) => {
      e.preventDefault()
      return false
    })
  }

  submit() {
    if (this.submitTarget.disabled) {
      return false
    }

    // Disable submit button and show loading state
    this.submitTarget.disabled = true
    this.submitTarget.textContent = 'Verifying...'
    this.submitTarget.classList.add('opacity-75', 'cursor-not-allowed')

    // Re-enable after 10 seconds in case of network issues
    setTimeout(() => {
      this.submitTarget.disabled = false
      this.submitTarget.textContent = 'Verify'
      this.submitTarget.classList.remove('opacity-75', 'cursor-not-allowed')
    }, 10000)

    // Allow the form to submit normally
    return true
  }

  preventAutoSubmit() {
    // Some browsers auto-submit forms when TOTP fields are autofilled
    // This prevents that behavior while still allowing manual submission
    const codeInput = this.element.querySelector('input[name="code"]')

    if (codeInput) {
      let hasAutoSubmitted = false

      codeInput.addEventListener('input', (e) => {
        // Check if this looks like an auto-fill event
        // Auto-fill typically fills the entire field at once
        if (e.target.value.length >= 6 && !hasAutoSubmitted) {
          // Don't auto-submit, let user click the button manually
          hasAutoSubmitted = true

          // Optionally, focus the submit button to make it obvious
          this.submitTarget.focus()
        }
      })

      // Also prevent Enter key submission on TOTP field
      codeInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault()
          this.submitTarget.click()
          return false
        }
      })
    }
  }
}