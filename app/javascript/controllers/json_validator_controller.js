import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["textarea", "status"]
  static classes = ["valid", "invalid", "validStatus", "invalidStatus"]

  connect() {
    this.validate()
  }

  validate() {
    const value = this.textareaTarget.value.trim()

    if (!value) {
      this.clearStatus()
      return true
    }

    try {
      JSON.parse(value)
      this.showValid()
      return true
    } catch (error) {
      this.showInvalid(error.message)
      return false
    }
  }

  format() {
    const value = this.textareaTarget.value.trim()

    if (!value) return

    try {
      const parsed = JSON.parse(value)
      const formatted = JSON.stringify(parsed, null, 2)
      this.textareaTarget.value = formatted
      this.showValid()
    } catch (error) {
      this.showInvalid(error.message)
    }
  }

  clearStatus() {
    this.textareaTarget.classList.remove(...this.invalidClasses)
    this.textareaTarget.classList.remove(...this.validClasses)
    if (this.hasStatusTarget) {
      this.statusTarget.textContent = ""
      this.statusTarget.classList.remove(...this.validStatusClasses, ...this.invalidStatusClasses)
    }
  }

  showValid() {
    this.textareaTarget.classList.remove(...this.invalidClasses)
    this.textareaTarget.classList.add(...this.validClasses)
    if (this.hasStatusTarget) {
      this.statusTarget.textContent = "✓ Valid JSON"
      this.statusTarget.classList.remove(...this.invalidStatusClasses)
      this.statusTarget.classList.add(...this.validStatusClasses)
    }
  }

  showInvalid(errorMessage) {
    this.textareaTarget.classList.remove(...this.validClasses)
    this.textareaTarget.classList.add(...this.invalidClasses)
    if (this.hasStatusTarget) {
      this.statusTarget.textContent = `✗ Invalid JSON: ${errorMessage}`
      this.statusTarget.classList.remove(...this.validStatusClasses)
      this.statusTarget.classList.add(...this.invalidStatusClasses)
    }
  }

  insertSample(event) {
    event.preventDefault()
    const sample = event.params.json || event.target.dataset.jsonSample
    if (sample) {
      this.textareaTarget.value = sample
      this.format()
    }
  }
}