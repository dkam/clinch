import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["appTypeSelect", "oidcFields", "forwardAuthFields"]

  connect() {
    this.updateFieldVisibility()
  }

  updateFieldVisibility() {
    const appType = this.appTypeSelectTarget.value

    if (appType === 'oidc') {
      this.oidcFieldsTarget.classList.remove('hidden')
      this.forwardAuthFieldsTarget.classList.add('hidden')
    } else if (appType === 'forward_auth') {
      this.oidcFieldsTarget.classList.add('hidden')
      this.forwardAuthFieldsTarget.classList.remove('hidden')
    } else {
      this.oidcFieldsTarget.classList.add('hidden')
      this.forwardAuthFieldsTarget.classList.add('hidden')
    }
  }
}