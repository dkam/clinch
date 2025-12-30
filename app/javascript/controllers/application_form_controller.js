import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["appTypeSelect", "oidcFields", "forwardAuthFields", "pkceOptions"]

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

  updatePkceVisibility(event) {
    // Show PKCE options for confidential clients, hide for public clients
    const isPublicClient = event.target.value === "true"

    if (this.hasPkceOptionsTarget) {
      if (isPublicClient) {
        this.pkceOptionsTarget.classList.add('hidden')
      } else {
        this.pkceOptionsTarget.classList.remove('hidden')
      }
    }
  }
}