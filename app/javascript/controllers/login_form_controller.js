import { Controller } from "@hotwired/stimulus"

// Handles login form UI changes based on WebAuthn availability
export default class extends Controller {
  static targets = ["webauthnSection", "passwordSection", "statusMessage", "loadingOverlay"]

  connect() {
    // Listen for WebAuthn availability events from the webauthn controller
    this.element.addEventListener('webauthn:webauthn-available', this.handleWebAuthnAvailable.bind(this));

    // Listen for WebAuthn registration events (from profile page)
    this.element.addEventListener('webauthn:passkey-registered', this.handlePasskeyRegistered.bind(this));

    // Listen for authentication start/end to show/hide loading
    document.addEventListener('webauthn:authenticate-start', this.showLoading.bind(this));
    document.addEventListener('webauthn:authenticate-end', this.hideLoading.bind(this));
  }

  disconnect() {
    // Clean up event listeners
    document.removeEventListener('webauthn:authenticate-start', this.showLoading.bind(this));
    document.removeEventListener('webauthn:authenticate-end', this.hideLoading.bind(this));
  }

  handleWebAuthnAvailable(event) {
    const detail = event.detail;

    if (!this.hasWebauthnSectionTarget || !this.hasPasswordSectionTarget) {
      return;
    }

    if (detail.hasWebauthn) {
      this.webauthnSectionTarget.classList.remove('hidden');

      // If WebAuthn is required, hide password section
      if (detail.requiresWebauthn) {
        this.passwordSectionTarget.classList.add('hidden');
      } else {
        // Show both options with a divider
        this.passwordSectionTarget.classList.add('border-t', 'pt-4', 'mt-4');
        this.addOrDivider();
      }
    }
  }

  handlePasskeyRegistered(event) {
    if (!this.hasStatusMessageTarget) {
      return;
    }

    // Show success message
    this.statusMessageTarget.className = 'mt-4 p-3 rounded-md bg-green-50 text-green-800 border border-green-200';
    this.statusMessageTarget.textContent = 'Passkey registered successfully!';
    this.statusMessageTarget.classList.remove('hidden');

    // Hide after 3 seconds
    setTimeout(() => {
      this.statusMessageTarget.classList.add('hidden');
    }, 3000);
  }

  showLoading() {
    if (this.hasLoadingOverlayTarget) {
      this.loadingOverlayTarget.classList.remove('hidden');
    }
  }

  hideLoading() {
    if (this.hasLoadingOverlayTarget) {
      this.loadingOverlayTarget.classList.add('hidden');
    }
  }

  addOrDivider() {
    // Check if divider already exists
    if (this.element.querySelector('.login-divider')) {
      return;
    }

    const orDiv = document.createElement('div');
    orDiv.className = 'relative my-4 login-divider';
    orDiv.innerHTML = `
      <div class="absolute inset-0 flex items-center">
        <div class="w-full border-t border-gray-300"></div>
      </div>
      <div class="relative flex justify-center text-sm">
        <span class="px-2 bg-white text-gray-500">Or</span>
      </div>
    `;
    this.webauthnSectionTarget.parentNode.insertBefore(orDiv, this.passwordSectionTarget);
  }
}
