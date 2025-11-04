import { Controller } from "@hotwired/stimulus";

export default class extends Controller {
  static targets = ["nickname", "submitButton", "status", "error"];
  static values = {
    challengeUrl: String,
    createUrl: String,
    checkUrl: String
  };

  connect() {
    // Check if WebAuthn is supported
    if (!this.isWebAuthnSupported()) {
      console.warn("WebAuthn is not supported in this browser");
      return;
    }
  }

  // Check if browser supports WebAuthn
  isWebAuthnSupported() {
    return (
      window.PublicKeyCredential !== undefined &&
      typeof window.PublicKeyCredential === "function"
    );
  }

  // Check if user has passkeys (for login page)
  async checkWebAuthnSupport(event) {
    const email = event.target.value.trim();

    if (!email || !this.isValidEmail(email)) {
      return;
    }

    try {
      const response = await fetch(`${this.checkUrlValue}?email=${encodeURIComponent(email)}`);
      const data = await response.json();

      console.debug("WebAuthn check response:", data);

      if (data.has_webauthn) {
        console.debug("Dispatching webauthn-available event");
        // Trigger custom event for login form to show passkey option
        this.dispatch("webauthn-available", {
          detail: {
            hasWebauthn: data.has_webauthn,
            requiresWebauthn: data.requires_webauthn,
            preferredMethod: data.preferred_method
          }
        });

        // Auto-trigger passkey authentication if required
        if (data.requires_webauthn) {
          setTimeout(() => this.authenticate(), 100);
        }
      } else {
        console.debug("No WebAuthn credentials found for this email");
      }
    } catch (error) {
      console.error("Error checking WebAuthn support:", error);
    }
  }

  // Start registration ceremony
  async register(event) {
    event.preventDefault();

    if (!this.isWebAuthnSupported()) {
      this.showError("WebAuthn is not supported in your browser");
      return;
    }

    const nickname = this.nicknameTarget.value.trim();
    if (!nickname) {
      this.showError("Please enter a nickname for this passkey");
      return;
    }

    this.setLoading(true);
    this.clearMessages();

    try {
      // Get registration challenge from server
      const challengeResponse = await fetch(this.challengeUrlValue, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.getCSRFToken()
        }
      });

      if (!challengeResponse.ok) {
        throw new Error("Failed to get registration challenge");
      }

      const credentialCreationOptions = await challengeResponse.json();

      // Use modern Web Authentication API Level 3 to parse options
      // This automatically handles all base64url encoding/decoding
      const publicKeyOptions = PublicKeyCredential.parseCreationOptionsFromJSON(
        credentialCreationOptions
      );

      // Create credential via WebAuthn API
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      });

      if (!credential) {
        throw new Error("Failed to create credential");
      }

      // Send credential to server for verification
      // Use toJSON() to properly serialize the credential
      const credentialResponse = await fetch(this.createUrlValue, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.getCSRFToken()
        },
        body: JSON.stringify({
          credential: credential.toJSON(),
          nickname: nickname
        })
      });

      const result = await credentialResponse.json();

      if (result.success) {
        this.showSuccess(result.message);

        // Clear the form
        this.nicknameTarget.value = "";

        // Dispatch event to refresh the passkey list
        this.dispatch("passkey-registered", {
          detail: {
            nickname: nickname,
            credentialId: result.credential_id
          }
        });

        // Optionally close modal or redirect
        setTimeout(() => {
          if (window.location.pathname === "/webauthn/new") {
            window.location.href = "/profile";
          }
        }, 1500);
      } else {
        this.showError(result.error || "Failed to register passkey");
      }

    } catch (error) {
      console.error("WebAuthn registration error:", error);
      this.showError(this.getErrorMessage(error));
    } finally {
      this.setLoading(false);
    }
  }

  // Start authentication ceremony
  async authenticate(event) {
    if (event) {
      event.preventDefault();
    }

    if (!this.isWebAuthnSupported()) {
      this.showError("WebAuthn is not supported in your browser");
      return;
    }

    this.setLoading(true);
    this.clearMessages();

    try {
      // Get authentication challenge from server
      const response = await fetch("/sessions/webauthn/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.getCSRFToken()
        },
        body: JSON.stringify({
          email: this.getUserEmail()
        })
      });

      if (!response.ok) {
        throw new Error("Failed to get authentication challenge");
      }

      const credentialRequestOptions = await response.json();

      // Use modern Web Authentication API Level 3 to parse options
      // This automatically handles all base64url encoding/decoding
      const publicKeyOptions = PublicKeyCredential.parseRequestOptionsFromJSON(
        credentialRequestOptions
      );

      // Get credential via WebAuthn API
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      });

      if (!credential) {
        throw new Error("Failed to get credential");
      }

      // Send assertion to server for verification
      // Use toJSON() to properly serialize the credential
      const authResponse = await fetch("/sessions/webauthn/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.getCSRFToken()
        },
        body: JSON.stringify({
          credential: credential.toJSON(),
          email: this.getUserEmail()
        })
      });

      const result = await authResponse.json();

      if (result.success) {
        // Redirect to dashboard or intended URL
        window.location.href = result.redirect_to || "/";
      } else {
        this.showError(result.error || "Authentication failed");
      }

    } catch (error) {
      console.error("WebAuthn authentication error:", error);
      this.showError(this.getErrorMessage(error));
    } finally {
      this.setLoading(false);
    }
  }

  // UI helper methods
  setLoading(isLoading) {
    if (this.hasSubmitButtonTarget) {
      this.submitButtonTarget.disabled = isLoading;
      this.submitButtonTarget.textContent = isLoading ? "Registering..." : "Register Passkey";
    }
  }

  showSuccess(message) {
    if (this.hasStatusTarget) {
      this.statusTarget.textContent = message;
      this.statusTarget.className = "mt-2 text-sm text-green-600";
      this.statusTarget.style.display = "block";
    }
  }

  showError(message) {
    if (this.hasErrorTarget) {
      this.errorTarget.textContent = message;
      this.errorTarget.className = "mt-2 text-sm text-red-600";
      this.errorTarget.style.display = "block";
    }
  }

  clearMessages() {
    if (this.hasStatusTarget) {
      this.statusTarget.style.display = "none";
      this.statusTarget.textContent = "";
    }
    if (this.hasErrorTarget) {
      this.errorTarget.style.display = "none";
      this.errorTarget.textContent = "";
    }
  }

  getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  getUserEmail() {
    // Try multiple ways to get the user email from login form
    let emailInput = document.querySelector('input[type="email"]');
    if (!emailInput) {
      emailInput = document.querySelector('input[name="email"]');
    }
    if (!emailInput) {
      emailInput = document.querySelector('input[name="session[email_address]"]');
    }
    if (!emailInput) {
      emailInput = document.querySelector('input[name="user[email_address]"]');
    }
    return emailInput ? emailInput.value.trim() : "";
  }

  isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  getErrorMessage(error) {
    // Common WebAuthn errors
    if (error.name === "NotAllowedError") {
      return "Authentication was cancelled or timed out. Please try again.";
    }
    if (error.name === "SecurityError") {
      return "Security requirements not met. Make sure you're using HTTPS.";
    }
    if (error.name === "NotSupportedError") {
      return "This device doesn't support the requested authentication method.";
    }
    if (error.name === "InvalidStateError") {
      return "This authenticator has already been registered.";
    }

    // Fallback to error message
    return error.message || "An unexpected error occurred";
  }
}
