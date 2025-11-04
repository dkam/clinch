import { Controller } from "@hotwired/stimulus"

// Generic modal controller for showing/hiding modal dialogs
export default class extends Controller {
  static targets = ["dialog"]

  show(event) {
    // If called from a button with data-modal-id, find and show that modal
    const modalId = event.currentTarget?.dataset?.modalId;
    if (modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.remove("hidden");
      }
    } else if (this.hasDialogTarget) {
      // Otherwise show the dialog target
      this.dialogTarget.classList.remove("hidden");
    } else {
      // Or show this element itself
      this.element.classList.remove("hidden");
    }
  }

  hide() {
    if (this.hasDialogTarget) {
      this.dialogTarget.classList.add("hidden");
    } else {
      this.element.classList.add("hidden");
    }
  }

  // Close modal when clicking backdrop
  closeOnBackdrop(event) {
    // Only close if clicking directly on the backdrop (not child elements)
    if (event.target === this.element || event.target.classList.contains('modal-backdrop')) {
      this.hide();
    }
  }

  // Close modal on Escape key
  closeOnEscape(event) {
    if (event.key === "Escape") {
      this.hide();
    }
  }
}
