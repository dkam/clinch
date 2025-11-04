import { Controller } from "@hotwired/stimulus";

export default class extends Controller {
  static targets = ["sidebarOverlay", "button"];

  connect() {
    // Initialize mobile sidebar functionality
  }

  openSidebar() {
    if (this.hasSidebarOverlayTarget) {
      this.sidebarOverlayTarget.classList.remove('hidden');
    }
  }

  closeSidebar() {
    if (this.hasSidebarOverlayTarget) {
      this.sidebarOverlayTarget.classList.add('hidden');
    }
  }
}