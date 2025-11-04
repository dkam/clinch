import { Controller } from "@hotwired/stimulus";

export default class extends Controller {
  static targets = ["sidebarOverlay"];

  connect() {
    // Initialize mobile sidebar functionality
    // Add escape key listener to close sidebar
    this.boundHandleEscape = this.handleEscape.bind(this);
    document.addEventListener('keydown', this.boundHandleEscape);
  }

  disconnect() {
    // Clean up event listeners
    document.removeEventListener('keydown', this.boundHandleEscape);
  }

  openSidebar() {
    if (this.hasSidebarOverlayTarget) {
      this.sidebarOverlayTarget.classList.remove('hidden');
      // Prevent body scroll when sidebar is open
      document.body.style.overflow = 'hidden';
    }
  }

  closeSidebar() {
    if (this.hasSidebarOverlayTarget) {
      this.sidebarOverlayTarget.classList.add('hidden');
      // Restore body scroll
      document.body.style.overflow = '';
    }
  }

  // Close sidebar when clicking on the overlay background
  closeOnBackgroundClick(event) {
    // Check if the click is on the overlay background (the semi-transparent layer)
    if (event.target === this.sidebarOverlayTarget || event.target.classList.contains('bg-gray-900/80')) {
      this.closeSidebar();
    }
  }

  // Handle escape key to close sidebar
  handleEscape(event) {
    if (event.key === 'Escape' && this.hasSidebarOverlayTarget && !this.sidebarOverlayTarget.classList.contains('hidden')) {
      this.closeSidebar();
    }
  }
}