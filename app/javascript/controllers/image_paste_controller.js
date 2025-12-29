import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["input", "dropzone"]

  connect() {
    // Listen for paste events on the dropzone
    this.dropzoneTarget.addEventListener("paste", this.handlePaste.bind(this))
  }

  disconnect() {
    this.dropzoneTarget.removeEventListener("paste", this.handlePaste.bind(this))
  }

  handlePaste(e) {
    e.preventDefault()
    e.stopPropagation()

    const clipboardData = e.clipboardData || e.originalEvent.clipboardData

    // First, try to get image data
    for (let item of clipboardData.items) {
      if (item.type.indexOf("image") !== -1) {
        const blob = item.getAsFile()
        this.handleImageBlob(blob)
        return
      }
    }

    // If no image found, check for SVG text
    const text = clipboardData.getData("text/plain")
    if (text && this.isSVG(text)) {
      this.handleSVGText(text)
      return
    }
  }

  isSVG(text) {
    // Check if the text looks like SVG code
    const trimmed = text.trim()
    return trimmed.startsWith("<svg") && trimmed.includes("</svg>")
  }

  handleSVGText(svgText) {
    // Validate file size (2MB)
    const size = new Blob([svgText]).size
    if (size > 2 * 1024 * 1024) {
      alert("SVG code is too large (must be less than 2MB)")
      return
    }

    // Create a blob from the SVG text
    const blob = new Blob([svgText], { type: "image/svg+xml" })

    // Create a File object
    const file = new File([blob], `pasted-svg-${Date.now()}.svg`, {
      type: "image/svg+xml"
    })

    // Create a DataTransfer object to set files on the input
    const dataTransfer = new DataTransfer()
    dataTransfer.items.add(file)
    this.inputTarget.files = dataTransfer.files

    // Trigger change event to update preview (file-drop controller will handle it)
    const event = new Event("change", { bubbles: true })
    this.inputTarget.dispatchEvent(event)

    // Visual feedback
    this.dropzoneTarget.classList.add("border-green-500", "bg-green-50")
    setTimeout(() => {
      this.dropzoneTarget.classList.remove("border-green-500", "bg-green-50")
    }, 500)
  }

  handleImageBlob(blob) {
    // Validate file type
    const validTypes = ["image/png", "image/jpg", "image/jpeg", "image/gif", "image/svg+xml"]
    if (!validTypes.includes(blob.type)) {
      alert("Please paste a PNG, JPG, GIF, or SVG image")
      return
    }

    // Validate file size (2MB)
    if (blob.size > 2 * 1024 * 1024) {
      alert("Image size must be less than 2MB")
      return
    }

    // Create a File object from the blob with a default name
    const file = new File([blob], `pasted-image-${Date.now()}.${this.getExtension(blob.type)}`, {
      type: blob.type
    })

    // Create a DataTransfer object to set files on the input
    const dataTransfer = new DataTransfer()
    dataTransfer.items.add(file)
    this.inputTarget.files = dataTransfer.files

    // Trigger change event to update preview (file-drop controller will handle it)
    const event = new Event("change", { bubbles: true })
    this.inputTarget.dispatchEvent(event)

    // Visual feedback
    this.dropzoneTarget.classList.add("border-green-500", "bg-green-50")
    setTimeout(() => {
      this.dropzoneTarget.classList.remove("border-green-500", "bg-green-50")
    }, 500)
  }

  getExtension(mimeType) {
    const extensions = {
      "image/png": "png",
      "image/jpeg": "jpg",
      "image/jpg": "jpg",
      "image/gif": "gif",
      "image/svg+xml": "svg"
    }
    return extensions[mimeType] || "png"
  }
}
