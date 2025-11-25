import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["input", "dropzone", "preview", "previewImage", "filename", "filesize"]

  connect() {
    // Prevent default drag behaviors on the whole document
    ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
      document.body.addEventListener(eventName, this.preventDefaults, false)
    })
  }

  disconnect() {
    ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
      document.body.removeEventListener(eventName, this.preventDefaults, false)
    })
  }

  preventDefaults(e) {
    e.preventDefault()
    e.stopPropagation()
  }

  dragover(e) {
    e.preventDefault()
    e.stopPropagation()
    this.dropzoneTarget.classList.add("border-blue-500", "bg-blue-50")
  }

  dragleave(e) {
    e.preventDefault()
    e.stopPropagation()
    this.dropzoneTarget.classList.remove("border-blue-500", "bg-blue-50")
  }

  drop(e) {
    e.preventDefault()
    e.stopPropagation()
    this.dropzoneTarget.classList.remove("border-blue-500", "bg-blue-50")

    const files = e.dataTransfer.files
    if (files.length > 0) {
      // Set the file to the input element
      this.inputTarget.files = files
      this.handleFiles()
    }
  }

  handleFiles() {
    const file = this.inputTarget.files[0]
    if (!file) return

    // Validate file type
    const validTypes = ["image/png", "image/jpg", "image/jpeg", "image/gif", "image/svg+xml"]
    if (!validTypes.includes(file.type)) {
      alert("Please upload a PNG, JPG, GIF, or SVG image")
      this.clear()
      return
    }

    // Validate file size (2MB)
    if (file.size > 2 * 1024 * 1024) {
      alert("File size must be less than 2MB")
      this.clear()
      return
    }

    // Show preview
    this.filenameTarget.textContent = file.name
    this.filesizeTarget.textContent = this.formatFileSize(file.size)

    // Create preview image
    const reader = new FileReader()
    reader.onload = (e) => {
      this.previewImageTarget.src = e.target.result
      this.previewTarget.classList.remove("hidden")
    }
    reader.readAsDataURL(file)
  }

  clear(e) {
    if (e) {
      e.preventDefault()
    }
    this.inputTarget.value = ""
    this.previewTarget.classList.add("hidden")
  }

  formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes"
    const k = 1024
    const sizes = ["Bytes", "KB", "MB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i]
  }
}
