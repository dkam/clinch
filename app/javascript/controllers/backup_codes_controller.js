import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static values = {
    codes: Array
  }

  download() {
    const content = "Clinch Backup Codes\n" +
                    "===================\n\n" +
                    this.codesValue.join("\n") +
                    "\n\nSave these codes in a secure location."

    const blob = new Blob([content], { type: 'text/plain' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'clinch-backup-codes.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
  }

  print() {
    window.print()
  }
}