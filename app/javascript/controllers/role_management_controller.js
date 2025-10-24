import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["userSelect", "assignLink", "editForm"]

  connect() {
    console.log("Role management controller connected")
  }

  assignRole(event) {
    event.preventDefault()

    const link = event.currentTarget
    const roleId = link.dataset.roleId
    const select = document.getElementById(`assign-user-${roleId}`)

    if (!select.value) {
      alert("Please select a user")
      return
    }

    // Update the href with the selected user ID
    const originalHref = link.href
    const newHref = originalHref.replace("PLACEHOLDER", select.value)

    // Navigate to the updated URL
    window.location.href = newHref
  }

  toggleEdit(event) {
    event.preventDefault()

    const roleId = event.currentTarget.dataset.roleId
    const editForm = document.getElementById(`edit-role-${roleId}`)

    if (editForm) {
      editForm.classList.toggle("hidden")
    }
  }

  hideEdit(event) {
    event.preventDefault()

    const roleId = event.currentTarget.dataset.roleId
    const editForm = document.getElementById(`edit-role-${roleId}`)

    if (editForm) {
      editForm.classList.add("hidden")
    }
  }
}