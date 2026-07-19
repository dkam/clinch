class AddResourceIdentifiersToApplications < ActiveRecord::Migration[8.1]
  # The RFC 8707 resource identifier(s) this application serves as a resource
  # server. Used to authorize RFC 7662 introspection: a caller may only introspect
  # tokens bound to a resource it serves (or tokens issued to itself).
  def change
    add_column :applications, :resource_identifiers, :text
  end
end
