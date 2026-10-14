# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# db:prepare runs this on the first boot of every new install, and anything it
# prints ends up in the container's logs. Clinch needs no seeded records: the
# admins group is created with the first account (Setup.create_admin), and
# OAuth clients, including CLI or introspection clients for the device flow
# (docs/decisions/0002-device-authorization-grant.md), are created in the admin
# panel.
