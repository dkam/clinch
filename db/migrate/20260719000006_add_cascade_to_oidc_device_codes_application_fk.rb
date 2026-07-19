class AddCascadeToOidcDeviceCodesApplicationFk < ActiveRecord::Migration[8.1]
  # Deleting an application left its oidc_device_codes orphaned, tripping this
  # FK and 500ing the destroy. Mirror application_user_claims: cascade at the DB
  # level so the delete is safe even if the model-layer cascade is bypassed.
  def up
    remove_foreign_key :oidc_device_codes, :applications
    add_foreign_key :oidc_device_codes, :applications, on_delete: :cascade
  end

  def down
    remove_foreign_key :oidc_device_codes, :applications
    add_foreign_key :oidc_device_codes, :applications
  end
end
