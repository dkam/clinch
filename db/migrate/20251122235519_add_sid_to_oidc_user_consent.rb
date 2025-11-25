class AddSidToOidcUserConsent < ActiveRecord::Migration[8.1]
  def change
    add_column :oidc_user_consents, :sid, :string
    add_index :oidc_user_consents, :sid

    # Generate UUIDs for existing consent records
    reversible do |dir|
      dir.up do
        OidcUserConsent.where(sid: nil).find_each do |consent|
          consent.update_column(:sid, SecureRandom.uuid)
        end
      end
    end
  end
end
