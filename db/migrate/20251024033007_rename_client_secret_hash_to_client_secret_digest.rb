class RenameClientSecretHashToClientSecretDigest < ActiveRecord::Migration[8.1]
  def change
    rename_column :applications, :client_secret_hash, :client_secret_digest
  end
end
