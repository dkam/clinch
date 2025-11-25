class CreateApplicationUserClaims < ActiveRecord::Migration[8.1]
  def change
    create_table :application_user_claims do |t|
      t.references :application, null: false, foreign_key: { on_delete: :cascade }
      t.references :user, null: false, foreign_key: { on_delete: :cascade }
      t.json :custom_claims, default: {}, null: false

      t.timestamps
    end

    add_index :application_user_claims, [:application_id, :user_id], unique: true, name: 'index_app_user_claims_unique'
  end
end
