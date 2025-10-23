class CreateForwardAuthRules < ActiveRecord::Migration[8.1]
  def change
    create_table :forward_auth_rules do |t|
      t.string :domain_pattern
      t.integer :policy
      t.boolean :active

      t.timestamps
    end
  end
end
