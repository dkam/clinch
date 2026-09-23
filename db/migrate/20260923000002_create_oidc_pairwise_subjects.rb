class CreateOidcPairwiseSubjects < ActiveRecord::Migration[8.1]
  # CLN-05: the pairwise `sub` lived on the consent row, so revoking consent
  # destroyed it and the next consent minted a new one — the same person became
  # a different subject to the relying party. Subjects now live in their own
  # table and outlive consent.
  #
  # Backfilled from each existing consent's sid, which is the subject relying
  # parties have been given so far.
  def up
    create_table :oidc_pairwise_subjects do |t|
      t.references :user, null: false, foreign_key: {on_delete: :cascade}
      t.references :application, null: false, foreign_key: {on_delete: :cascade}
      t.string :subject, null: false
      t.timestamps
    end
    add_index :oidc_pairwise_subjects, [:user_id, :application_id], unique: true

    execute <<~SQL
      INSERT INTO oidc_pairwise_subjects (user_id, application_id, subject, created_at, updated_at)
      SELECT user_id, application_id, sid, granted_at, granted_at
      FROM oidc_user_consents
      WHERE sid IS NOT NULL
    SQL
  end

  def down
    drop_table :oidc_pairwise_subjects
  end
end
