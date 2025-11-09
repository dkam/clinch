class FixEmptyDomainPatterns < ActiveRecord::Migration[8.1]
  def up
    # Convert empty string domain_patterns to NULL
    # This fixes a unique constraint issue where multiple OIDC apps
    # had empty string domain_patterns, causing uniqueness violations
    execute <<-SQL
      UPDATE applications
      SET domain_pattern = NULL
      WHERE domain_pattern = ''
    SQL
  end

  def down
    # No need to reverse this - empty strings and NULL are functionally equivalent
    # for OIDC applications where domain_pattern is not used
  end
end
