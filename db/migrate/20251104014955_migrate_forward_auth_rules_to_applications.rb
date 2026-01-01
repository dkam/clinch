class MigrateForwardAuthRulesToApplications < ActiveRecord::Migration[8.1]
  def up
    # Temporarily define models for migration
    forward_auth_rule_class = Class.new(ActiveRecord::Base) do
      self.table_name = "forward_auth_rules"
      has_many :forward_auth_rule_groups, foreign_key: :forward_auth_rule_id, dependent: :destroy
      has_many :allowed_groups, through: :forward_auth_rule_groups, source: :group, class_name: "MigrateForwardAuthRulesToApplications::Group"
    end

    forward_auth_rule_group_class = Class.new(ActiveRecord::Base) do
      self.table_name = "forward_auth_rule_groups"
      belongs_to :forward_auth_rule, class_name: "MigrateForwardAuthRulesToApplications::ForwardAuthRule"
      belongs_to :group, class_name: "MigrateForwardAuthRulesToApplications::Group"
    end

    group_class = Class.new(ActiveRecord::Base) do
      self.table_name = "groups"
    end

    application_class = Class.new(ActiveRecord::Base) do
      self.table_name = "applications"
      has_many :application_groups, foreign_key: :application_id, dependent: :destroy
    end

    application_group_class = Class.new(ActiveRecord::Base) do
      self.table_name = "application_groups"
      belongs_to :application, class_name: "MigrateForwardAuthRulesToApplications::Application"
      belongs_to :group, class_name: "MigrateForwardAuthRulesToApplications::Group"
    end

    # Assign to constants so we can reference them
    stub_const("MigrateForwardAuthRulesToApplications::ForwardAuthRule", forward_auth_rule_class)
    stub_const("MigrateForwardAuthRulesToApplications::ForwardAuthRuleGroup", forward_auth_rule_group_class)
    stub_const("MigrateForwardAuthRulesToApplications::Group", group_class)
    stub_const("MigrateForwardAuthRulesToApplications::Application", application_class)
    stub_const("MigrateForwardAuthRulesToApplications::ApplicationGroup", application_group_class)

    # Migrate each ForwardAuthRule to an Application
    forward_auth_rule_class.find_each do |rule|
      # Create Application from ForwardAuthRule
      app = application_class.create!(
        name: rule.domain_pattern.titleize,
        slug: rule.domain_pattern.parameterize.presence || "forward-auth-#{rule.id}",
        app_type: "forward_auth",
        domain_pattern: rule.domain_pattern,
        headers_config: rule.headers_config || {},
        active: rule.active
      )

      # Migrate group associations
      forward_auth_rule_group_class.where(forward_auth_rule_id: rule.id).find_each do |far_group|
        application_group_class.create!(
          application_id: app.id,
          group_id: far_group.group_id
        )
      end
    end
  end

  def down
    # Remove all forward_auth applications created by this migration
    Application.where(app_type: "forward_auth").destroy_all
  end

  private

  def stub_const(name, value)
    parts = name.split("::")
    parts[0..-2].inject(Object) { |mod, part| mod.const_get(part) }.const_set(parts.last, value)
  end
end
