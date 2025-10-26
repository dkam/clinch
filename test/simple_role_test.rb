#!/usr/bin/env ruby

# Simple test script to verify role mapping functionality
# Run with: ruby test/simple_role_test.rb

require_relative "../config/environment"

puts "🧪 Testing OIDC Role Mapping functionality..."

begin
  # Create test user
  user = User.create!(
    email_address: "test#{Time.current.to_i}@example.com",
    password: "password123",
    admin: false,
    status: :active
  )
  puts "✅ Created test user: #{user.email_address}"

  # Create test application
  application = Application.create!(
    name: "Test Role App",
    slug: "test-role-app-#{Time.current.to_i}",
    app_type: "oidc",
    role_mapping_mode: "oidc_managed"
  )
  puts "✅ Created test application: #{application.name}"

  # Create role
  role = application.application_roles.create!(
    name: "admin",
    display_name: "Administrator",
    description: "Full access role"
  )
  puts "✅ Created role: #{role.name}"

  # Test role assignment
  application.assign_role_to_user!(user, "admin", source: 'manual')
  puts "✅ Assigned role to user"

  # Verify role assignment
  unless application.user_has_role?(user, "admin")
    raise "Role should be assigned to user"
  end
  puts "✅ Verified role assignment"

  # Test role mapping engine
  claims = { "roles" => ["admin", "editor"] }
  RoleMappingEngine.sync_user_roles!(user, application, claims)
  puts "✅ Synced roles from OIDC claims"

  # Test JWT generation with roles
  token = OidcJwtService.generate_id_token(user, application)
  decoded = JWT.decode(token, nil, false).first
  unless decoded["roles"]&.include?("admin")
    raise "JWT should contain roles"
  end
  puts "✅ JWT includes roles claim"

  # Test custom claim name
  application.update!(role_claim_name: "user_roles")
  token = OidcJwtService.generate_id_token(user, application)
  decoded = JWT.decode(token, nil, false).first
  unless decoded["user_roles"]&.include?("admin")
    raise "JWT should use custom claim name"
  end
  puts "✅ Custom claim name works"

  # Test role prefix filtering
  application.update!(role_prefix: "app-")
  role.update!(name: "app-admin")
  application.assign_role_to_user!(user, "app-admin", source: 'manual')

  claims = { "roles" => ["app-admin", "external-role"] }
  RoleMappingEngine.sync_user_roles!(user, application, claims)
  unless application.user_has_role?(user, "app-admin")
    raise "Prefixed role should be assigned"
  end
  if application.user_has_role?(user, "external-role")
    raise "Non-prefixed role should be filtered"
  end
  puts "✅ Role prefix filtering works"

  # Cleanup
  user.destroy
  application.destroy
  puts "🧹 Cleaned up test data"

  puts "\n🎉 All tests passed! OIDC Role Mapping is working correctly."

rescue => e
  puts "❌ Test failed: #{e.message}"
  puts e.backtrace.first(5)
  exit 1
end

