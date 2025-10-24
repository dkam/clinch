# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2025_10_24_055739) do
  create_table "application_groups", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.integer "group_id", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id", "group_id"], name: "index_application_groups_on_application_id_and_group_id", unique: true
    t.index ["application_id"], name: "index_application_groups_on_application_id"
    t.index ["group_id"], name: "index_application_groups_on_group_id"
  end

  create_table "application_roles", force: :cascade do |t|
    t.boolean "active", default: true
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.text "description"
    t.string "display_name"
    t.string "name", null: false
    t.json "permissions", default: {}
    t.datetime "updated_at", null: false
    t.index ["application_id", "name"], name: "index_application_roles_on_application_id_and_name", unique: true
    t.index ["application_id"], name: "index_application_roles_on_application_id"
  end

  create_table "applications", force: :cascade do |t|
    t.boolean "active", default: true, null: false
    t.string "app_type", null: false
    t.string "client_id"
    t.string "client_secret_digest"
    t.datetime "created_at", null: false
    t.text "description"
    t.json "managed_permissions", default: {}
    t.text "metadata"
    t.string "name", null: false
    t.text "redirect_uris"
    t.string "role_claim_name", default: "roles"
    t.string "role_mapping_mode", default: "disabled", null: false
    t.string "role_prefix"
    t.string "slug", null: false
    t.datetime "updated_at", null: false
    t.index ["active"], name: "index_applications_on_active"
    t.index ["client_id"], name: "index_applications_on_client_id", unique: true
    t.index ["slug"], name: "index_applications_on_slug", unique: true
  end

  create_table "forward_auth_rule_groups", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "forward_auth_rule_id", null: false
    t.integer "group_id", null: false
    t.datetime "updated_at", null: false
    t.index ["forward_auth_rule_id"], name: "index_forward_auth_rule_groups_on_forward_auth_rule_id"
    t.index ["group_id"], name: "index_forward_auth_rule_groups_on_group_id"
  end

  create_table "forward_auth_rules", force: :cascade do |t|
    t.boolean "active"
    t.datetime "created_at", null: false
    t.string "domain_pattern"
    t.integer "policy"
    t.datetime "updated_at", null: false
  end

  create_table "groups", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "index_groups_on_name", unique: true
  end

  create_table "oidc_access_tokens", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.string "scope"
    t.string "token", null: false
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id", "user_id"], name: "index_oidc_access_tokens_on_application_id_and_user_id"
    t.index ["application_id"], name: "index_oidc_access_tokens_on_application_id"
    t.index ["expires_at"], name: "index_oidc_access_tokens_on_expires_at"
    t.index ["token"], name: "index_oidc_access_tokens_on_token", unique: true
    t.index ["user_id"], name: "index_oidc_access_tokens_on_user_id"
  end

  create_table "oidc_authorization_codes", force: :cascade do |t|
    t.integer "application_id", null: false
    t.string "code", null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.string "nonce"
    t.string "redirect_uri", null: false
    t.string "scope"
    t.datetime "updated_at", null: false
    t.boolean "used", default: false, null: false
    t.integer "user_id", null: false
    t.index ["application_id", "user_id"], name: "index_oidc_authorization_codes_on_application_id_and_user_id"
    t.index ["application_id"], name: "index_oidc_authorization_codes_on_application_id"
    t.index ["code"], name: "index_oidc_authorization_codes_on_code", unique: true
    t.index ["expires_at"], name: "index_oidc_authorization_codes_on_expires_at"
    t.index ["user_id"], name: "index_oidc_authorization_codes_on_user_id"
  end

  create_table "oidc_user_consents", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.datetime "granted_at", null: false
    t.text "scopes_granted", null: false
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id"], name: "index_oidc_user_consents_on_application_id"
    t.index ["granted_at"], name: "index_oidc_user_consents_on_granted_at"
    t.index ["user_id", "application_id"], name: "index_oidc_user_consents_on_user_id_and_application_id", unique: true
    t.index ["user_id"], name: "index_oidc_user_consents_on_user_id"
  end

  create_table "sessions", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "device_name"
    t.datetime "expires_at"
    t.string "ip_address"
    t.datetime "last_activity_at"
    t.boolean "remember_me", default: false, null: false
    t.datetime "updated_at", null: false
    t.string "user_agent"
    t.integer "user_id", null: false
    t.index ["expires_at"], name: "index_sessions_on_expires_at"
    t.index ["last_activity_at"], name: "index_sessions_on_last_activity_at"
    t.index ["user_id"], name: "index_sessions_on_user_id"
  end

  create_table "user_groups", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "group_id", null: false
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["group_id"], name: "index_user_groups_on_group_id"
    t.index ["user_id", "group_id"], name: "index_user_groups_on_user_id_and_group_id", unique: true
    t.index ["user_id"], name: "index_user_groups_on_user_id"
  end

  create_table "user_role_assignments", force: :cascade do |t|
    t.integer "application_role_id", null: false
    t.datetime "created_at", null: false
    t.json "metadata", default: {}
    t.string "source", default: "oidc"
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_role_id"], name: "index_user_role_assignments_on_application_role_id"
    t.index ["user_id", "application_role_id"], name: "index_user_role_assignments_on_user_id_and_application_role_id", unique: true
    t.index ["user_id"], name: "index_user_role_assignments_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.boolean "admin", default: false, null: false
    t.text "backup_codes"
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.string "password_digest", null: false
    t.integer "status", default: 0, null: false
    t.boolean "totp_required", default: false, null: false
    t.string "totp_secret"
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
    t.index ["status"], name: "index_users_on_status"
  end

  add_foreign_key "application_groups", "applications"
  add_foreign_key "application_groups", "groups"
  add_foreign_key "application_roles", "applications"
  add_foreign_key "forward_auth_rule_groups", "forward_auth_rules"
  add_foreign_key "forward_auth_rule_groups", "groups"
  add_foreign_key "oidc_access_tokens", "applications"
  add_foreign_key "oidc_access_tokens", "users"
  add_foreign_key "oidc_authorization_codes", "applications"
  add_foreign_key "oidc_authorization_codes", "users"
  add_foreign_key "oidc_user_consents", "applications"
  add_foreign_key "oidc_user_consents", "users"
  add_foreign_key "sessions", "users"
  add_foreign_key "user_groups", "groups"
  add_foreign_key "user_groups", "users"
  add_foreign_key "user_role_assignments", "application_roles"
  add_foreign_key "user_role_assignments", "users"
end
