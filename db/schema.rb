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

ActiveRecord::Schema[8.1].define(version: 2025_11_04_042206) do
  create_table "application_groups", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.integer "group_id", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id", "group_id"], name: "index_application_groups_on_application_id_and_group_id", unique: true
    t.index ["application_id"], name: "index_application_groups_on_application_id"
    t.index ["group_id"], name: "index_application_groups_on_group_id"
  end

  create_table "applications", force: :cascade do |t|
    t.boolean "active", default: true, null: false
    t.string "app_type", null: false
    t.string "client_id"
    t.string "client_secret_digest"
    t.datetime "created_at", null: false
    t.text "description"
    t.string "domain_pattern"
    t.json "headers_config", default: {}, null: false
    t.text "metadata"
    t.string "name", null: false
    t.text "redirect_uris"
    t.string "slug", null: false
    t.datetime "updated_at", null: false
    t.index ["active"], name: "index_applications_on_active"
    t.index ["client_id"], name: "index_applications_on_client_id", unique: true
    t.index ["domain_pattern"], name: "index_applications_on_domain_pattern", unique: true, where: "domain_pattern IS NOT NULL"
    t.index ["slug"], name: "index_applications_on_slug", unique: true
  end

  create_table "groups", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.json "custom_claims", default: {}, null: false
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

  create_table "users", force: :cascade do |t|
    t.boolean "admin", default: false, null: false
    t.text "backup_codes"
    t.datetime "created_at", null: false
    t.json "custom_claims", default: {}, null: false
    t.string "email_address", null: false
    t.datetime "last_sign_in_at"
    t.string "name"
    t.string "password_digest", null: false
    t.string "preferred_2fa_method"
    t.integer "status", default: 0, null: false
    t.boolean "totp_required", default: false, null: false
    t.string "totp_secret"
    t.datetime "updated_at", null: false
    t.string "webauthn_id"
    t.boolean "webauthn_required", default: false, null: false
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
    t.index ["status"], name: "index_users_on_status"
    t.index ["webauthn_id"], name: "index_users_on_webauthn_id", unique: true
  end

  create_table "webauthn_credentials", force: :cascade do |t|
    t.string "authenticator_type"
    t.boolean "backup_eligible", default: false
    t.boolean "backup_state", default: false
    t.datetime "created_at", null: false
    t.string "external_id", null: false
    t.datetime "last_used_at"
    t.string "last_used_ip"
    t.string "nickname"
    t.string "public_key", null: false
    t.integer "sign_count", default: 0, null: false
    t.datetime "updated_at", null: false
    t.string "user_agent"
    t.integer "user_id", null: false
    t.index ["authenticator_type"], name: "index_webauthn_credentials_on_authenticator_type"
    t.index ["external_id"], name: "index_webauthn_credentials_on_external_id", unique: true
    t.index ["last_used_at"], name: "index_webauthn_credentials_on_last_used_at"
    t.index ["user_id", "external_id"], name: "index_webauthn_credentials_on_user_id_and_external_id", unique: true
    t.index ["user_id", "last_used_at"], name: "index_webauthn_credentials_on_user_id_and_last_used_at"
    t.index ["user_id"], name: "index_webauthn_credentials_on_user_id"
  end

  add_foreign_key "application_groups", "applications"
  add_foreign_key "application_groups", "groups"
  add_foreign_key "oidc_access_tokens", "applications"
  add_foreign_key "oidc_access_tokens", "users"
  add_foreign_key "oidc_authorization_codes", "applications"
  add_foreign_key "oidc_authorization_codes", "users"
  add_foreign_key "oidc_user_consents", "applications"
  add_foreign_key "oidc_user_consents", "users"
  add_foreign_key "sessions", "users"
  add_foreign_key "user_groups", "groups"
  add_foreign_key "user_groups", "users"
  add_foreign_key "webauthn_credentials", "users"
end
