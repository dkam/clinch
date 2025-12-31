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

ActiveRecord::Schema[8.1].define(version: 2025_12_31_060112) do
  create_table "active_storage_attachments", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "record_id", null: false
    t.string "record_type", null: false
    t.index ["blob_id"], name: "index_active_storage_attachments_on_blob_id"
    t.index ["record_type", "record_id", "name", "blob_id"], name: "index_active_storage_attachments_uniqueness", unique: true
  end

  create_table "active_storage_blobs", force: :cascade do |t|
    t.bigint "byte_size", null: false
    t.string "checksum"
    t.string "content_type"
    t.datetime "created_at", null: false
    t.string "filename", null: false
    t.string "key", null: false
    t.text "metadata"
    t.string "service_name", null: false
    t.index ["key"], name: "index_active_storage_blobs_on_key", unique: true
  end

  create_table "active_storage_variant_records", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.string "variation_digest", null: false
    t.index ["blob_id", "variation_digest"], name: "index_active_storage_variant_records_uniqueness", unique: true
  end

  create_table "application_groups", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.integer "group_id", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id", "group_id"], name: "index_application_groups_on_application_id_and_group_id", unique: true
    t.index ["application_id"], name: "index_application_groups_on_application_id"
    t.index ["group_id"], name: "index_application_groups_on_group_id"
  end

  create_table "application_user_claims", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.json "custom_claims", default: {}, null: false
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id", "user_id"], name: "index_app_user_claims_unique", unique: true
    t.index ["application_id"], name: "index_application_user_claims_on_application_id"
    t.index ["user_id"], name: "index_application_user_claims_on_user_id"
  end

  create_table "applications", force: :cascade do |t|
    t.integer "access_token_ttl", default: 3600
    t.boolean "active", default: true, null: false
    t.string "app_type", null: false
    t.string "backchannel_logout_uri"
    t.string "client_id"
    t.string "client_secret_digest"
    t.datetime "created_at", null: false
    t.text "description"
    t.string "domain_pattern"
    t.json "headers_config", default: {}, null: false
    t.integer "id_token_ttl", default: 3600
    t.string "landing_url"
    t.text "metadata"
    t.string "name", null: false
    t.text "redirect_uris"
    t.integer "refresh_token_ttl", default: 2592000
    t.boolean "require_pkce", default: true, null: false
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
    t.datetime "revoked_at"
    t.string "scope"
    t.string "token_hmac"
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id", "user_id"], name: "index_oidc_access_tokens_on_application_id_and_user_id"
    t.index ["application_id"], name: "index_oidc_access_tokens_on_application_id"
    t.index ["expires_at"], name: "index_oidc_access_tokens_on_expires_at"
    t.index ["revoked_at"], name: "index_oidc_access_tokens_on_revoked_at"
    t.index ["token_hmac"], name: "index_oidc_access_tokens_on_token_hmac", unique: true
    t.index ["user_id"], name: "index_oidc_access_tokens_on_user_id"
  end

  create_table "oidc_authorization_codes", force: :cascade do |t|
    t.string "acr"
    t.integer "application_id", null: false
    t.integer "auth_time"
    t.string "code_challenge"
    t.string "code_challenge_method"
    t.string "code_hmac", null: false
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
    t.index ["code_challenge"], name: "index_oidc_authorization_codes_on_code_challenge"
    t.index ["code_hmac"], name: "index_oidc_authorization_codes_on_code_hmac", unique: true
    t.index ["expires_at"], name: "index_oidc_authorization_codes_on_expires_at"
    t.index ["user_id"], name: "index_oidc_authorization_codes_on_user_id"
  end

  create_table "oidc_refresh_tokens", force: :cascade do |t|
    t.string "acr"
    t.integer "application_id", null: false
    t.integer "auth_time"
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.integer "oidc_access_token_id", null: false
    t.datetime "revoked_at"
    t.string "scope"
    t.integer "token_family_id"
    t.string "token_hmac"
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id", "user_id"], name: "index_oidc_refresh_tokens_on_application_id_and_user_id"
    t.index ["application_id"], name: "index_oidc_refresh_tokens_on_application_id"
    t.index ["expires_at"], name: "index_oidc_refresh_tokens_on_expires_at"
    t.index ["oidc_access_token_id"], name: "index_oidc_refresh_tokens_on_oidc_access_token_id"
    t.index ["revoked_at"], name: "index_oidc_refresh_tokens_on_revoked_at"
    t.index ["token_family_id"], name: "index_oidc_refresh_tokens_on_token_family_id"
    t.index ["token_hmac"], name: "index_oidc_refresh_tokens_on_token_hmac", unique: true
    t.index ["user_id"], name: "index_oidc_refresh_tokens_on_user_id"
  end

  create_table "oidc_user_consents", force: :cascade do |t|
    t.integer "application_id", null: false
    t.datetime "created_at", null: false
    t.datetime "granted_at", null: false
    t.text "scopes_granted", null: false
    t.string "sid"
    t.datetime "updated_at", null: false
    t.integer "user_id", null: false
    t.index ["application_id"], name: "index_oidc_user_consents_on_application_id"
    t.index ["granted_at"], name: "index_oidc_user_consents_on_granted_at"
    t.index ["sid"], name: "index_oidc_user_consents_on_sid"
    t.index ["user_id", "application_id"], name: "index_oidc_user_consents_on_user_id_and_application_id", unique: true
    t.index ["user_id"], name: "index_oidc_user_consents_on_user_id"
  end

  create_table "sessions", force: :cascade do |t|
    t.string "acr"
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
    t.json "backup_codes"
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
    t.string "username"
    t.string "webauthn_id"
    t.boolean "webauthn_required", default: false, null: false
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
    t.index ["status"], name: "index_users_on_status"
    t.index ["username"], name: "index_users_on_username", unique: true
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

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "application_groups", "applications"
  add_foreign_key "application_groups", "groups"
  add_foreign_key "application_user_claims", "applications", on_delete: :cascade
  add_foreign_key "application_user_claims", "users", on_delete: :cascade
  add_foreign_key "oidc_access_tokens", "applications"
  add_foreign_key "oidc_access_tokens", "users"
  add_foreign_key "oidc_authorization_codes", "applications"
  add_foreign_key "oidc_authorization_codes", "users"
  add_foreign_key "oidc_refresh_tokens", "applications"
  add_foreign_key "oidc_refresh_tokens", "oidc_access_tokens"
  add_foreign_key "oidc_refresh_tokens", "users"
  add_foreign_key "oidc_user_consents", "applications"
  add_foreign_key "oidc_user_consents", "users"
  add_foreign_key "sessions", "users"
  add_foreign_key "user_groups", "groups"
  add_foreign_key "user_groups", "users"
  add_foreign_key "webauthn_credentials", "users"
end
