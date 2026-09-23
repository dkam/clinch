Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  resources :invitations, param: :token, only: [:show, :update]
  resources :email_confirmations, param: :token, only: [:create, :show, :update]
  mount ActionCable.server => "/cable"

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", :as => :rails_health_check

  # Authentication routes
  get "/signup", to: "users#new", as: :signup
  post "/signup", to: "users#create"
  get "/signin", to: "sessions#new", as: :signin
  post "/signin", to: "sessions#create"
  delete "/signout", to: "sessions#destroy", as: :signout
  get "/totp-verification", to: "sessions#verify_totp", as: :totp_verification
  post "/totp-verification", to: "sessions#verify_totp"

  # WebAuthn authentication routes
  post "/sessions/webauthn/challenge", to: "sessions#webauthn_challenge"
  post "/sessions/webauthn/verify", to: "sessions#webauthn_verify"

  # OIDC (OpenID Connect) routes
  get "/.well-known/openid-configuration", to: "oidc#discovery"
  # RFC 8414 OAuth 2.0 Authorization Server Metadata (alias of OIDC discovery;
  # MCP clients look here). OIDC discovery is a superset of the RFC 8414 fields.
  get "/.well-known/oauth-authorization-server", to: "oidc#discovery"
  get "/.well-known/jwks.json", to: "oidc#jwks"
  # RFC 7591 Dynamic Client Registration
  post "/oauth/register", to: "oidc_registration#create"
  match "/oauth/authorize", to: "oidc#authorize", via: [:get, :post]
  post "/oauth/authorize/consent", to: "oidc#consent", as: :oauth_consent
  post "/oauth/token", to: "oidc#token"
  post "/oauth/revoke", to: "oidc#revoke"
  post "/oauth/introspect", to: "oidc#introspect"
  match "/oauth/userinfo", to: "oidc#userinfo", via: [:get, :post]
  get "/logout", to: "oidc#logout"

  # OAuth 2.0 Device Authorization Grant (RFC 8628)
  post "/oauth/device_authorization", to: "oidc#device_authorization"
  get "/device", to: "device_authorizations#show", as: :device_verification
  post "/device", to: "device_authorizations#verify"

  # ForwardAuth / Trusted Header SSO
  namespace :api do
    get "/verify", to: "forward_auth#verify"
    post "/csp-violation-report", to: "csp#violation_report"
  end

  # Authenticated routes
  resources :api_keys, only: [:index, :new, :create, :show, :destroy]

  root "dashboard#index"
  resource :profile, only: [:show, :update] do
    member do
      delete :revoke_consent
      delete :revoke_all_consents
    end
  end
  resource :active_sessions, only: [:show] do
    member do
      delete :logout_from_app
      delete :revoke_consent
      delete :revoke_all_consents
    end
  end
  resources :sessions, only: [] do
    member do
      delete :destroy, action: :destroy_other
    end
  end

  # TOTP (2FA) routes
  get "/totp/new", to: "totp#new", as: :new_totp
  post "/totp", to: "totp#create", as: :totp
  delete "/totp", to: "totp#destroy"
  get "/totp/backup_codes", to: "totp#backup_codes", as: :backup_codes_totp
  post "/totp/verify_password", to: "totp#verify_password", as: :verify_password_totp
  get "/totp/regenerate_backup_codes", to: "totp#regenerate_backup_codes", as: :regenerate_backup_codes_totp
  post "/totp/regenerate_backup_codes", to: "totp#create_new_backup_codes", as: :create_new_backup_codes_totp
  post "/totp/complete_setup", to: "totp#complete_setup", as: :complete_totp_setup

  # WebAuthn (Passkeys) routes
  get "/webauthn/new", to: "webauthn#new", as: :new_webauthn
  post "/webauthn/challenge", to: "webauthn#challenge"
  post "/webauthn/create", to: "webauthn#create"
  delete "/webauthn/:id", to: "webauthn#destroy", as: :webauthn_credential
  get "/webauthn/check", to: "webauthn#check"

  # Admin routes
  namespace :admin do
    root "dashboard#index"
    resources :users do
      member do
        post :resend_invitation
        post :update_application_claims
        delete :delete_application_claims
      end
    end
    resources :applications do
      member do
        post :regenerate_credentials
      end
    end
    resources :groups
    get "access", to: "access_checks#new"
    # Runtime toggle for the RFC 7591 dynamic client registration window.
    resource :dynamic_client_registration, only: [:update], controller: "dynamic_client_registration"
  end

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker
end
