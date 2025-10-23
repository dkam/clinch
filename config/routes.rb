Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  mount ActionCable.server => "/cable"

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Authentication routes
  get "/signup", to: "users#new", as: :signup
  post "/signup", to: "users#create"
  get "/signin", to: "sessions#new", as: :signin
  post "/signin", to: "sessions#create"
  delete "/signout", to: "sessions#destroy", as: :signout
  get "/totp-verification", to: "sessions#verify_totp", as: :totp_verification
  post "/totp-verification", to: "sessions#verify_totp"

  # OIDC (OpenID Connect) routes
  get "/.well-known/openid-configuration", to: "oidc#discovery"
  get "/.well-known/jwks.json", to: "oidc#jwks"
  get "/oauth/authorize", to: "oidc#authorize"
  post "/oauth/authorize/consent", to: "oidc#consent", as: :oauth_consent
  post "/oauth/token", to: "oidc#token"
  get "/oauth/userinfo", to: "oidc#userinfo"

  # ForwardAuth / Trusted Header SSO
  namespace :api do
    get "/verify", to: "forward_auth#verify"
  end

  # Authenticated routes
  root "dashboard#index"
  resource :profile, only: [:show, :update]
  resources :sessions, only: [] do
    member do
      delete :destroy, action: :destroy_other
    end
  end

  # TOTP (2FA) routes
  get '/totp/new', to: 'totp#new', as: :new_totp
  post '/totp', to: 'totp#create', as: :totp
  delete '/totp', to: 'totp#destroy'
  get '/totp/backup_codes', to: 'totp#backup_codes', as: :backup_codes_totp
  post '/totp/verify_password', to: 'totp#verify_password', as: :verify_password_totp

  # Admin routes
  namespace :admin do
    root "dashboard#index"
    resources :users
    resources :applications do
      member do
        post :regenerate_credentials
      end
    end
    resources :groups
  end

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker
end
