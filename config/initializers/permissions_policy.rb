# Configure the Permissions-Policy header
# See https://api.rubyonrails.org/classes/ActionDispatch/PermissionsPolicy.html

Rails.application.config.permissions_policy do |f|
  # Disable sensitive browser features for security
  f.camera :none
  f.gyroscope :none
  f.microphone :none
  f.payment :none
  f.usb :none
  f.magnetometer :none

  # You can enable specific features as needed:
  # f.fullscreen      :self
  # f.geolocation     :self

  # You can also allow specific origins:
  # f.payment         :self, "https://secure.example.com"
end
