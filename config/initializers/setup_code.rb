# While nobody has an account, every boot prints the setup code. It is the only
# credential that exists before the first user does, and the console is the
# only place it is ever shown. See Setup.
#
# after_initialize rather than at load: the database has to be there to know
# whether anybody has signed up, and Setup.announce stays quiet if it isn't.
# Skipped during asset precompilation (the Docker build sets
# SECRET_KEY_BASE_DUMMY): there is no real secret to derive the code from, and
# asking for users would leave an empty database file in the image.
Rails.application.config.after_initialize do
  Setup.announce unless Rails.env.test? || ENV["SECRET_KEY_BASE_DUMMY"].present?
end
