class ApplicationMailer < ActionMailer::Base
  default from: ENV.fetch('CLINCH_FROM_EMAIL', 'clinch@example.com')
  layout "mailer"
end
