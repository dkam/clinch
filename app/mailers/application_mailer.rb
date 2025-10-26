class ApplicationMailer < ActionMailer::Base
  default from: ENV.fetch('CLINCH_EMAIL_FROM', 'clinch@example.com'),
  layout "mailer"
end
