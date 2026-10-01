namespace :clinch do
  desc "Reprint the first-run setup code, while no users exist"
  task setup_code: :environment do
    abort "Clinch already has a user; setup is closed." unless Setup.open?

    puts Setup.banner
  end
end
