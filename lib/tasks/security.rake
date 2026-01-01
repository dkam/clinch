namespace :security do
  desc "Run all security checks (brakeman + bundler-audit)"
  task all: :environment do
    Rake::Task["security:brakeman"].invoke
    Rake::Task["security:bundler_audit"].invoke
  end

  desc "Run Brakeman static security scanner"
  task brakeman: :environment do
    puts "Running Brakeman security scanner..."
    system("bin/brakeman --no-pager") || abort("Brakeman found security issues!")
  end

  desc "Run bundler-audit to check for vulnerable dependencies"
  task bundler_audit: :environment do
    puts "Running bundler-audit..."
    system("bin/bundler-audit check --update") || abort("bundler-audit found vulnerable dependencies!")
  end

  desc "Generate code coverage report (requires tests to be run with COVERAGE=1)"
  task :coverage do
    puts "Running tests with coverage..."
    ENV["COVERAGE"] = "1"
    system("bin/rails test") || abort("Tests failed!")
    puts "\nCoverage report generated at coverage/index.html"
  end
end

# Alias for convenience
desc "Run all security checks"
task security: "security:all"
