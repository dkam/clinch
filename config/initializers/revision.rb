# frozen_string_literal: true

# The commit this build came from, so "which revision is actually running?" is
# answerable without guessing.
#
# The Dockerfile writes VERSION at build time from a --build-arg GIT_SHA.
# Outside a container there is no such file, so fall back to asking git — but
# only in development, because shelling out on boot is not something a deployed
# container should do, and it has a VERSION file anyway.
#
# This is deliberately a different thing from Clinch::VERSION (config/version.rb).
# Both are worth having:
#
#   version   which release is this? Survives a rebuild of the same code, and is
#             what the image tag is named after.
#   revision  which commit is this? Precise, automatic, meaningless to read, and
#             the only thing that answers "is what I just built actually running?"
#
# Named to sort before sentry.rb, which composes the two into config.release.
Rails.application.config.x.revision = begin
  version_file = Rails.root.join("VERSION")
  from_file = version_file.exist? ? version_file.read.strip.presence : nil

  from_git =
    if from_file.nil? && Rails.env.development?
      `git rev-parse --short HEAD 2>/dev/null`.strip.presence
    end

  from_file || from_git || ENV["GIT_SHA"].presence || "unknown"
end
