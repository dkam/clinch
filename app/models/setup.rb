# The first user cannot be invited: there is nobody here to invite them. So
# while the instance has no users at all, Clinch prints a setup code to the
# server's console, and /signup accepts it. Being able to read that console is
# the only credential that exists before anybody has an account — without it,
# whoever reaches a freshly deployed instance first would become its admin.
#
# The code is derived from secret_key_base rather than stored, so every process
# agrees on it without a shared table, file or cache, and it is never written
# down anywhere. The moment one user exists, setup closes: the code stops being
# printed, and /signup redirects to sign in.
class Setup
  # No 0/O/1/I: this gets read off a terminal and typed into a browser. 32
  # divides 256 evenly, so folding a random byte into it stays uniform.
  ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ".freeze
  LENGTH = 12
  GROUP = 4

  class << self
    def open?
      !User.exists?
    end

    def code
      @code ||= Rails.application.key_generator.generate_key("clinch/setup code", LENGTH)
        .each_byte.map { |byte| ALPHABET[byte % ALPHABET.size] }.join
        .scan(/.{#{GROUP}}/).join("-")
    end

    # Generous about how it was typed — case, spaces, the dashes we printed —
    # and constant-time about whether it was right.
    def correct?(given)
      ActiveSupport::SecurityUtils.secure_compare(normalise(given), normalise(code))
    end

    # The first account, made a member of every admin group so someone can
    # reach the admin panel without an existing admin to grant it.
    #
    # The setup code is what keeps strangers out; only someone holding it can
    # race here. The transaction is for that someone: Rails opens it on SQLite
    # with BEGIN IMMEDIATE, so a double submit blocks at BEGIN and then finds a
    # user already there, and a failed group grant takes the user with it
    # rather than closing setup behind an account that isn't an admin.
    def create_admin(attributes)
      user = User.new(attributes)
      user.status = :active

      User.transaction do
        if User.exists?
          user.errors.add(:base, "Clinch already has an administrator. Please sign in.")
        elsif user.save
          Group.admin.where.not(id: user.group_ids).each { |group| user.groups << group }
        end
      end

      user
    end

    # Printed at boot while the instance is empty. Nothing to say once someone
    # has an account.
    def announce(io = $stdout)
      io.puts banner if open?
    rescue ActiveRecord::ActiveRecordError
      # No schema yet — this is the db:prepare that will create it, and the
      # server boots again afterwards.
    end

    def banner
      rule = "─" * 52

      <<~BANNER

        #{rule}
          Clinch has no users yet.

          Open /signup and enter this setup code:

              #{code}

          It is printed only until the first account exists.
        #{rule}

      BANNER
    end

    private

    def normalise(given)
      given.to_s.upcase.gsub(/[^A-Z0-9]/, "")
    end
  end
end
