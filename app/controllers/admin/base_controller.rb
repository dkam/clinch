module Admin
  class BaseController < ApplicationController
    before_action :require_admin

    private

    def require_admin
      user = Current.session&.user
      unless user&.admin?
        redirect_to root_path, alert: "You must be an administrator to access this page."
      end
    end

    # Admin mutations are the highest-blast-radius actions in the product and
    # were the only ones leaving no trace at all: ForwardAuth logs every routine
    # access decision (see Api::ForwardAuthController) while creating an
    # application, moving someone into a group or rewriting a user's email
    # logged nothing whatsoever.
    #
    # This is deliberately not an audit log — no table, no retention policy, no
    # query UI. It is the cheap half: one greppable line in the stream you
    # already collect, saying who did what to which record from where. That is
    # enough to reconstruct an admin session after the fact, which is the part
    # that matters when there is only one administrator and accountability
    # between admins is moot.
    # The set of user ids currently holding administrator access.
    def admin_user_ids
      User.joins(:groups).where(groups: {admin: true}).distinct.pluck(:id).to_set
    end

    # Both the user form and the group form can move someone into or out of the
    # administrator set, and flipping a group's own `admin` flag moves everyone
    # in it at once. So detection works on the resulting set of admin user ids
    # rather than on whichever field happened to be edited — a notification that
    # only fired on one of those screens would be bypassable from the other,
    # which is worse than not having it, since it invites trust it hasn't earned.
    #
    # Recipients are the affected user plus every other administrator. The actor
    # is left out; they just made the change.
    def notify_admin_access_delta(before_ids, fallback_group: nil)
      after_ids = admin_user_ids
      changed = (before_ids | after_ids) - (before_ids & after_ids)
      return if changed.empty?

      actor = Current.session.user
      context = security_event_context
      admin_emails = User.where(id: after_ids.to_a).pluck(:email_address)

      User.where(id: changed.to_a).find_each do |user|
        granted = after_ids.include?(user.id)
        group = granted ? user.groups.reload.find(&:admin?) : fallback_group
        recipients = ([user.email_address] + admin_emails).uniq - [actor.email_address]

        recipients.each do |recipient|
          SecurityMailer.admin_access_changed(
            user,
            recipient: recipient,
            granted: granted,
            group_name: group&.name || "an administrator group",
            actor_email: actor.email_address,
            **context
          ).deliver_later
        end
      end
    end

    def log_admin_action(action, record, **details)
      actor = Current.session&.user&.email_address || "unknown"
      label = record.try(:email_address) || record.try(:name)
      suffix = details.map { |k, v| "#{k}=#{v}" }.join(" ")

      Rails.logger.info(
        "Admin: #{actor} #{action} #{record.class.name}##{record.id} " \
        "(#{label}) from #{request.remote_ip} #{suffix}".squish
      )
    end
  end
end
