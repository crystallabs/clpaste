module Clpaste
  # Pure access-policy evaluation. Given a live paste's metadata and the
  # request context, returns the first failing requirement (or Ok).
  module Access
    enum Result
      Ok
      NeedLogin  # private paste, no identity
      NotAllowed # identity not in email list
      IpBlocked
      CliOnly
      NeedPin
      NeedPassword
    end

    record Ctx,
      identity : Identity?,
      ip : String,
      cli : Bool,
      pin : String?,
      password : String?

    # Evaluates everything except secret verification (PIN/password
    # correctness is checked by the service since it may consume attempts).
    def self.check(meta : Meta, ctx : Ctx) : Result
      return Result::CliOnly if meta.cli_only? && !ctx.cli
      return Result::IpBlocked if !meta.ips.empty? && !Net.any_match?(meta.ips, ctx.ip)
      unless meta.public?
        id = ctx.identity
        return Result::NeedLogin unless id
        return Result::NotAllowed if meta.admins_only? && !id.admin?
        unless meta.emails.empty? || meta.emails.includes?(id.email.downcase)
          return Result::NotAllowed
        end
      end
      return Result::NeedPin if meta.pin? && ctx.pin.to_s.empty?
      return Result::NeedPassword if meta.password? && ctx.password.to_s.empty?
      Result::Ok
    end

    # May they see the metadata/log? Purely per-role paste permissions —
    # no built-in author or admin exemption: any role the identity holds
    # (author, admin, signed-in user) whose flag is on grants access.
    def self.team_meta?(meta : Meta, identity : Identity?) : Bool
      return false unless identity
      return true if meta.author_meta? && meta.creator.downcase == identity.email.downcase
      return true if meta.admin_meta? && identity.admin?
      meta.team_meta?
    end

    # May they see the content via the uncounted peek route? Same role
    # rules as team_meta?.
    def self.team_view?(meta : Meta, identity : Identity?) : Bool
      return false unless identity
      return false if meta.expired?
      return true if meta.author_view? && meta.creator.downcase == identity.email.downcase
      return true if meta.admin_view? && identity.admin?
      meta.team_view?
    end

    # May they manage the paste (expire it, delete it)? Author and admins
    # only, each governed by the paste's manage flag.
    def self.manage?(meta : Meta, identity : Identity?) : Bool
      return false unless identity
      return true if meta.author_manage? && meta.creator.downcase == identity.email.downcase
      meta.admin_manage? && identity.admin?
    end
  end
end
