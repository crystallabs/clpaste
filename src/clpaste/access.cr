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
        unless meta.emails.empty? || meta.emails.includes?(id.email.downcase)
          return Result::NotAllowed
        end
      end
      return Result::NeedPin if meta.pin? && ctx.pin.to_s.empty?
      return Result::NeedPassword if meta.password? && ctx.password.to_s.empty?
      Result::Ok
    end

    # Team: any authenticated OIDC member. May they see the metadata/log?
    def self.team_meta?(meta : Meta, identity : Identity?) : Bool
      return false unless identity
      return true if identity.admin?
      return true if meta.creator.downcase == identity.email.downcase
      meta.team_meta?
    end

    # May they see the content via the team route (not counted)?
    def self.team_view?(meta : Meta, identity : Identity?) : Bool
      return false unless identity
      return false if meta.expired?
      return true if meta.creator.downcase == identity.email.downcase
      meta.team_view?
    end
  end
end
