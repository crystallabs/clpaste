require "json"

module Clpaste
  # Everything we know about a paste except its content. Stored as JSON,
  # encrypted with the master key. After expiry only a residual subset
  # survives (see `Meta#residual`).
  class Meta
    include JSON::Serializable

    property visibility : String = "users" # guests | users | admins ("public"/"private" are legacy aliases)
    property title : String? = nil
    property creator : String = ""
    property created_at : Time = Time.utc
    property expires_at : Time? = nil
    property max_views : Int32? = nil
    property views : Int32 = 0
    property pin_hash : String? = nil
    property password_salt : String? = nil # base64; presence => password protected
    property key_wrap : String = ""        # base64; data key sealed with master or password-derived key
    property emails : Array(String) = [] of String
    property ips : Array(String) = [] of String
    property? cli_only : Bool = false
    property? team_meta : Bool = false
    property? team_view : Bool = false
    # Per-role permissions for the detail page (metadata + audit log) and the
    # uncounted peek. Default on; pastes stored before these existed behave
    # as before (author and admins allowed).
    property? author_meta : Bool = true
    property? author_view : Bool = true
    property? admin_meta : Bool = true
    property? admin_view : Bool = true
    property? log_ips : Bool = false
    property max_failures : Int32 = 0
    property text_size : Int64 = 0
    property attachments : Array(AttachmentInfo) = [] of AttachmentInfo
    # Deletion removes every trace (record, metadata, audit log), unlike
    # expiry. nil hours = never. The timer starts at expiry, or — with
    # delete_on_retrieval — restarts on every successful counted retrieval
    # (0 = delete the moment it is retrieved). delete_at is the armed deadline.
    property delete_after_hours : Float64? = nil
    property? delete_on_retrieval : Bool = false
    property delete_at : Time? = nil
    # residual
    property expired_at : Time? = nil
    property expiry_reason : String? = nil
    # Residual-only: whether the paste was PIN/password protected (the
    # hashes and salts themselves do not survive expiry).
    property? had_pin : Bool = false
    property? had_password : Bool = false

    def initialize
    end

    def pin? : Bool
      !pin_hash.nil? || had_pin?
    end

    def password? : Bool
      !password_salt.nil? || had_password?
    end

    # Canonical audience: guests | users | admins. Accepts the legacy
    # "public"/"private" values still stored in older pastes; anything
    # unrecognised falls back to "users" (the safe middle).
    def self.audience(v : String?) : String
      case v
      when "public", "guests" then "guests"
      when "admin", "admins"  then "admins"
      else                         "users"
      end
    end

    def audience : String
      Meta.audience(visibility)
    end

    # No login needed to retrieve.
    def public? : Bool
      audience == "guests"
    end

    def admins_only? : Bool
      audience == "admins"
    end

    def expired? : Bool
      !expired_at.nil?
    end

    def past_due?(now = Time.utc) : Bool
      (e = expires_at) ? e <= now : false
    end

    def remaining_views : Int32?
      (m = max_views) ? {m - views, 0}.max : nil
    end

    def remaining_time(now = Time.utc) : Time::Span?
      (e = expires_at) ? (e - now) : nil
    end

    # What survives expiry: every descriptive setting, so the detail page
    # reads the same for expired pastes. No secrets or key material — the
    # PIN hash, password salt and wrapped key are gone (only had_pin /
    # had_password record that they existed), and so is the body.
    def residual(reason : String, now = Time.utc) : Meta
      r = Meta.new
      r.visibility = visibility
      r.title = title
      r.creator = creator
      r.created_at = created_at
      r.max_views = max_views
      r.views = views
      r.emails = emails
      r.ips = ips
      r.cli_only = cli_only?
      r.max_failures = max_failures
      r.text_size = text_size
      r.attachments = attachments
      r.had_pin = pin?
      r.had_password = password?
      r.team_meta = team_meta?
      r.team_view = team_view?
      r.author_meta = author_meta?
      r.author_view = author_view?
      r.admin_meta = admin_meta?
      r.admin_view = admin_view?
      r.log_ips = log_ips?
      r.delete_after_hours = delete_after_hours
      r.delete_on_retrieval = delete_on_retrieval?
      r.delete_at = delete_at
      r.expired_at = now
      r.expiry_reason = reason
      r
    end

    # Human description of the deletion rule, nil when the paste is never deleted.
    def delete_desc : String?
      h = delete_after_hours || return
      anchor = delete_on_retrieval? ? "last view" : "expiry"
      h == 0 ? "immediately after #{anchor}" : "#{h.to_s.sub(/\.0$/, "")} h after #{anchor}"
    end

    # Short protection summary for lists.
    def flags : Array(String)
      f = [] of String
      f << audience
      f << "pin" if pin?
      f << "password" if password?
      f << "emails" unless emails.empty?
      f << "ips" unless ips.empty?
      f << "cli" if cli_only?
      f << "team-meta" if team_meta?
      f << "team-view" if team_view?
      f << "views:#{max_views}" if max_views
      f << "log-ips" if log_ips?
      f
    end
  end

  struct AttachmentInfo
    include JSON::Serializable
    property name : String
    property size : Int64
    property content_type : String

    def initialize(@name, @size, @content_type)
    end
  end

  # The encrypted payload.
  class Body
    include JSON::Serializable
    property text : String = ""
    property files : Array(Attachment) = [] of Attachment

    def initialize(@text = "", @files = [] of Attachment)
    end
  end

  class Attachment
    include JSON::Serializable
    property name : String
    property content_type : String
    @[JSON::Field(converter: Clpaste::Attachment::BytesConverter)]
    property data : Bytes

    def initialize(@name, @content_type, @data)
    end

    module BytesConverter
      def self.from_json(pull : JSON::PullParser) : Bytes
        Base64.decode(pull.read_string)
      end

      def self.to_json(value : Bytes, builder : JSON::Builder)
        builder.string(Base64.strict_encode(value))
      end
    end
  end

  struct LogEntry
    getter id : Int64
    getter paste_id : String
    getter at : Time
    getter action : String
    getter identity : String?
    getter ip : String?
    getter ua : String?
    getter channel : String
    getter detail : String?

    def initialize(@id, @paste_id, @at, @action, @identity, @ip, @ua, @channel, @detail)
    end
  end

  struct Session
    getter id : String
    getter kind : String # web | token
    getter email : String
    getter name : String
    getter created_at : Time
    getter expires_at : Time
    getter label : String
    getter? admin : Bool

    def initialize(@id, @kind, @email, @name, @created_at, @expires_at, @label, @admin)
    end

    def token? : Bool
      kind == "token"
    end
  end

  # Who is asking, and how.
  struct Identity
    getter email : String
    getter name : String
    getter? admin : Bool
    getter? via_token : Bool

    def initialize(@email, @name, @admin, @via_token)
    end
  end
end
