require "log"

module Clpaste
  # Core operations on pastes: create / retrieve / expire / sweep. All
  # read-modify-write paths run under one mutex (single-process app), which
  # makes view counting and expiry race-free without DB locking
  # semantics that differ between SQLite and PostgreSQL.
  class Service
    Log = ::Log.for("clpaste")

    class Error < Exception
      getter code : String

      def initialize(@code : String, message : String)
        super(message)
      end
    end

    getter repo : Repo
    getter master : Bytes
    @lock = Mutex.new
    @tickets = {} of String => Ticket

    record Ticket, paste_id : String, body : Body, expires_at : Time

    record Input,
      title : String?,
      text : String,
      files : Array(Attachment),
      visibility : String,
      emails : Array(String),
      ips : Array(String),
      pin : String?,
      password : String?,
      max_views : Int32?,
      ttl_hours : Float64?,
      cli_only : Bool,
      team_meta : Bool,
      team_view : Bool,
      log_ips : Bool,
      max_failures : Int32,
      delete_after_hours : Float64? = nil,
      delete_on_retrieval : Bool = false

    record Created, id : String, meta : Meta, pin : String?, password : String?

    # Successful retrieval.
    record Retrieved,
      id : String,
      meta : Meta,
      body : Body,
      expired_now : Bool,
      counted : Bool,
      ticket : String?

    # Everything the caller needs to know about a request for a paste.
    record Request,
      ctx : Access::Ctx,
      channel : String, # web | cli
      ua : String?

    def initialize(@repo : Repo, @master : Bytes)
    end

    # ---- helpers ------------------------------------------------------------

    private def seal_meta(id : String, meta : Meta) : Bytes
      Crypto.seal(@master, meta.to_json.to_slice, "meta:#{id}")
    end

    def open_meta(row : Repo::Row) : Meta
      Meta.from_json(String.new(Crypto.open(@master, row.meta, "meta:#{row.id}")))
    end

    private def data_key(meta : Meta, password : String?) : Bytes
      wrap = Base64.decode(meta.key_wrap)
      if salt = meta.password_salt
        raise Error.new("need_password", "Password required") unless password
        kek = Crypto.derive(password, Base64.decode(salt))
        begin
          Crypto.open(kek, wrap, "key")
        rescue Crypto::Error
          raise Error.new("bad_password", "Wrong password")
        end
      else
        Crypto.open(@master, wrap, "key")
      end
    end

    private def open_body(id : String, row : Repo::Row, meta : Meta, password : String?) : Body
      raw = row.body || raise Error.new("gone", "Paste content is gone")
      key = data_key(meta, password)
      Body.from_json(String.new(Crypto.open(key, raw, "body:#{id}")))
    end

    def log(id : String, action : String, meta : Meta?, req : Request, detail : String? = nil)
      identity = req.ctx.identity.try(&.email) || "guest"
      ip = (meta.nil? || meta.log_ips?) ? req.ctx.ip : nil
      @repo.log(id, action, identity, ip, req.ua, req.channel, detail)
    end

    private def ipkey(meta : Meta, ip : String) : String
      meta.log_ips? ? ip : "*"
    end

    # ---- create -------------------------------------------------------------

    def create(input : Input, creator : Identity, req : Request) : Created
      input.emails.each do |e|
        raise Error.new("invalid", "Invalid email: #{e}") unless e =~ /\A[^@\s]+@[^@\s]+\z/
      end
      input.ips.each do |ip|
        raise Error.new("invalid", "Invalid IP/CIDR: #{ip}") unless Net.valid_cidr?(ip)
      end
      if (p = input.pin) && p !~ /\A[0-9]{4,8}\z/
        raise Error.new("invalid", "PIN must be 4 to 8 digits")
      end
      if input.title.to_s.empty? && input.text.empty? && input.files.empty?
        raise Error.new("invalid", "Nothing to paste: provide a title, text and/or files")
      end
      unless %w[guests users admins public private].includes?(input.visibility)
        raise Error.new("invalid", "Invalid visibility: #{input.visibility} (guests|users|admins)")
      end
      if input.files.size > Superconf.max_attachments
        raise Error.new("invalid", "Too many attachments (max #{Superconf.max_attachments})")
      end
      input.files.each do |file|
        if file.data.size.to_i64 > Superconf.max_attachment_size
          raise Error.new("invalid", "Attachment #{file.name} is too large (#{file.data.size} bytes, max #{Superconf.max_attachment_size})")
        end
      end
      total = input.text.bytesize.to_i64 + input.files.sum(&.data.size.to_i64)
      if total > Superconf.max_body_size
        raise Error.new("invalid", "Paste too large (#{total} bytes, max #{Superconf.max_body_size})")
      end

      meta = Meta.new
      meta.visibility = Meta.audience(input.visibility)
      meta.title = input.title.presence
      meta.creator = creator.email
      meta.created_at = Time.utc
      if (h = input.ttl_hours) && h > 0
        meta.expires_at = meta.created_at + (h * 3600).seconds
      end
      meta.max_views = input.max_views.try { |v| v > 0 ? v : nil }
      meta.emails = input.emails.map(&.downcase).uniq!
      meta.ips = input.ips
      meta.cli_only = input.cli_only
      meta.team_meta = input.team_meta
      meta.team_view = input.team_view
      meta.log_ips = input.log_ips
      meta.max_failures = {input.max_failures, 0}.max
      meta.delete_after_hours = input.delete_after_hours.try { |hours| hours >= 0 ? hours : nil }
      meta.delete_on_retrieval = input.delete_on_retrieval
      meta.text_size = input.text.bytesize.to_i64
      meta.attachments = input.files.map { |file| AttachmentInfo.new(file.name, file.data.size.to_i64, file.content_type) }
      meta.pin_hash = input.pin.try { |secret| Crypto.hash_secret(secret) }

      dk = Crypto.random_key
      if pw = input.password.presence
        salt = Random::Secure.random_bytes(16)
        meta.password_salt = Base64.strict_encode(salt)
        meta.key_wrap = Base64.strict_encode(Crypto.seal(Crypto.derive(pw, salt), dk, "key"))
      else
        meta.key_wrap = Base64.strict_encode(Crypto.seal(@master, dk, "key"))
      end

      body = Body.new(input.text, input.files)

      id = ""
      @lock.synchronize do
        20.times do
          id = Ids.generate
          enc_body = Crypto.seal(dk, body.to_json.to_slice, "body:#{id}")
          break if @repo.insert_paste(id, meta.expires_at, seal_meta(id, meta), enc_body)
          id = ""
        end
      end
      raise Error.new("internal", "Could not allocate a paste ID") if id.empty?
      log(id, "created", meta, req, meta.flags.join(","))
      Log.info { "paste #{id} created by #{creator.email} [#{meta.flags.join(",")}]" }
      Created.new(id, meta, input.pin, input.password.presence)
    end

    # ---- retrieve (counted: the guest/user retrieval route) -----------------

    # Raises Service::Error with codes: not_found, expired,
    # need_login, not_allowed, ip_blocked, cli_only, need_pin, bad_pin,
    # need_password, bad_password.
    def retrieve(id : String, req : Request, want_ticket : Bool) : Retrieved
      @lock.synchronize do
        row = @repo.get_paste(id) || raise Error.new("not_found", "No such paste")
        meta = open_meta(row)
        if row.state != "live" || meta.expired?
          log(id, "denied", meta, req, "already expired")
          raise expired_error(meta)
        end
        if meta.past_due?
          expire_locked(id, meta, "time limit reached", req)
          raise expired_error("time limit reached")
        end

        case Access.check(meta, req.ctx)
        in .ok?
        in .need_login?    then deny(id, meta, req, "need_login", "Login required")
        in .not_allowed?   then deny(id, meta, req, "not_allowed", "Your account is not allowed to view this paste")
        in .ip_blocked?    then deny(id, meta, req, "ip_blocked", "Not available from your network")
        in .cli_only?      then deny(id, meta, req, "cli_only", "This paste can only be retrieved with the CLI")
        in .need_pin?      then prompt(id, meta, req, "need_pin", "PIN required")
        in .need_password? then prompt(id, meta, req, "need_password", "Password required")
        end

        # Secrets: verify PIN, then unwrap key with password.
        if (h = meta.pin_hash) && !Crypto.verify_secret(req.ctx.pin.to_s, h)
          failed(id, meta, req, "bad_pin", "Wrong PIN")
        end
        body = begin
          open_body(id, row, meta, req.ctx.password)
        rescue e : Error
          failed(id, meta, req, e.code, e.message.to_s) if e.code == "bad_password"
          raise e
        end
        @repo.clear_attempts(id, ipkey(meta, req.ctx.ip))

        meta.views += 1
        # A successful retrieval (re)starts the deletion timer in
        # delete-on-retrieval mode; 0 hours deletes the paste right away.
        if meta.delete_on_retrieval? && (hours = meta.delete_after_hours)
          meta.delete_at = Time.utc + (hours * 3600).seconds
        end
        expired_now = false
        if (r = meta.remaining_views) && r <= 0
          expire_locked(id, meta, "view limit reached", req, log_it: false, delete_due: false)
          expired_now = true
        else
          @repo.update_meta(id, seal_meta(id, meta))
        end
        log(id, "view", meta, req, "views=#{meta.views}#{expired_now ? " (last)" : ""}")
        @repo.log(id, "expired", nil, nil, nil, "system", "view limit reached") if expired_now

        ticket = want_ticket && !body.files.empty? ? issue_ticket(id, body) : nil
        delete_if_due(id, meta)
        Retrieved.new(id, meta, body, expired_now, true, ticket)
      end
    end

    # ---- team / admin view (not counted) ------------------------------------

    def view_uncounted(id : String, req : Request, kind : String, want_ticket : Bool) : Retrieved
      @lock.synchronize do
        row = @repo.get_paste(id) || raise Error.new("not_found", "No such paste")
        meta = open_meta(row)
        raise expired_error(meta) if row.state != "live" || meta.expired?
        if meta.past_due?
          expire_locked(id, meta, "time limit reached", req)
          raise expired_error("time limit reached")
        end
        body = open_body(id, row, meta, req.ctx.password)
        log(id, kind, meta, req)
        ticket = want_ticket && !body.files.empty? ? issue_ticket(id, body) : nil
        Retrieved.new(id, meta, body, false, false, ticket)
      end
    end

    def meta_for(id : String) : {Repo::Row, Meta}?
      row = @repo.get_paste(id) || return
      {row, open_meta(row)}
    end

    def list_all : Array({Repo::Row, Meta})
      @repo.all_pastes.map { |row| {row, open_meta(row)} }
    end

    # ---- expiry --------------------------------------------------------

    private def expired_error(meta : Meta) : Error
      return Error.new("expired", "This paste has expired.") unless Superconf.show_meta
      when_ = meta.expired_at.try(&.to_s("%Y-%m-%d %H:%M UTC")) || "earlier"
      Error.new("expired", "This paste expired #{when_} (#{meta.expiry_reason || "unknown reason"}).")
    end

    # For a paste that expires as a consequence of this very request.
    private def expired_error(reason : String) : Error
      Error.new("expired", Superconf.show_meta ? "This paste has expired (#{reason})." : "This paste has expired.")
    end

    private def deny(id, meta, req, code, msg)
      log(id, "denied", meta, req, code)
      raise Error.new(code, msg)
    end

    # The viewer reached a PIN/password entry page (content not shown yet).
    private def prompt(id, meta, req, code, msg)
      log(id, "prompt", meta, req, code)
      raise Error.new(code, msg)
    end

    # Wrong PIN/password: bump the counter, maybe expire.
    private def failed(id, meta, req, code, msg)
      n = @repo.bump_attempts(id, ipkey(meta, req.ctx.ip))
      log(id, "denied", meta, req, "#{code} (attempt #{n}#{meta.max_failures > 0 ? "/#{meta.max_failures}" : ""})")
      if meta.max_failures > 0 && n >= meta.max_failures
        expire_locked(id, meta, "too many failed attempts", req)
        raise Error.new("expired", Superconf.show_meta ? "Too many failed attempts — this paste has expired." : "This paste has expired.")
      end
      raise Error.new(code, msg)
    end

    private def expire_locked(id : String, meta : Meta, reason : String, req : Request?, log_it = true, delete_due = true)
      now = Time.utc
      residual = meta.residual(reason, now)
      # Expiry starts the deletion timer (unless it is retrieval-anchored,
      # where an already armed deadline just carries over).
      if !meta.delete_on_retrieval? && (h = meta.delete_after_hours)
        residual.delete_at = now + (h * 3600).seconds
      end
      meta.delete_at = residual.delete_at
      @repo.expire_paste(id, seal_meta(id, residual))
      if log_it
        if req
          log(id, "expired", meta, req, reason)
        else
          @repo.log(id, "expired", nil, nil, nil, "system", reason)
        end
      end
      Log.info { "paste #{id} expired: #{reason}" }
      delete_if_due(id, meta, now) if delete_due
    end

    # Remove every trace of a paste whose deletion deadline has passed.
    private def delete_if_due(id : String, meta : Meta, now = Time.utc) : Bool
      return false unless (da = meta.delete_at) && da <= now
      @repo.delete_paste(id)
      Log.info { "paste #{id} deleted (#{meta.delete_desc})" }
      true
    end

    def expire(id : String, reason : String, req : Request?)
      @lock.synchronize do
        row = @repo.get_paste(id) || raise Error.new("not_found", "No such paste")
        meta = open_meta(row)
        raise Error.new("expired", "Already expired") if row.state != "live"
        expire_locked(id, meta, reason, req)
      end
    end

    # Hourly job.
    def sweep
      @lock.synchronize do
        @repo.expired_ids.each do |id|
          row = @repo.get_paste(id) || next
          expire_locked(id, open_meta(row), "time limit reached", nil)
        rescue e
          Log.error(exception: e) { "sweep: failed to expire #{id}" }
        end
        now = Time.utc
        @repo.all_pastes.each do |row|
          delete_if_due(row.id, open_meta(row), now)
        rescue e
          Log.error(exception: e) { "sweep: failed to delete #{row.id}" }
        end
        @repo.purge_sessions
        @tickets.reject! { |_, ticket| ticket.expires_at <= now }
      end
    end

    # ---- attachment tickets -------------------------------------------------

    private def issue_ticket(id : String, body : Body) : String
      t = Crypto.token(24)
      @tickets[t] = Ticket.new(id, body, Time.utc + Superconf.ticket_ttl)
      t
    end

    def ticket(token : String, paste_id : String) : Body?
      @lock.synchronize do
        t = @tickets[token]? || return
        return if t.paste_id != paste_id || t.expires_at <= Time.utc
        t.body
      end
    end

    # Human message for the retriever.
    def self.status_message(meta : Meta, expired_now : Bool) : String
      return "This paste has now been viewed and has expired (view limit reached). It cannot be retrieved again." if expired_now
      parts = [] of String
      if m = meta.max_views
        r = meta.remaining_views || 0
        parts << "#{r} of #{m} view#{m == 1 ? "" : "s"} remaining"
      else
        parts << "unlimited views"
      end
      if (exp = meta.expires_at) && (t = meta.remaining_time)
        parts << "expires in #{humanize(t)} (#{exp.to_s("%Y-%m-%d %H:%M UTC")})"
      else
        parts << "no time limit"
      end
      msg = parts.join("; ") + "."
      msg[0].upcase.to_s + msg[1..]
    end

    def self.humanize(span : Time::Span) : String
      return "0 minutes" if span <= Time::Span.zero
      d = span.total_days.floor.to_i
      h = (span.total_hours - d * 24).floor.to_i
      m = (span.total_minutes - d * 24 * 60 - h * 60).floor.to_i
      out = [] of String
      out << "#{d}d" if d > 0
      out << "#{h}h" if h > 0
      out << "#{m}m" if m > 0 || out.empty?
      out.join(' ')
    end
  end
end
