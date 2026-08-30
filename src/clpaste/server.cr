require "http/server"
require "http/formdata"
require "json"
require "uri"

module Clpaste
  class Server
    Log = ::Log.for("clpaste.http")

    COOKIE = "clpaste_session"

    # Creator recorded for pastes made without signing in (unprotected mode).
    GUEST = Identity.new("guest", "Guest", false, false)

    record Pending, nonce : String, next : String, redirect_uri : String, created_at : Time
    record CliCode, challenge : String, email : String, name : String, admin : Bool, created_at : Time

    # Per-request bundle.
    class Req
      getter ctx : HTTP::Server::Context
      getter ip : String
      getter identity : Identity?
      getter session : Session?
      getter? cli : Bool
      getter ua : String?
      # "scheme://host" this request was addressed to, or nil when unknown.
      getter base_url : String?

      def initialize(@ctx, @ip, @identity, @session, @cli, @ua, @base_url)
      end

      # Absolute URL when the host is known, otherwise just the path.
      def url(path : String) : String
        "#{@base_url}#{path}"
      end

      # Absolute URL, or raise when the host cannot be determined.
      def url!(path : String) : String
        @base_url || raise Service::Error.new("bad_request", "Cannot determine this site's URL: request has no Host header (set base_url)")
        url(path)
      end

      def https? : Bool
        @base_url.to_s.starts_with?("https://")
      end

      def request
        @ctx.request
      end

      def response
        @ctx.response
      end

      def path
        @ctx.request.path
      end

      def query(k : String) : String?
        @ctx.request.query_params[k]?
      end

      def channel : String
        @cli ? "cli" : "web"
      end

      def service_request(pin : String? = nil, password : String? = nil) : Service::Request
        Service::Request.new(Access::Ctx.new(@identity, @ip, @cli, pin.presence, password.presence), channel, @ua)
      end
    end

    @pending = {} of String => Pending
    @cli_codes = {} of String => CliCode
    @rate = {} of String => {Int32, Time}
    @state_lock = Mutex.new

    def initialize(@svc : Service, @views : Views, @oidc : OIDC, @repo : Repo)
      @trusted = Config.list(Superconf.trusted_proxies)
    end

    # Binds and returns the HTTP server without blocking (used by specs).
    def bind(host : String = Superconf.bind, port : Int32 = Superconf.port) : HTTP::Server
      server = HTTP::Server.new([HTTP::ErrorHandler.new(verbose: false)]) { |ctx| dispatch(ctx) }
      addr = server.bind_tcp(host, port)
      Log.info { "listening on http://#{addr} (public URL #{Config.base_url || "from request Host header"})" }
      server
    end

    def run
      server = bind
      spawn sweeper
      server.listen
    end

    private def sweeper
      loop do
        sleep Superconf.sweep_interval
        begin
          @svc.sweep
          @state_lock.synchronize do
            cutoff = Time.utc - 10.minutes
            @pending.reject! { |_, pending| pending.created_at < cutoff }
            @cli_codes.reject! { |_, entry| entry.created_at < cutoff }
            @rate.reject! { |_, entry| entry[1] < cutoff }
          end
        rescue e
          Log.error(exception: e) { "sweep failed" }
        end
      end
    end

    # ---- dispatch -----------------------------------------------------------

    private def dispatch(ctx : HTTP::Server::Context)
      req = build_req(ctx)
      begin
        route(req)
      rescue e : Service::Error
        Log.warn { "#{ctx.request.method} #{ctx.request.path}: #{e.code}: #{e.message}" }
        if ctx.request.path.starts_with?("/api/") || ctx.request.path.starts_with?("/cli/token")
          json_error(ctx, e.code, e.message.to_s)
        elsif e.code == "need_login"
          unauthenticated(req)
        else
          status = API_STATUS[e.code]? || 400
          message(req, status == 429 ? "Slow down" : "Error", e.message.to_s, status, status == 429 ? "warning" : "danger")
        end
      end
    rescue e
      Log.error(exception: e) { "#{ctx.request.method} #{ctx.request.path}" }
      ctx.response.status_code = 500
      ctx.response.content_type = "text/plain"
      ctx.response.print "internal error"
    end

    private def build_req(ctx) : Req
      r = ctx.request
      ip = Net.client_ip(r, @trusted)
      cli = r.headers.has_key?(Superconf.cli_header)
      session = nil
      if (auth = r.headers["Authorization"]?) && auth.starts_with?("Bearer ")
        session = @repo.find_session(auth[7..].strip)
        session = nil if session && !session.token?
        cli = true if session
      elsif c = r.cookies[COOKIE]?
        session = @repo.find_session(c.value)
        session = nil if session && session.token?
      end
      identity = session.try { |sess| Identity.new(sess.email, sess.name, sess.admin?, sess.token?) }
      identity ||= basic_identity(r.headers["Authorization"]?)
      Req.new(ctx, ip, identity, session, cli, r.headers["User-Agent"]?, Config.base_url || Net.request_base_url(r, @trusted))
    end

    private def route(req : Req)
      m = req.request.method
      p = req.path.split('/').reject(&.empty?)
      # Tuple#=== matches element-wise (String === "x"), unlike Array.
      case {m, p.size, p[0]?, p[1]?, p[2]?, p[3]?}
      when {"GET", 0, nil, nil, nil, nil}                                                                    then home(req)
      when {"GET", 1, "healthz", nil, nil, nil}                                                              then text(req.ctx, "ok")
      when {"GET", 2, "static", String, nil, nil}                                                            then static(req, p[1])
      when {"GET", 1, "login", nil, nil, nil}                                                                then login(req)
      when {"GET", 2, "auth", "callback", nil, nil}                                                          then callback(req)
      when {"GET", 1, "logout", nil, nil, nil}, {"POST", 1, "logout", nil, nil, nil}                         then logout(req)
      when {"GET", 1, "open", nil, nil, nil}                                                                 then find_paste(req)
      when {"GET", 1, "view", nil, nil, nil}                                                                 then view_by_id(req)
      when {"POST", 1, "paste", nil, nil, nil}                                                               then create_web(req)
      when {"GET", 2, "p", String, nil, nil}                                                                 then view_web(req, p[1], nil, nil)
      when {"POST", 2, "p", String, nil, nil}                                                                then view_web_post(req, p[1])
      when {"GET", 4, "p", String, "f", String}                                                              then attachment(req, p[1], p[3])
      when {"GET", 1, "pastes", nil, nil, nil}                                                               then list(req)
      when {"GET", 2, "pastes", String, nil, nil}                                                            then detail(req, p[1])
      when {"GET", 3, "pastes", String, "view", nil}, {"POST", 3, "pastes", String, "view", nil}             then view_uncounted(req, p[1], admin: false)
      when {"GET", 3, "pastes", String, "admin-view", nil}, {"POST", 3, "pastes", String, "admin-view", nil} then view_uncounted(req, p[1], admin: true)
      when {"POST", 3, "pastes", String, "expire", nil}                                                      then expire(req, p[1])
        # Legacy/admin entry point: same list; guest hits get the basic-auth challenge.
      when {"GET", 1, "admin", nil, nil, nil}       then (require_user(req); redirect(req, "/pastes"))
      when {"GET", 2, "admin", String, nil, nil}    then (require_user(req); redirect(req, "/pastes/#{p[1]}"))
      when {"GET", 2, "cli", "auth", nil, nil}      then cli_auth(req)
      when {"POST", 2, "cli", "token", nil, nil}    then cli_token(req)
      when {"POST", 2, "api", "pastes", nil, nil}   then api_create(req)
      when {"GET", 3, "api", "pastes", String, nil} then api_get(req, p[2])
      when {"GET", 2, "api", "whoami", nil, nil}    then api_whoami(req)
      when {"DELETE", 2, "api", "token", nil, nil}  then api_logout(req)
      else
        if req.path.starts_with?("/api/")
          json_error(req.ctx, "not_found", "No such endpoint")
        else
          message(req.ctx, "Not found", "No such page.", 404)
        end
      end
    end

    # ---- rendering helpers --------------------------------------------------

    private def base_vars(req : Req?) : Hash(String, Crinja::Value)
      user = req.try(&.identity).try { |i| {"email" => i.email, "name" => i.name, "admin" => i.admin?} }
      Crinja.variables({
        "site_name"    => Superconf.site_name,
        "color_mode"   => Superconf.color_mode,
        "version"      => VERSION,
        "show_meta"    => Superconf.show_meta,
        "show_version" => Superconf.show_version,
        "id_digits"    => Superconf.id_digits,
        "user"         => user,
        "oidc"         => @oidc.configured?,
        "unprotected"  => unprotected?,
        "team"         => !Config.plain_users?,
      })
    end

    private def render(req : Req, name : String, vars, status = 200)
      all = base_vars(req)
      Crinja.variables(vars).each { |k, v| all[k] = v }
      req.response.status_code = status
      req.response.content_type = "text/html; charset=utf-8"
      req.response.headers["Cache-Control"] = "no-store"
      req.response.headers["X-Content-Type-Options"] = "nosniff"
      req.response.headers["X-Frame-Options"] = "DENY"
      req.response.print @views.render(name, all)
    end

    private def message(ctx : HTTP::Server::Context, heading : String, msg : String, status = 200, kind = "warning", home = true)
      all = base_vars(nil)
      # identity for the navbar if we have it cheaply
      all["user"] = Crinja::Value.new(nil)
      {"heading" => heading, "message" => msg, "kind" => kind, "home" => home}.each { |k, v| all[k] = Crinja::Value.new(v) }
      ctx.response.status_code = status
      ctx.response.content_type = "text/html; charset=utf-8"
      ctx.response.print @views.render("message.html", all)
    end

    private def message(req : Req, heading : String, msg : String, status = 200, kind = "warning", home = true)
      render(req, "message.html", {"heading" => heading, "message" => msg, "kind" => kind, "home" => home}, status)
    end

    private def text(ctx, body : String, status = 200)
      ctx.response.status_code = status
      ctx.response.content_type = "text/plain; charset=utf-8"
      ctx.response.print body
    end

    private def json(ctx, obj, status = 200)
      ctx.response.status_code = status
      ctx.response.content_type = "application/json"
      ctx.response.print obj.to_json
    end

    API_STATUS = {
      "not_found" => 404, "expired" => 410, "gone" => 410,
      "need_login" => 401, "not_allowed" => 403, "ip_blocked" => 403, "cli_only" => 403,
      "need_pin" => 428, "need_password" => 428, "bad_pin" => 403, "bad_password" => 403,
      "invalid" => 400, "rate_limited" => 429, "forbidden" => 403, "internal" => 500,
    }

    private def json_error(ctx, code : String, msg : String)
      json(ctx, {"error" => code, "message" => msg}, API_STATUS[code]? || 400)
    end

    private def redirect(req : Req, to : String, status = 302)
      req.response.status_code = status
      req.response.headers["Location"] = to
    end

    private def safe_next(s : String?) : String
      s = s.to_s
      (s.starts_with?('/') && !s.starts_with?("//")) ? s : "/"
    end

    def self.basic_enabled? : Bool
      !Superconf.admin_password.empty?
    end

    # `Authorization: Basic …` with the configured admin credentials grants an
    # admin identity on any route (browser, curl, CLI token-less use).
    private def basic_identity(auth : String?) : Identity?
      return unless auth && auth.starts_with?("Basic ") && self.class.basic_enabled?
      user, _, pw = Base64.decode_string(auth[6..].strip).partition(':')
      ok = Crypto.constant_equal?(user, Superconf.admin_user) & Crypto.constant_equal?(pw, Superconf.admin_password)
      ok ? Identity.new("#{user}@local", user, true, false) : nil
    rescue
      nil
    end

    # What to do with a guest request that needs a login: basic-auth
    # challenge for admin pages (or whenever OIDC is absent), else OIDC.
    private def unauthenticated(req : Req)
      if self.class.basic_enabled? && (req.path.starts_with?("/admin") || req.path == "/login" || !@oidc.configured?)
        req.response.headers["WWW-Authenticate"] = %(Basic realm="#{Superconf.site_name} admin", charset="UTF-8")
        hint = @oidc.configured? ? "Enter the admin credentials, or sign in with your organisation account via /login." : "Enter the admin credentials."
        message(req, "Sign in", hint, 401)
      elsif @oidc.configured?
        redirect(req, "/login?next=#{URI.encode_www_form(req.request.resource)}")
      else
        message(req, "No sign-in method", "Neither OIDC nor an admin password is configured on this server.", 503, "danger")
      end
    end

    private def require_login(req : Req) : Identity
      req.identity || raise Service::Error.new("need_login", "Login required")
    end

    private def require_admin(req : Req) : Identity
      id = require_login(req)
      raise Service::Error.new("forbidden", "Admin rights required") unless id.admin?
      id
    end

    # Unprotected mode: guests may create public pastes, there is no "team",
    # and the paste list / details / manual expiry are admin-only.
    private def unprotected? : Bool
      Superconf.unprotected
    end

    # Who may use the team pages: any signed-in user normally, admins only
    # when signed-in non-admins are plain users (see Config.plain_users?).
    private def require_user(req : Req) : Identity
      Config.plain_users? ? require_admin(req) : require_login(req)
    end

    # Who may create a paste; nil means "must sign in first".
    private def creator_for(req : Req) : Identity?
      req.identity || (unprotected? ? GUEST : nil)
    end

    # May this identity set the team options (and peek)? Formal admins always;
    # when there is no admin/user split (no admin_domains, not unprotected)
    # every signed-in user counts.
    private def team_capable?(identity : Identity?) : Bool
      return false unless identity
      identity.admin? || !Config.plain_users?
    end

    # Whatever the form or API client sent: the team options require admin
    # (team) status, and in unprotected mode every paste is also public and
    # guest creation is rate limited.
    private def restrict_fields!(req : Req, fields : Hash(String, String))
      unless team_capable?(req.identity)
        fields["team_meta"] = "false"
        fields["team_view"] = "false"
      end
      return unless unprotected?
      rate_check!(req)
      fields["visibility"] = "guests"
      fields["emails"] = ""
    end

    private def rate_check!(req : Req)
      limit = Superconf.rate_limit
      return if limit <= 0
      @state_lock.synchronize do
        now = Time.utc
        count, start = @rate[req.ip]? || {0, now}
        if now - start > 1.minute
          count, start = 0, now
        end
        count += 1
        @rate[req.ip] = {count, start}
        raise Service::Error.new("rate_limited", "Too many attempts; try again in a minute") if count > limit
      end
    end

    private def fmt_time(t : Time?) : String
      t ? t.to_s("%Y-%m-%d %H:%M UTC") : "never"
    end

    # With seconds; used where precision matters (detail settings table).
    private def fmt_time_s(t : Time?) : String
      t ? t.to_s("%Y-%m-%d %H:%M:%S UTC") : "never"
    end

    # ---- static / home ------------------------------------------------------

    private def static(req : Req, name : String)
      if s = @views.static(name)
        req.response.content_type = s[1]
        req.response.headers["Cache-Control"] = "public, max-age=3600"
        req.response.print s[0]
      else
        message(req, "Not found", "No such file.", 404)
      end
    end

    private def home(req : Req)
      if req.identity || unprotected?
        render(req, "index.html", form_vars(default_form(team_capable?(req.identity))))
      elsif @oidc.configured?
        render(req, "login.html", {"title" => "Sign in", "basic" => self.class.basic_enabled?})
      else
        # Default (protected) mode without OIDC: straight to the basic-auth prompt.
        unauthenticated(req)
      end
    end

    private def default_form(team : Bool) : Hash(String, String | Bool)
      Hash(String, String | Bool){
        "title" => "", "text" => "", "visibility" => "guests", "emails" => "", "ips" => "",
        "pin" => Superconf.default_pin ? random_pin : "", "password" => "",
        "max_views" => default_max_views_str("guests"),
        "ttl_hours" => Superconf.default_ttl_hours > 0 ? Superconf.default_ttl_hours.to_s.sub(/\.0$/, "") : "",
        "max_failures" => Superconf.default_max_failures > 0 ? Superconf.default_max_failures.to_s : "",
        "cli_only" => false, "team_meta" => Superconf.default_team_meta && team, "team_view" => false, "log_ips" => false,
      }
    end

    private def form_vars(f, error : String? = nil)
      {
        "title"             => "New paste",
        "f"                 => f,
        "error"             => error,
        "max_attachments"   => Superconf.max_attachments,
        "max_views_default" => {"private" => default_max_views_str("private"), "public" => default_max_views_str("public")},
        "max_size_mb"       => (Superconf.max_body_size / 1048576.0).round(1),
        "max_file_mb"       => (Superconf.max_attachment_size / 1048576.0).round(1),
      }
    end

    private def default_max_views(visibility : String) : Int32
      Meta.audience(visibility) == "guests" ? Superconf.default_max_views_public : Superconf.default_max_views_private
    end

    private def default_max_views_str(visibility : String) : String
      n = default_max_views(visibility)
      n > 0 ? n.to_s : ""
    end

    private def random_pin : String
      Random::Secure.rand(0..9999).to_s.rjust(4, '0')
    end

    # ---- auth ---------------------------------------------------------------

    private def login(req : Req)
      if req.identity
        return redirect(req, safe_next(req.query("next")))
      end
      if !@oidc.configured? || req.query("basic")
        return unauthenticated(req)
      end
      state = Crypto.token(16)
      nonce = Crypto.token(16)
      redirect_uri = req.url!("/auth/callback")
      @state_lock.synchronize { @pending[state] = Pending.new(nonce, safe_next(req.query("next")), redirect_uri, Time.utc) }
      redirect(req, @oidc.authorize_url(state, nonce, redirect_uri))
    end

    private def callback(req : Req)
      state = req.query("state").to_s
      code = req.query("code").to_s
      pending = @state_lock.synchronize { @pending.delete(state) }
      if pending.nil? || code.empty?
        return message(req, "Login failed", req.query("error_description") || "Invalid or expired login state. Please try again.", 400, "danger")
      end
      user = begin
        @oidc.exchange(code, pending.nonce, pending.redirect_uri)
      rescue e
        Log.warn(exception: e) { "OIDC exchange failed" }
        return message(req, "Login failed", e.message.to_s, 502, "danger")
      end
      admin = Config.admin?(user.email, user.claims)
      s = @repo.create_session("web", user.email, user.name, admin, Superconf.session_ttl, req.ua.to_s[0, 60])
      req.response.cookies << HTTP::Cookie.new(COOKIE, s.id, path: "/", http_only: true, secure: req.https?,
        samesite: HTTP::Cookie::SameSite::Lax, expires: s.expires_at)
      Log.info { "login #{user.email}#{admin ? " (admin)" : ""} from #{req.ip}" }
      redirect(req, pending.next)
    end

    private def logout(req : Req)
      if s = req.session
        @repo.delete_session(s.id)
      end
      req.response.cookies << HTTP::Cookie.new(COOKIE, "", path: "/", http_only: true, expires: Time.unix(0))
      redirect(req, "/")
    end

    # ---- create -------------------------------------------------------------

    private def truthy?(v : String?) : Bool
      {"on", "true", "1", "yes"}.includes?(v.to_s.downcase)
    end

    # Parses multipart or urlencoded bodies into fields + attachments.
    private def parse_form(req : Req) : {Hash(String, String), Array(Attachment)}
      fields = {} of String => String
      files = [] of Attachment
      r = req.request
      if (len = r.headers["Content-Length"]?.try(&.to_i64?)) && len > Superconf.max_body_size + 1_048_576
        raise Service::Error.new("invalid", "Request too large")
      end
      ct = r.headers["Content-Type"]?.to_s
      if ct.starts_with?("multipart/form-data")
        HTTP::FormData.parse(r) do |part|
          if fn = part.filename.presence
            data = part.body.getb_to_end
            files << Attachment.new(File.basename(fn), part.headers["Content-Type"]? || "application/octet-stream", data)
            raise Service::Error.new("invalid", "Too many attachments") if files.size > Superconf.max_attachments
          else
            fields[part.name] = part.body.gets_to_end
          end
        end
      else
        body = r.body.try(&.gets_to_end) || ""
        URI::Params.parse(body).each { |k, v| fields[k] = v }
      end
      {fields, files}
    end

    private def input_from(f : Hash(String, String), files : Array(Attachment)) : {Service::Input, String?}
      pin_enabled = f.has_key?("pin_enabled") ? truthy?(f["pin_enabled"]) : !f["pin"]?.to_s.empty?
      pin = pin_enabled ? (f["pin"]?.presence || random_pin) : nil
      pw_enabled = f.has_key?("password_enabled") ? truthy?(f["password_enabled"]) : !f["password"]?.to_s.empty?
      password = pw_enabled ? f["password"]?.presence : nil
      raise Service::Error.new("invalid", "Password protection is on but no password was given") if pw_enabled && password.nil?
      ttl = f["ttl_hours"]?.presence.try(&.to_f?)
      ttl = Superconf.default_ttl_hours if !f.has_key?("ttl_hours") # API default
      # Absent field (API/CLI) => server default; present but empty => unlimited.
      max_views = f.has_key?("max_views") ? f["max_views"].presence.try(&.to_i?) : default_max_views(f["visibility"]? || "guests")
      max_views = nil if max_views == 0
      input = Service::Input.new(
        title: f["title"]?.try(&.strip).presence,
        text: f["text"]?.to_s,
        files: files,
        visibility: f["visibility"]? || "guests",
        emails: Config.list(f["emails"]?.to_s),
        ips: Config.list(f["ips"]?.to_s),
        pin: pin,
        password: password,
        max_views: max_views,
        ttl_hours: ttl,
        cli_only: truthy?(f["cli_only"]?),
        team_meta: f.has_key?("team_meta") ? truthy?(f["team_meta"]) : Superconf.default_team_meta, # absent (API/CLI) => default; web form always sends it
        team_view: truthy?(f["team_view"]?),
        log_ips: truthy?(f["log_ips"]?),
        max_failures: f.has_key?("max_failures") ? (f["max_failures"].presence.try(&.to_i?) || 0) : Superconf.default_max_failures,
      )
      {input, pin}
    end

    private def create_web(req : Req)
      id = creator_for(req) || return redirect(req, "/login?next=/")
      fields, files = parse_form(req)
      # HTML checkboxes are simply absent when unchecked. PIN/password are plain
      # fields: empty means off (input_from handles that when *_enabled is absent).
      %w[cli_only team_meta team_view log_ips].each { |k| fields[k] = fields[k]? || "false" }
      restrict_fields!(req, fields)
      begin
        input, _ = input_from(fields, files)
        c = @svc.create(input, id, req.service_request)
        render(req, "created.html", created_vars(req, c))
      rescue e : Service::Error
        f = default_form(team_capable?(req.identity))
        fields.each { |k, v| f[k] = v }
        %w[cli_only team_meta team_view log_ips].each { |k| f[k] = truthy?(fields[k]?) }
        # Canonical audience so the right visibility tile is re-checked.
        fields["visibility"]?.try { |v| f["visibility"] = Meta.audience(v) }
        render(req, "index.html", form_vars(f, e.message), 400)
      end
    end

    # Label/value lines shown under the URL on the created page (only what is set).
    private def created_details(c : Service::Created) : Array(Array(String))
      m = c.meta
      rows = [] of Array(String)
      add = ->(k : String, v : String) { rows << [(k + ":").ljust(10), v] }
      c.pin.try { |pin| add.call("PIN", pin) }
      c.password.try { |password| add.call("Password", password) }
      add.call("Emails", m.emails.join(" ")) unless m.emails.empty?
      add.call("IPs", m.ips.join(" ")) unless m.ips.empty?
      add.call("Views", m.max_views.try { |v| "max #{v}" } || "unlimited")
      add.call("Expires", fmt_time(m.expires_at))
      add.call("Failures", "expires after #{m.max_failures} failed attempts") if m.max_failures > 0
      add.call("CLI only", "yes") if m.cli_only?
      access = case m.audience
               when "guests" then "guests (no login needed)"
               when "admins" then "admins (admin status required)"
               else               "users (login required)"
               end
      add.call("Access", access)
      rows
    end

    private def created_vars(req : Req, c : Service::Created)
      {
        "details"     => created_details(c),
        "title"       => "Paste created",
        "id"          => c.id,
        "id_fmt"      => Ids.format(c.id),
        "url"         => req.url("/p/#{Ids.format(c.id)}"),
        "pin"         => c.pin,
        "password"    => c.meta.password?,
        "flags"       => c.meta.flags,
        "expires"     => fmt_time(c.meta.expires_at),
        "attachments" => c.meta.attachments.map { |a| {"name" => a.name, "size" => a.size} },
      }
    end

    # ---- retrieve (web) -----------------------------------------------------

    # Paste-ID box on the sign-in page: anyone may jump to a paste by ID.
    private def view_by_id(req : Req)
      id = Ids.normalize(req.query("id").to_s) || return message(req, "Invalid ID", "Paste IDs are #{Superconf.id_digits} digits (dashes optional).", 400)
      redirect(req, "/p/#{Ids.format(id)}")
    end

    # Navbar "Find" form: admins jump to a paste's detail page by ID.
    private def find_paste(req : Req)
      require_admin(req)
      id = Ids.normalize(req.query("id").to_s) || return message(req, "Invalid ID", "Paste IDs are #{Superconf.id_digits} digits (dashes optional).", 400)
      @svc.meta_for(id) || return message(req, "No such paste", "There is no paste with ID #{Ids.format(id)}.", 404)
      redirect(req, "/pastes/#{id}")
    end

    private def view_web_post(req : Req, raw_id : String)
      fields, _ = parse_form(req)
      view_web(req, raw_id, fields["pin"]?, fields["password"]?)
    end

    # Every web retrieval attempt (GET or POST, valid ID or not) counts
    # against the per-IP rate limit, so IDs cannot be scanned for.
    private def view_web(req : Req, raw_id : String, pin : String?, password : String?)
      rate_check!(req)
      id = Ids.normalize(raw_id) || return message(req, "Invalid ID", "Not a valid paste ID.", 400)
      begin
        r = @svc.retrieve(id, req.service_request(pin, password), want_ticket: true)
        render_paste(req, r)
      rescue e : Service::Error
        web_retrieve_error(req, id, e)
      end
    end

    private def web_retrieve_error(req : Req, id : String, e : Service::Error, action : String? = nil)
      case e.code
      when "need_login"
        render(req, "gate.html", {"title" => "Sign in", "id_fmt" => Ids.format(id), "need_login" => true, "next" => req.path}, 401)
      when "need_pin", "need_password", "bad_pin", "bad_password"
        meta = @svc.meta_for(id).try(&.[1])
        render(req, "gate.html", {
          "title"         => "Protected paste",
          "id_fmt"        => Ids.format(id),
          "need_pin"      => meta.try(&.pin?) || false,
          "need_password" => meta.try(&.password?) || false,
          "error"         => e.code.starts_with?("bad_") ? e.message : nil,
          "action"        => action || "/p/#{id}",
          "peek"          => !action.nil?, # an explicit action means a peek route, not a counted view
        }, e.code.starts_with?("bad_") ? 403 : 200)
      when "not_found"
        message(req, "No such paste", "There is no paste with ID #{Ids.format(id)}.", 404)
      when "expired", "gone"
        message(req, "Paste unavailable", e.message.to_s, 410, "danger", home: false)
      when "rate_limited"
        message(req, "Slow down", e.message.to_s, 429)
      else
        message(req, "Access denied", e.message.to_s, 403, "danger")
      end
    end

    private def render_paste(req : Req, r : Service::Retrieved)
      files = r.body.files.map_with_index do |file, i|
        {"name" => file.name, "size" => file.data.size, "content_type" => file.content_type,
         "href" => r.ticket ? "/p/#{r.id}/f/#{i}?t=#{r.ticket}" : ""}
      end
      status = r.counted ? Service.status_message(r.meta, r.expired_now) : "Peek — not counted as a retrieval, but logged. " + Service.status_message(r.meta, false)
      render(req, "paste.html", {
        "title"          => r.meta.title || "Paste #{Ids.format(r.id)}",
        "id_fmt"         => Ids.format(r.id),
        "meta"           => {"title" => r.meta.title, "creator" => r.meta.creator, "created_at" => fmt_time(r.meta.created_at)},
        "status"         => status,
        "status_kind"    => r.expired_now ? "danger" : "info",
        "text"           => r.body.text,
        "files"          => files,
        "ticket"         => r.ticket,
        "ticket_minutes" => Superconf.ticket_ttl.total_minutes.to_i,
      })
    end

    private def attachment(req : Req, raw_id : String, index : String)
      id = Ids.normalize(raw_id) || return message(req, "Invalid ID", "Not a valid paste ID.", 400)
      body = @svc.ticket(req.query("t").to_s, id) || return message(req, "Link expired", "This download link is no longer valid. View the paste again.", 410)
      f = body.files[index.to_i? || -1]? || return message(req, "Not found", "No such attachment.", 404)
      req.response.content_type = f.content_type
      req.response.headers["Content-Disposition"] = %(attachment; filename="#{f.name.gsub('"', "'")}")
      req.response.headers["Content-Length"] = f.data.size.to_s
      req.response.write f.data
    end

    # ---- team / admin -------------------------------------------------------

    private def list(req : Req)
      identity = require_user(req)
      admin = identity.admin?
      rows = @svc.list_all.select { |_, meta| admin || Access.team_meta?(meta, identity) }
      render(req, "list.html", {
        "title"   => "Pastes",
        "heading" => "Pastes",
        "rows"    => rows.map { |row, meta| row_vars(row, meta) },
        "admin"   => admin,
      })
    rescue e : Service::Error
      e.code == "need_login" ? unauthenticated(req) : raise e
    end

    private def row_vars(row : Repo::Row, meta : Meta)
      size = meta.text_size + meta.attachments.sum(&.size)
      {
        "id_fmt"  => Ids.format(row.id),
        "href"    => "/pastes/#{row.id}",
        "title"   => meta.title || "",
        "creator" => meta.creator,
        "created" => fmt_time(meta.created_at),
        "expires" => meta.expired? ? "#{fmt_time(meta.expired_at)} (expired)" : fmt_time(meta.expires_at),
        "views"   => meta.max_views ? "#{meta.views}/#{meta.max_views}" : meta.views.to_s,
        "size"    => meta.expired? ? "" : "#{size} B#{meta.attachments.empty? ? "" : " (#{meta.attachments.size} files)"}",
        "flags"   => meta.flags,
        "expired" => meta.expired?,
      }
    end

    private def detail(req : Req, raw_id : String)
      identity = require_user(req)
      admin = identity.admin?
      id = Ids.normalize(raw_id) || return message(req, "Invalid ID", "Not a valid paste ID.", 400)
      _, meta = @svc.meta_for(id) || return message(req, "No such paste", "", 404)
      unless admin || Access.team_meta?(meta, identity)
        return message(req, "Access denied", "You may not see this paste's metadata.", 403, "danger")
      end
      @svc.log(id, admin ? "admin_meta" : "user_meta", meta, req.service_request)
      base = "/pastes/#{id}"
      can_view = !meta.expired? && Access.team_view?(meta, identity)
      note = nil
      if (can_view || (admin && !meta.expired?)) && meta.password?
        note = "This paste is password-protected: its content key is wrapped with the password, so viewing requires the password even for admins."
      end
      settings = [
        ["Title", meta.title || "—"], ["Access permissions", meta.audience], ["Creator", meta.creator],
        ["Created", fmt_time_s(meta.created_at)], ["Expires", fmt_time_s(meta.expires_at)],
      ]
      settings << ["Views", meta.max_views ? "#{meta.views} of max #{meta.max_views}" : "#{meta.views} (unlimited)"]
      if meta.expired?
        settings << ["Expired", "#{fmt_time_s(meta.expired_at)} (#{meta.expiry_reason})"]
      else
        settings.concat [
          ["PIN", meta.pin? ? "yes" : "no"], ["Password", meta.password? ? "yes" : "no"],
          ["Restricted to emails", meta.emails.empty? ? (meta.public? ? "n/a (guest paste)" : "unrestricted") : meta.emails.join(", ")],
          ["Allowed IPs", meta.ips.empty? ? "any" : meta.ips.join(", ")],
          ["CLI only", meta.cli_only? ? "yes" : "no"],
        ]
        settings.concat [
          ["Users can see metadata", meta.team_meta? ? "yes" : "no"], ["Users can view content", meta.team_view? ? "yes" : "no"],
          ["IPs logged", meta.log_ips? ? "yes" : "no"],
          ["Max failed attempts", meta.max_failures > 0 ? meta.max_failures.to_s : "unlimited"],
          ["Text size", "#{meta.text_size} B"],
          ["Attachments", meta.attachments.empty? ? "none" : meta.attachments.map { |a| "#{a.name} (#{a.size} B)" }.join(", ")],
        ]
      end
      log = @repo.log_for(id).map do |e|
        {"at" => fmt_time(e.at), "action" => e.action, "identity" => e.identity || "", "ip" => e.ip || "", "channel" => e.channel, "detail" => e.detail || ""}
      end
      render(req, "detail.html", {
        "title"           => "Paste #{Ids.format(id)}",
        "id_fmt"          => Ids.format(id),
        "meta"            => {"expired" => meta.expired?},
        "admin"           => admin,
        "can_view"        => can_view,
        "can_expire"      => !meta.expired? && (admin || meta.creator.downcase == identity.email.downcase),
        "view_href"       => "#{base}/view",
        "admin_view_href" => "#{base}/admin-view",
        "expire_href"     => "#{base}/expire",
        "note"            => note,
        "settings"        => settings,
        "log"             => log,
      })
    rescue e : Service::Error
      e.code == "need_login" ? unauthenticated(req) : raise e
    end

    private def view_uncounted(req : Req, raw_id : String, admin : Bool)
      identity = admin ? require_admin(req) : require_user(req)
      id = Ids.normalize(raw_id) || return message(req, "Invalid ID", "Not a valid paste ID.", 400)
      _, meta = @svc.meta_for(id) || return message(req, "No such paste", "", 404)
      unless admin || Access.team_view?(meta, identity)
        return message(req, "Access denied", "You may not view this paste.", 403, "danger")
      end
      password = nil
      if req.request.method == "POST"
        fields, _ = parse_form(req)
        rate_check!(req)
        password = fields["password"]?
      end
      if meta.password? && password.to_s.empty?
        return render(req, "gate.html", {"title" => "Password", "id_fmt" => Ids.format(id), "need_password" => true, "action" => req.path, "peek" => true})
      end
      begin
        r = @svc.view_uncounted(id, req.service_request(nil, password), admin ? "admin_view" : "user_view", want_ticket: true)
        render_paste(req, r)
      rescue e : Service::Error
        web_retrieve_error(req, id, e, action: req.path)
      end
    rescue e : Service::Error
      e.code == "need_login" ? unauthenticated(req) : raise e
    end

    private def expire(req : Req, raw_id : String)
      identity = require_user(req)
      admin = identity.admin?
      id = Ids.normalize(raw_id) || return message(req, "Invalid ID", "Not a valid paste ID.", 400)
      _, meta = @svc.meta_for(id) || return message(req, "No such paste", "", 404)
      unless admin || meta.creator.downcase == identity.email.downcase
        return message(req, "Access denied", "Only the creator or an admin may expire a paste.", 403, "danger")
      end
      @svc.expire(id, "expired by #{identity.email}", req.service_request)
      redirect(req, "/pastes/#{id}", 303)
    end

    # ---- CLI login handshake ------------------------------------------------

    private def cli_auth(req : Req)
      identity = req.identity || return redirect(req, "/login?next=#{URI.encode_www_form(req.request.resource)}")
      challenge = req.query("challenge").to_s
      state = req.query("state").to_s
      port = req.query("port").to_s.to_i? || 0
      if challenge.size < 32 || state.empty?
        return message(req, "Bad request", "Missing CLI login parameters.", 400, "danger")
      end
      code = Crypto.token(24)
      @state_lock.synchronize { @cli_codes[code] = CliCode.new(challenge, identity.email, identity.name, identity.admin?, Time.utc) }
      if port > 0
        redirect(req, "http://127.0.0.1:#{port}/callback?code=#{code}&state=#{URI.encode_www_form(state)}")
      else
        render(req, "cli_code.html", {"title" => "CLI login", "code" => code})
      end
    end

    private def cli_token(req : Req)
      body = JSON.parse(req.request.body.try(&.gets_to_end) || "{}")
      code = body["code"]?.try(&.as_s?).to_s
      verifier = body["verifier"]?.try(&.as_s?).to_s
      label = body["label"]?.try(&.as_s?).to_s[0, 60]
      entry = @state_lock.synchronize { @cli_codes.delete(code) }
      if entry.nil? || Time.utc - entry.created_at > 5.minutes || !Crypto.constant_equal?(Crypto.sha256_b64url(verifier), entry.challenge)
        return json_error(req.ctx, "forbidden", "Invalid or expired login code")
      end
      s = @repo.create_session("token", entry.email, entry.name, entry.admin, Superconf.token_ttl, label)
      Log.info { "cli token issued to #{entry.email} (#{label})" }
      json(req.ctx, {"token" => s.id, "email" => s.email, "name" => s.name, "admin" => s.admin?, "expires_at" => s.expires_at.to_rfc3339})
    end

    # ---- JSON API -----------------------------------------------------------

    private def api_whoami(req : Req)
      id = req.identity || return json_error(req.ctx, "need_login", "Not logged in")
      json(req.ctx, {"email" => id.email, "name" => id.name, "admin" => id.admin?})
    end

    private def api_logout(req : Req)
      if s = req.session
        @repo.delete_session(s.id)
      end
      json(req.ctx, {"ok" => true})
    end

    private def api_create(req : Req)
      id = creator_for(req) || return json_error(req.ctx, "need_login", "Login required (run `clpaste login`)")
      fields, files = parse_form(req)
      restrict_fields!(req, fields)
      input, _ = input_from(fields, files)
      c = @svc.create(input, id, req.service_request)
      v = created_vars(req, c)
      json(req.ctx, {
        "id" => c.id, "id_fmt" => v["id_fmt"], "url" => v["url"], "pin" => c.pin,
        "flags" => c.meta.flags, "expires_at" => c.meta.expires_at.try(&.to_rfc3339),
      }, 201)
    end

    private def api_get(req : Req, raw_id : String)
      id = Ids.normalize(raw_id) || return json_error(req.ctx, "invalid", "Not a valid paste ID")
      rate_check!(req)
      h = req.request.headers
      pin = h["X-Clpaste-Pin"]? || req.query("pin")
      password = h["X-Clpaste-Password"]? || req.query("password")
      r = @svc.retrieve(id, req.service_request(pin, password), want_ticket: false)
      json(req.ctx, {
        "id"              => r.id,
        "id_fmt"          => Ids.format(r.id),
        "title"           => r.meta.title,
        "creator"         => Superconf.show_meta ? r.meta.creator : nil,
        "created_at"      => Superconf.show_meta ? r.meta.created_at.to_rfc3339 : nil,
        "text"            => r.body.text,
        "files"           => r.body.files.map { |file| {"name" => file.name, "content_type" => file.content_type, "data" => Base64.strict_encode(file.data)} },
        "message"         => Service.status_message(r.meta, r.expired_now),
        "expired_now"     => r.expired_now,
        "remaining_views" => r.meta.remaining_views,
        "expires_at"      => r.meta.expires_at.try(&.to_rfc3339),
      })
    end
  end
end
