require "option_parser"
require "http/client"
require "http/server"
require "json"
require "socket"

module Clpaste
  # gcloud-style client: `clpaste login` once, then `clpaste put` / `clpaste get`.
  class CLI
    class Fail < Exception; end

    record Creds, server : String, token : String, email : String do
      include JSON::Serializable
    end

    def initialize(@args : Array(String))
    end

    def self.usage : String
      <<-TXT
        clpaste #{VERSION} — encrypted paste service

        Usage: clpaste <command> [options]

        Server:
          serve                      Run the web/API server (needs --master-key / CLPASTE_MASTER_KEY)
          keygen                     Print a fresh random master key
          config                     Dump effective configuration

        Client:
          login [--server URL] [--no-browser]
                                     Sign in via the server's OIDC app (browser), store a CLI token
          logout                     Revoke the stored token
          whoami                     Show who you are logged in as
          put [FILE...] [options]    Create a paste; text is read from stdin unless --text is given
          get ID [options]           Retrieve a paste; prints text, saves attachments

        Run `clpaste <command> --help` for command options.
        TXT
    end

    # Usage plus the full server option table.
    def self.full_help : String
      usage + "\n" + options_help
    end

    # Every server option as flag / env var / description. Options come from
    # superconf: each is also a config-file key (see `clpaste config`).
    def self.options_help : String
      String.build do |io|
        io << "Server options (flags for `clpaste serve`; also environment variables, or keys in "
        io << Superconf.default_config_path << " / --config FILE):\n"
        io << "  --config FILE            Load a YAML/JSON config file\n"
        io << "  --dump-config [FORMAT]   Print the effective configuration (yaml|json|env|pretty|report) and exit\n\n"
        rows = [] of {String, String, String}
        Superconf.each do |opt|
          flag = opt.bool? ? "#{opt.cli} / --no-#{opt.cli[2..]}" : "#{opt.cli} VALUE"
          rows << {flag, Superconf.env_name(opt), "#{opt.description} [default: #{opt.default_string.presence || "empty"}]"}
        end
        w = rows.max_of(&.[0].size)
        e = rows.max_of(&.[1].size)
        rows.sort_by(&.[1]).each { |row| io << "  " << row[0].ljust(w) << "  " << row[1].ljust(e) << "  " << row[2] << "\n" }
      end
    end

    def run
      cmd = @args.shift?
      if cmd.in?("serve", "keygen", "config") && @args.any?(&.in?("-h", "--help"))
        puts "Usage: clpaste #{cmd} [options]\n\n" + self.class.options_help
        return
      end
      case cmd
      when "serve"  then serve
      when "keygen" then puts Crypto.generate_master_key
      when "config" then Superconf.dump(STDOUT, Superconf::Format::Pretty)
      when "login"  then login
      when "logout" then logout
      when "whoami" then whoami
      when "put"    then put
      when "get"    then get
      when nil, "help", "--help", "-h"
        puts self.class.full_help
      else
        STDERR.puts "unknown command: #{cmd}\n\n#{self.class.usage}"
        exit 2
      end
    rescue e : Fail
      STDERR.puts "error: #{e.message}"
      exit 1
    end

    # ---- server ---------------------------------------------------------------

    private def serve
      ::Log.setup(::Log::Severity.parse(Superconf.log_level), ::Log::IOBackend.new(STDERR))
      master = load_master_key
      url = Database.resolve
      STDERR.puts "database: #{url.sub(/:[^:@\/]*@/, ":***@")}"
      repo = Repo.new(url)
      svc = Service.new(repo, master)
      views = Views.new(Superconf.theme_dir)
      oidc = OIDC.new(Superconf.oidc_issuer, Superconf.oidc_client_id, Superconf.oidc_client_secret,
        Superconf.oidc_scopes, Superconf.oidc_auth_method)
      if !oidc.configured? && Superconf.admin_password.empty?
        Superconf.admin_password = Crypto.token(12)
        STDERR.puts "OIDC not configured — ad-hoc mode. Admin basic-auth credentials for this run:\n  user: #{Superconf.admin_user}\n  password: #{Superconf.admin_password}\n(set CLPASTE_ADMIN_PASSWORD to make it permanent)"
      elsif !oidc.configured?
        STDERR.puts "OIDC not configured; only the basic-auth admin (#{Superconf.admin_user}) can sign in"
      end
      Server.new(svc, views, oidc, repo).run
    end

    # CLPASTE_MASTER_KEY wins; otherwise the key lives in key_file, generated on
    # first run so a bare `clpaste serve` just works.
    private def load_master_key : Bytes
      unless Superconf.master_key.empty?
        return Crypto.parse_key(Superconf.master_key)
      end
      path = Superconf.key_file
      if File.exists?(path)
        return Crypto.parse_key(File.read(path))
      end
      key = Crypto.generate_master_key
      File.write(path, key + "\n", perm: 0o600)
      STDERR.puts "generated master key in #{path} — back it up; without it every paste is unreadable"
      Crypto.parse_key(key)
    end

    # ---- credentials ----------------------------------------------------------

    private def creds_path : String
      p = Superconf.credentials_file
      return p unless p.empty?
      xdg = ENV["XDG_CONFIG_HOME"]?.presence
      base = xdg ? Path[xdg] : Path.home / ".config"
      (base / "clpaste" / "credentials.json").to_s
    end

    private def load_creds : Creds?
      return unless File.exists?(creds_path)
      Creds.from_json(File.read(creds_path))
    rescue
      nil
    end

    private def save_creds(c : Creds)
      Dir.mkdir_p(File.dirname(creds_path))
      File.write(creds_path, c.to_pretty_json + "\n", perm: 0o600)
    end

    private def server_url : String
      s = Superconf.server.presence || load_creds.try(&.server) || Superconf.base_url.presence
      raise Fail.new("no server: pass --server URL (or run `clpaste login --server URL` first)") unless s
      s.rstrip('/')
    end

    private def client_headers(auth : Bool) : HTTP::Headers
      h = HTTP::Headers{Superconf.cli_header => "clpaste/#{VERSION}", "Accept" => "application/json"}
      if auth && (c = load_creds)
        h["Authorization"] = "Bearer #{c.token}"
      end
      h
    end

    # ---- login ----------------------------------------------------------------

    private def login
      no_browser = false
      OptionParser.parse(@args) do |parser|
        parser.banner = "Usage: clpaste login [--server URL] [--no-browser]"
        parser.on("--no-browser", "Print the URL instead of opening a browser; paste the code back") { no_browser = true }
        parser.on("-h", "--help", "Help") { puts parser; exit }
      end
      server = server_url
      verifier = Crypto.token(48)
      challenge = Crypto.sha256_b64url(verifier)
      state = Crypto.token(12)
      code = nil

      if no_browser
        url = "#{server}/cli/auth?port=0&state=#{state}&challenge=#{challenge}"
        STDERR.puts "Open this URL in a browser, sign in, then paste the code shown:\n\n  #{url}\n"
        STDERR.print "Code: "
        code = STDIN.gets.to_s.strip
      else
        ch = Channel(String).new
        srv = HTTP::Server.new do |ctx|
          q = ctx.request.query_params
          if ctx.request.path == "/callback" && q["state"]? == state && (c = q["code"]?)
            ctx.response.content_type = "text/html"
            ctx.response.print "<!doctype html><body style='font-family:sans-serif'><h3>clpaste: login complete</h3><p>You can close this window.</p></body>"
            ch.send(c)
          else
            ctx.response.status_code = 400
            ctx.response.print "bad request"
          end
        end
        addr = srv.bind_tcp("127.0.0.1", 0)
        spawn { srv.listen }
        url = "#{server}/cli/auth?port=#{addr.port}&state=#{state}&challenge=#{challenge}"
        STDERR.puts "Opening browser for sign-in. If it does not open, visit:\n\n  #{url}\n"
        open_browser(url)
        select
        when c = ch.receive
          code = c
        when timeout(5.minutes)
          raise Fail.new("timed out waiting for browser sign-in")
        end
        srv.close
      end

      raise Fail.new("no code received") if code.to_s.empty?
      res = HTTP::Client.post("#{server}/cli/token", headers: client_headers(false).merge!({"Content-Type" => "application/json"}),
        body: {"code" => code, "verifier" => verifier, "label" => "#{System.hostname}"}.to_json)
      j = parse_json(res)
      raise Fail.new(j["message"]?.try(&.as_s?) || "login failed (#{res.status_code})") unless res.success?
      save_creds(Creds.new(server, j["token"].as_s, j["email"].as_s))
      STDERR.puts "Logged in as #{j["email"]} (token valid until #{j["expires_at"]}). Credentials saved to #{creds_path}."
    end

    private def open_browser(url : String)
      cmd = {% if flag?(:darwin) %} "open" {% else %} "xdg-open" {% end %}
      Process.run(cmd, [url], output: Process::Redirect::Close, error: Process::Redirect::Close)
    rescue
    end

    private def logout
      c = load_creds || raise Fail.new("not logged in")
      begin
        HTTP::Client.delete("#{c.server}/api/token", headers: client_headers(true))
      rescue e
        STDERR.puts "warning: could not revoke token on server: #{e.message}"
      end
      File.delete(creds_path)
      STDERR.puts "Logged out."
    end

    private def whoami
      c = load_creds || raise Fail.new("not logged in (run `clpaste login`)")
      res = HTTP::Client.get("#{c.server}/api/whoami", headers: client_headers(true))
      j = parse_json(res)
      raise Fail.new("token rejected by #{c.server}: #{j["message"]?} — run `clpaste login` again") unless res.success?
      puts "#{j["email"]} (#{j["name"]})#{j["admin"]?.try(&.as_bool?) ? " [admin]" : ""} @ #{c.server}"
    end

    # ---- put ------------------------------------------------------------------

    private def put
      fields = {} of String => String
      files = [] of String
      as_json = false
      text_given = false
      fields["visibility"] = "guests"
      fields["pin_enabled"] = "true"
      fields["password_enabled"] = "false"
      OptionParser.parse(@args) do |parser|
        parser.banner = "Usage: clpaste put [FILE...] [options]\nText is read from stdin unless --text is given."
        parser.on("-t", "--text TEXT", "Paste text (instead of stdin)") { |v| fields["text"] = v; text_given = true }
        parser.on("--no-text", "Attach files only, don't read stdin") { fields["text"] = ""; text_given = true }
        parser.on("--title T", "Title") { |v| fields["title"] = v }
        parser.on("--guests", "Guest paste: no login needed to retrieve (default)") { fields["visibility"] = "guests" }
        parser.on("--users", "Retrieval requires a signed-in user") { fields["visibility"] = "users" }
        parser.on("--admins", "Retrieval requires an admin") { fields["visibility"] = "admins" }
        parser.on("--public", "Alias for --guests") { fields["visibility"] = "guests" }
        parser.on("--private", "Alias for --users") { fields["visibility"] = "users" }
        parser.on("--emails LIST", "Users/Admins only: restrict to these emails, comma-separated (empty = unrestricted)") { |v| fields["emails"] = v }
        parser.on("--ips LIST", "Allowed IPs/CIDRs, space-separated (quote the list)") { |v| fields["ips"] = v }
        parser.on("--pin PIN", "PIN (4-8 digits; default: random 4-digit PIN)") { |v| fields["pin"] = v; fields["pin_enabled"] = "true" }
        parser.on("--no-pin", "Disable PIN") { fields["pin_enabled"] = "false" }
        parser.on("--password PW", "Password-protect (also hides content from admins)") { |v| fields["password"] = v; fields["password_enabled"] = "true" }
        parser.on("--views N", "Max retrievals (0 = unlimited; server default: unlimited for private, 1 for public)") { |v| fields["max_views"] = v }
        parser.on("--ttl HOURS", "Expiry in hours (0 = never; default from server)") { |v| fields["ttl_hours"] = v }
        parser.on("--max-failures N", "Max retrieval (PIN/password) failures before expiry (0 = no limit)") { |v| fields["max_failures"] = v }
        parser.on("--cli-only", "Retrievable only via CLI") { fields["cli_only"] = "true" }
        parser.on("--team-meta", "Users may see metadata & audit log (server default: on)") { fields["team_meta"] = "true" }
        parser.on("--no-team-meta", "Hide metadata & audit log from other users") { fields["team_meta"] = "false" }
        parser.on("--team-view", "Users may view the content (uncounted, logged)") { fields["team_view"] = "true" }
        parser.on("--log-ips", "Record retriever IPs in the audit log") { fields["log_ips"] = "true" }
        parser.on("--json", "Machine-readable output") { as_json = true }
        parser.on("-h", "--help", "Help") { puts parser; exit }
        parser.unknown_args { |rest, _| files = rest }
      end
      c = load_creds || raise Fail.new("not logged in (run `clpaste login`)")
      unless text_given
        STDERR.puts "Reading text from stdin (Ctrl-D to finish)…" if STDIN.tty?
        fields["text"] = STDIN.gets_to_end
      end
      files.each { |path| raise Fail.new("no such file: #{path}") unless File.file?(path) }

      io = IO::Memory.new
      builder = HTTP::FormData::Builder.new(io)
      fields.each { |k, v| builder.field(k, v) }
      files.each do |path|
        File.open(path) do |file|
          builder.file("files", file, HTTP::FormData::FileMetadata.new(filename: File.basename(path)), HTTP::Headers{"Content-Type" => "application/octet-stream"})
        end
      end
      builder.finish
      headers = client_headers(true)
      headers["Content-Type"] = builder.content_type
      res = HTTP::Client.post("#{c.server}/api/pastes", headers: headers, body: io.to_s)
      j = parse_json(res)
      raise Fail.new("#{j["message"]?.try(&.as_s?) || "failed"} (#{res.status_code})#{res.status_code == 401 ? " — run `clpaste login`" : ""}") unless res.success?
      if as_json
        puts j.to_json
      else
        puts "URL:  #{j["url"]}"
        puts "ID:   #{j["id_fmt"]}"
        puts "PIN:  #{j["pin"]}" if j["pin"]?.try(&.as_s?)
        puts "Protection: #{j["flags"].as_a.join(", ")}"
        puts "Expires: #{j["expires_at"]?.try(&.as_s?) || "never"}"
      end
    end

    # ---- get ------------------------------------------------------------------

    private def get
      pin = nil
      password = nil
      out_dir = "."
      as_json = false
      force = false
      text_only = false
      OptionParser.parse(@args) do |parser|
        parser.banner = "Usage: clpaste get ID [options]\nText goes to stdout, status to stderr, attachments to files."
        parser.on("--pin PIN", "PIN (prompted if needed)") { |v| pin = v }
        parser.on("--password PW", "Password (prompted if needed)") { |v| password = v }
        parser.on("-o", "--out DIR", "Directory for attachments (default .)") { |v| out_dir = v }
        parser.on("-f", "--force", "Overwrite existing files") { force = true }
        parser.on("--text-only", "Don't save attachments") { text_only = true }
        parser.on("--json", "Print the raw JSON response") { as_json = true }
        parser.on("-h", "--help", "Help") { puts parser; exit }
      end
      raw = @args.shift? || raise Fail.new("usage: clpaste get ID")
      id = Ids.normalize(raw) || raise Fail.new("not a valid paste ID: #{raw}")
      server = server_url

      j = nil.as(JSON::Any?)
      3.times do
        headers = client_headers(true)
        headers["X-Clpaste-Pin"] = pin.to_s unless pin.to_s.empty?
        headers["X-Clpaste-Password"] = password.to_s unless password.to_s.empty?
        res = HTTP::Client.get("#{server}/api/pastes/#{id}", headers: headers)
        j = parse_json(res)
        break if res.success?
        code = j["error"]?.try(&.as_s?)
        case code
        when "need_pin", "bad_pin"
          STDERR.puts j["message"] if code == "bad_pin"
          raise Fail.new("PIN required (use --pin)") unless STDIN.tty?
          STDERR.print "PIN: "
          pin = STDIN.gets.to_s.strip
        when "need_password", "bad_password"
          STDERR.puts j["message"] if code == "bad_password"
          raise Fail.new("password required (use --password)") unless STDIN.tty?
          STDERR.print "Password: "
          password = STDIN.noecho { STDIN.gets.to_s.strip }
          STDERR.puts
        when "need_login"
          raise Fail.new("this paste requires login: run `clpaste login`")
        else
          raise Fail.new("#{j["message"]?.try(&.as_s?) || "failed"} (#{code || res.status_code})")
        end
      end
      j = j || raise Fail.new("no response from server")
      raise Fail.new(j["message"]?.try(&.as_s?) || "failed") if j["error"]?

      if as_json
        puts j.to_json
        return
      end
      title = j["title"]?.try(&.as_s?)
      creator = j["creator"]?.try(&.as_s?) # absent when the server hides paste metadata
      STDERR.puts "# paste #{j["id_fmt"]}#{creator ? " from #{creator}" : ""}#{title ? " — #{title}" : ""}"
      print j["text"].as_s
      files = j["files"].as_a
      unless files.empty? || text_only
        Dir.mkdir_p(out_dir)
        files.each do |file|
          name = File.basename(file["name"].as_s)
          path = File.join(out_dir, name)
          if File.exists?(path) && !force
            STDERR.puts "# skipped #{path} (exists; use --force)"
            next
          end
          File.write(path, Base64.decode(file["data"].as_s))
          STDERR.puts "# saved #{path}"
        end
      end
      STDERR.puts "# #{j["message"]}"
    end

    private def parse_json(res : HTTP::Client::Response) : JSON::Any
      JSON.parse(res.body)
    rescue
      JSON.parse({"error" => "http_#{res.status_code}", "message" => res.body[0, 200]}.to_json)
    end
  end
end
