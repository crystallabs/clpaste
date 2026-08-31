require "superconf"
require "json"

# All tunables. Each becomes: config-file key, env var (CLPASTE_<KEY>),
# CLI flag (--key) and a typed accessor (Superconf.key).
module Superconf
  # --- server ---------------------------------------------------------------
  option "bind", "0.0.0.0", description: "Address to listen on"
  option "port", 8080, description: "Port to listen on"
  option "base_url", "", description: "Public URL override (e.g. https://paste.example.com). Empty = derived per request from the Host header (and X-Forwarded-Proto/Host from trusted proxies)"
  option "site_name", "clpaste", description: "Site name shown in the UI"
  option "db_url", "", description: "Database URL (sqlite3://PATH or postgres://user:pass@host/db). Empty = PostgreSQL from PG*/POSTGRES_* vars if any are set, else sqlite3://./clpaste.db"
  option "master_key", "", description: "32-byte master encryption key, hex (64 chars) or base64. Empty = load/generate key_file."
  option "key_file", "clpaste.key", description: "Where the master key is stored/generated when master_key is not set"
  option "admin_user", "admin", description: "HTTP basic-auth admin user"
  option "unprotected", false, description: "Guests can create public pastes without signing in; private/team features are hidden and listing pastes requires an admin"
  option "admin_password", "", description: "HTTP basic-auth admin password (enables basic auth; auto-generated and printed at startup when OIDC is not configured)"

  # --- PostgreSQL (libpq-style variables) ------------------
  option "pg.host", "", env: "PGHOST", description: "PostgreSQL host, or socket directory when it starts with / (default /var/run/postgresql)"
  option "pg.port", 5432, env: "PGPORT", description: "PostgreSQL port"
  option "pg.user", "", env: "PGUSER", description: "PostgreSQL app role (default clpaste)"
  option "pg.password", "", env: "POSTGRES_USER_PASSWORD", description: "App role password (PGPASSWORD and ~/.pgpass are honoured too)"
  option "pg.database", "", env: "PGDATABASE", description: "Database name (default clpaste); created if missing"
  option "pg.sslmode", "", env: "PGSSLMODE", description: "disable|prefer|require|verify-ca|verify-full"
  option "pg.superuser", "postgres", env: "POSTGRES_USER", description: "Superuser role used for bootstrap"
  option "pg.superuser_password", "", env: "POSTGRES_PASSWORD", description: "If set, the app role (LOGIN CREATEDB, password converged) and the database are created as the superuser at startup"
  option "log_level", "info", description: "Log level (trace|debug|info|warn|error)"
  option "trusted_proxies", "", description: "Comma-separated IPs/CIDRs whose X-Forwarded-For is trusted"

  # --- OIDC -----------------------------------------------------------------
  option "oidc.issuer", "", description: "OIDC issuer URL (discovery at ISSUER/.well-known/openid-configuration)"
  option "oidc.client_id", "", description: "OIDC client id"
  option "oidc.client_secret", "", description: "OIDC client secret"
  option "oidc.scopes", "openid email profile", description: "OIDC scopes"
  option "oidc.auth_method", "basic", description: "Token endpoint auth: basic|post"
  option "admin_emails", "", description: "Comma-separated emails with admin rights"
  option "admin_domains", "", description: "Comma-separated email domains whose users are admins. When set, other signed-in users are plain users: they may create pastes and view them like guests, but get no team pages"
  option "admin_claim", "", description: "Alternative admin rule: CLAIM=VALUE (e.g. groups=clpaste-admins); matched against id_token/userinfo"

  # --- paste defaults & limits ---------------------------------------------
  option "id_digits", 9, validate: ->(n : Int32) { n >= 6 && n <= 18 }, description: "Number of decimal digits in paste IDs"
  option "default_ttl_hours", 24.0, description: "Default expiry in hours (0 = never)"
  option "default_max_views_private", 0, description: "Default maximum views for user/admin pastes (0 = unlimited)"
  option "default_max_views_public", 1, description: "Default maximum views for guest (no-login) pastes (0 = unlimited)"
  option "default_team_meta", true, description: "Whether 'users can see metadata & audit log' is on by default"
  option "default_pin", true, description: "Whether the PIN option is on by default in the form"
  option "default_max_failures", 3, description: "Default number of failed PIN/password attempts before expiry (0 = unlimited)"
  option "max_attachment_size", 100_i64 * 1024 * 1024, description: "Maximum size of a single attachment in bytes"
  option "max_body_size", 100_i64 * 1024 * 1024, description: "Maximum total size of one paste in bytes (text + all attachments)"
  option "max_attachments", 10, description: "Maximum number of attachments per paste"
  option "rate_limit", 10, description: "Max view attempts per client IP per minute for non-admins (admins are exempt; 0 = unlimited)"
  option "sweep_interval", 1.hour, description: "How often expired pastes are purged"
  option "ticket_ttl", 30.minutes, description: "How long attachment download links stay valid after a successful web view"
  option "session_ttl", 12.hours, description: "Web session lifetime"
  option "token_ttl", 90.days, description: "CLI token lifetime"
  option "cli_header", "X-Clpaste-Client", description: "Header a CLI client must send to view cli-only pastes"

  # --- theming --------------------------------------------------------------
  option "theme_dir", "", description: "Directory overriding built-in templates (*.html) and static files (static/*)"
  option "color_mode", "auto", description: "Bootstrap color mode: auto|light|dark"
  option "show_meta", true, description: "Tell viewers who a paste is from and since when, and why/when an expired paste expired"
  option "show_version", true, description: "Show the clpaste version in the page footer"

  # --- CLI client -----------------------------------------------------------
  option "server", "", description: "(CLI) Server URL; defaults to the one saved by `clpaste login`"
  option "credentials_file", "", description: "(CLI) Path of the credentials file (default ~/.config/clpaste/credentials.json)"
end

module Clpaste
  VERSION = "0.3.0"
  # Compile-time git revision: CLPASTE_GIT_SHA when set (Docker builds pass
  # it, since the image has no .git), else asked from git directly.
  GIT_SHA = {{ env("CLPASTE_GIT_SHA") || `git rev-parse --short HEAD 2>/dev/null || echo unknown`.strip.stringify }}

  module Config
    # Naming only (needed before printing help); no sources are loaded.
    def self.init
      Superconf.app_name = "clpaste"
      Superconf.env_prefix = "CLPASTE_"
    end

    def self.setup!
      init
      Superconf.configure!
    end

    def self.list(value : String) : Array(String)
      # Lenient: whitespace and/or commas separate items.
      value.split(/[\s,]+/).map(&.strip).reject(&.empty?)
    end

    def self.admin_emails : Array(String)
      list(Superconf.admin_emails).map(&.downcase)
    end

    def self.admin_domains : Array(String)
      list(Superconf.admin_domains).map(&.downcase.lstrip('@'))
    end

    # First admin domain, if any: bare account names in email restrictions
    # are completed with it ("bob" => "bob@example.org").
    def self.default_email_domain : String?
      admin_domains.first?
    end

    def self.expand_emails(emails : Array(String)) : Array(String)
      domain = default_email_domain || return emails
      emails.map { |email| email.includes?('@') ? email : "#{email}@#{domain}" }
    end

    # Admin rules for OIDC users, any of which suffices: listed email, listed
    # email domain, or a matching claim.
    def self.admin?(email : String, claims : JSON::Any) : Bool
      email = email.downcase
      domain = email.partition('@')[2]
      admin_emails.includes?(email) ||
        (!domain.empty? && admin_domains.includes?(domain)) ||
        OIDC.claim_match?(Superconf.admin_claim, claims)
    end

    # Are signed-in non-admin users plain users (paste form only) rather than
    # team users with the pastes list and team views? Yes in unprotected mode
    # and whenever admin_domains draws the admin/user line.
    def self.plain_users? : Bool
      Superconf.unprotected || !admin_domains.empty?
    end

    # Configured public URL override, or nil when it is to be derived from
    # each request (see Server::Req#base_url).
    def self.base_url : String?
      Superconf.base_url.rstrip('/').presence
    end
  end
end
