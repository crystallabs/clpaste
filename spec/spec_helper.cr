require "spec"
require "../src/clpaste/config"
require "../src/clpaste/crypto"
require "../src/clpaste/ids"
require "../src/clpaste/model"
require "../src/clpaste/net"
require "../src/clpaste/repo"
require "../src/clpaste/database"
require "../src/clpaste/access"
require "../src/clpaste/service"
require "../src/clpaste/oidc"
require "../src/clpaste/views"
require "../src/clpaste/server"

SCRATCH = ENV["CLPASTE_SPEC_DIR"]? || File.join(Dir.tempdir, "clpaste-spec")
Dir.mkdir_p(SCRATCH)

MASTER = Clpaste::Crypto.random_key

# SQLite by default; set CLPASTE_SPEC_DB_URL=postgres://… to run the same
# specs against PostgreSQL (the database is created if missing and its
# tables emptied per example).
def fresh_repo(name : String) : Clpaste::Repo
  if url = ENV["CLPASTE_SPEC_DB_URL"]?.presence
    Clpaste::Database.ensure!(url)
    repo = Clpaste::Repo.new(url)
    %w[pastes log attempts sessions].each { |table| repo.db.exec "DELETE FROM #{table}" }
    return repo
  end
  path = File.join(SCRATCH, "#{name}-#{Random::Secure.hex(4)}.db")
  Clpaste::Repo.new("sqlite3://#{path}")
end

def ident(email, admin = false, token = false)
  Clpaste::Identity.new(email, email.split('@').first, admin, token)
end

def sreq(identity = nil, ip = "10.0.0.1", cli = false, pin = nil, password = nil)
  Clpaste::Service::Request.new(Clpaste::Access::Ctx.new(identity, ip, cli, pin, password), cli ? "cli" : "web", "spec")
end

def input(text = "hello", **opts)
  Clpaste::Service::Input.new(
    title: opts[:title]? || nil,
    text: text,
    files: opts[:files]? || [] of Clpaste::Attachment,
    visibility: opts[:visibility]? || "private",
    emails: opts[:emails]? || [] of String,
    ips: opts[:ips]? || [] of String,
    pin: opts[:pin]? || nil,
    password: opts[:password]? || nil,
    max_views: opts[:max_views]? || nil,
    ttl_hours: opts[:ttl_hours]? || 24.0,
    cli_only: opts[:cli_only]? || false,
    team_meta: opts[:team_meta]? || false,
    team_view: opts[:team_view]? || false,
    log_ips: opts[:log_ips]? || false,
    max_failures: opts[:max_failures]? || 3,
    delete_after_hours: opts[:delete_after_hours]? || nil,
    delete_on_retrieval: opts[:delete_on_retrieval]? || false,
  )
end

def expect_error(code : String, &)
  yield
  fail "expected Service::Error #{code}, got nothing"
rescue e : Clpaste::Service::Error
  e.code.should eq(code)
end

# Unwraps a nilable value in specs, failing loudly instead of `not_nil!`.
def must(value : T?) : T forall T
  value || raise "expected a value, got nil"
end
