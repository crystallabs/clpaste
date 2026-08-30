require "./spec_helper"

# A minimal fake OpenID provider: discovery, authorize (auto-approves),
# token (unsigned id_token), userinfo.
class FakeIdP
  getter issuer : String
  property email = "alice@example.com"
  property name = "Alice"
  property groups = [] of String
  @server : HTTP::Server
  @nonce = ""

  def initialize
    @server = HTTP::Server.new { |ctx| handle(ctx) }
    addr = @server.bind_tcp("127.0.0.1", 0)
    @issuer = "http://127.0.0.1:#{addr.port}"
    spawn { @server.listen }
  end

  def close
    @server.close
  end

  private def handle(ctx)
    r = ctx.request
    ctx.response.content_type = "application/json"
    case r.path
    when "/.well-known/openid-configuration"
      ctx.response.print({
        "issuer" => @issuer, "authorization_endpoint" => "#{@issuer}/authorize",
        "token_endpoint" => "#{@issuer}/token", "userinfo_endpoint" => "#{@issuer}/userinfo",
      }.to_json)
    when "/authorize"
      q = r.query_params
      @nonce = q["nonce"]
      ctx.response.status_code = 302
      ctx.response.headers["Location"] = "#{q["redirect_uri"]}?code=CODE123&state=#{q["state"]}"
    when "/token"
      body = URI::Params.parse(r.body.try(&.gets_to_end) || "")
      body["code"].should eq("CODE123")
      r.headers["Authorization"]?.to_s.should start_with("Basic ")
      payload = {"iss" => @issuer, "aud" => "cid", "exp" => (Time.utc + 5.minutes).to_unix, "nonce" => @nonce,
                 "sub" => "u1", "email" => @email, "name" => @name}.to_json
      b64 = ->(s : String) { Base64.urlsafe_encode(s, padding: false) }
      ctx.response.print({"access_token" => "AT", "id_token" => "#{b64.call(%({"alg":"none"}))}.#{b64.call(payload)}.sig"}.to_json)
    when "/userinfo"
      r.headers["Authorization"]?.should eq("Bearer AT")
      ctx.response.print({"sub" => "u1", "email" => @email, "name" => @name, "groups" => @groups}.to_json)
    else
      ctx.response.status_code = 404
    end
  end
end

# Tiny cookie-carrying client that does not follow redirects.
class Browser
  property cookie : String? = nil
  @base : String

  def initialize(@base)
  end

  def req(method, path, body = nil, headers = HTTP::Headers.new)
    headers["Cookie"] = "clpaste_session=#{cookie}" if cookie
    res = HTTP::Client.exec(method, @base + path, headers: headers, body: body)
    if (sc = res.headers["Set-Cookie"]?) && (m = sc.match(/clpaste_session=([^;]*)/))
      @cookie = m[1].empty? ? nil : m[1]
    end
    res
  end

  def get(path, headers = HTTP::Headers.new)
    req("GET", path, nil, headers)
  end

  def post(path, form : Hash(String, String), headers = HTTP::Headers.new)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    req("POST", path, URI::Params.encode(form), headers)
  end

  def multipart(path, fields : Hash(String, String), files = {} of String => Bytes)
    io = IO::Memory.new
    b = HTTP::FormData::Builder.new(io)
    fields.each { |k, v| b.field(k, v) }
    files.each { |name, data| b.file("files", IO::Memory.new(data), HTTP::FormData::FileMetadata.new(filename: name)) }
    b.finish
    req("POST", path, io.to_s, HTTP::Headers{"Content-Type" => b.content_type})
  end

  # Web login through the fake IdP: /login -> IdP -> callback.
  def login
    r1 = get("/login")
    r1.status_code.should eq(302)
    r2 = HTTP::Client.get(r1.headers["Location"])
    r2.status_code.should eq(302)
    cb = URI.parse(r2.headers["Location"])
    r3 = get("#{cb.path}?#{cb.query}")
    r3.status_code.should eq(302)
    cookie.should_not be_nil
    r3
  end
end

describe Clpaste::Server do
  idp = FakeIdP.new
  repo = fresh_repo("http")
  svc = Clpaste::Service.new(repo, MASTER)
  Superconf.oidc_issuer = idp.issuer
  Superconf.oidc_client_id = "cid"
  Superconf.oidc_client_secret = "sec"
  Superconf.admin_claim = "groups=clpaste-admins"
  Superconf.rate_limit = 1000
  oidc = Clpaste::OIDC.new(idp.issuer, "cid", "sec", "openid email", "basic")
  server = Clpaste::Server.new(svc, Clpaste::Views.new(""), oidc, repo)
  http = server.bind("127.0.0.1", 0)
  port = http.addresses.first.as(Socket::IPAddress).port
  spawn { http.listen }
  # No base_url configured: the server must derive it from the Host header.
  base = "http://127.0.0.1:#{port}"

  it "serves static assets and the login page anonymously" do
    b = Browser.new(base)
    b.get("/static/bootstrap.min.css").status_code.should eq(200)
    b.get("/static/app.css").headers["Content-Type"].should contain("text/css")
    b.get("/static/../etc/passwd").status_code.should eq(404)
    r = b.get("/")
    r.status_code.should eq(200)
    r.body.should contain("Sign in")
    b.get("/healthz").body.should eq("ok")
    b.get("/pastes").status_code.should eq(302)
    b.get("/api/pastes").status_code.should eq(404)
  end

  it "logs in via OIDC, creates a paste through the form, retrieves it with PIN, and enforces cli-only" do
    b = Browser.new(base)
    b.login.headers["Location"].should eq("/")
    b.get("/").body.should contain("New paste")

    r = b.multipart("/paste", {"title" => "hello", "text" => "top secret", "visibility" => "public",
                               "pin_enabled" => "on", "pin" => "4321", "max_views" => "1", "ttl_hours" => "1",
                               "max_failures" => "3"}, {"note.txt" => "attached".to_slice, "second.bin" => "zz".to_slice})
    r.status_code.should eq(200)
    r.body.should contain("second.bin")
    id = r.body.match!(/\/p\/([0-9-]+)/)[1]
    r.body.should contain("PIN:      4321")

    anon = Browser.new(base)
    g = anon.get("/p/#{id}")
    g.status_code.should eq(200)
    g.body.should contain(%(name="pin"))
    bad = anon.post("/p/#{id}", {"pin" => "0000"})
    bad.status_code.should eq(403)
    bad.body.should contain("Wrong PIN")
    ok = anon.post("/p/#{id}", {"pin" => "4321"})
    ok.status_code.should eq(200)
    ok.body.should contain("top secret")
    ok.body.should contain("expired")
    href = ok.body.match!(/href="(\/p\/[0-9]+\/f\/0\?t=[^"]+)"/)[1]
    dl = anon.get(href)
    dl.status_code.should eq(200)
    dl.body.should eq("attached")
    ok.body.scan(/\/f\/\d+\?t=/).size.should eq(2)
    dl.headers["Content-Disposition"].should contain("note.txt")
    anon.get("/p/#{id}").status_code.should eq(410)

    # cli-only
    # PIN/password are plain fields: empty => off, non-empty => on
    r = b.multipart("/paste", {"text" => "cli stuff", "visibility" => "public", "pin" => "", "password" => "", "cli_only" => "on", "ttl_hours" => ""})
    r.body.should_not contain(">pin<")
    r.body.should_not contain(">password<")
    r.body.should_not contain("team-meta") # web form: unchecked box => off
    home = b.get("/").body
    home.should contain(%(id="team_meta" checked)) # ...but the form defaults it on
    r.body.should contain("views:1")               # public default when the field is absent
    id2 = r.body.match!(/\/p\/([0-9-]+)/)[1]
    b.multipart("/paste", {"text" => "priv default", "visibility" => "private", "pin_enabled" => ""}).body.should_not contain("views:") # private default: unlimited
    anon.get("/p/#{id2}").status_code.should eq(403)
    api = HTTP::Client.get("#{base}/api/pastes/#{id2}", headers: HTTP::Headers{"X-Clpaste-Client" => "spec"})
    api.status_code.should eq(200)
    JSON.parse(api.body)["text"].should eq("cli stuff")
    # form validation error re-renders the form
    e = b.multipart("/paste", {"text" => "", "visibility" => "private", "pin_enabled" => "on", "pin" => "12"})
    e.status_code.should eq(400)
    e.body.should contain("PIN must be")
    # re-rendered form keeps checkboxes as submitted (regression: they all came back checked)
    e.body.should_not contain(%(id="cli_only" checked))
    e.body.should_not contain(%(id="log_ips" checked))
  end

  it "shows team/admin lists and details, honours team_meta/team_view, and expires" do
    idp.email = "alice@example.com"
    alice = Browser.new(base)
    alice.login
    r = alice.multipart("/paste", {"text" => "for the team", "visibility" => "private", "pin_enabled" => "", "team_meta" => "on", "team_view" => "on", "password_enabled" => "", "ttl_hours" => "2"})
    id = r.body.match!(/\/p\/([0-9-]+)/)[1].delete('-')
    r = alice.multipart("/paste", {"text" => "mine only", "visibility" => "private", "pin_enabled" => "", "ttl_hours" => "2", "max_views" => ""})
    id_private = r.body.match!(/\/p\/([0-9-]+)/)[1].delete('-')

    idp.email = "bob@example.com"
    bob = Browser.new(base)
    bob.login
    l = bob.get("/pastes")
    l.body.should contain(Clpaste::Ids.format(id))
    l.body.should_not contain(Clpaste::Ids.format(id_private))
    bob.get("/pastes/#{id_private}").status_code.should eq(403)
    d = bob.get("/pastes/#{id}")
    d.status_code.should eq(200)
    d.body.should contain("team_meta")
    v = bob.get("/pastes/#{id}/view")
    v.status_code.should eq(200)
    v.body.should contain("for the team")
    v.body.should contain("not counted")
    bob.get("/pastes/#{id}/admin-view").status_code.should eq(403)
    bob.post("/pastes/#{id}/expire", {} of String => String).status_code.should eq(403)
    # anonymous users get a sign-in gate for private pastes
    anon = Browser.new(base)
    gate = anon.get("/p/#{id_private}")
    gate.status_code.should eq(401)
    gate.body.should contain("/login?next=")
    # the private paste is still retrievable by bob as a member (no email list), and counted
    bob.get("/p/#{id_private}").body.should contain("mine only")

    idp.email = "root@example.com"
    idp.groups = ["clpaste-admins"]
    root = Browser.new(base)
    root.login
    root.get("/").body.should contain("admin")
    root.get("/admin").headers["Location"].should eq("/pastes")
    a = root.get("/pastes")
    a.body.should contain(Clpaste::Ids.format(id_private))
    root.get("/pastes/#{id_private}/admin-view").body.should contain("mine only")
    root.post("/pastes/#{id_private}/expire", {} of String => String).status_code.should eq(303)
    det = root.get("/pastes/#{id_private}")
    det.body.should contain("expired by root@example.com")
    det.body.should contain("admin_view")
    idp.groups = [] of String
  end

  it "issues CLI tokens via the loopback-less code flow and serves the API" do
    idp.email = "alice@example.com"
    alice = Browser.new(base)
    verifier = Clpaste::Crypto.token(48)
    challenge = Clpaste::Crypto.sha256_b64url(verifier)
    # not logged in => redirected to login with next preserved
    r0 = alice.get("/cli/auth?port=0&state=xyz&challenge=#{challenge}")
    r0.status_code.should eq(302)
    r0.headers["Location"].should start_with("/login?next=")
    alice.login
    r1 = alice.get("/cli/auth?port=0&state=xyz&challenge=#{challenge}")
    r1.status_code.should eq(200)
    code = r1.body.match!(/user-select-all">([^<]+)</)[1].strip
    # loopback variant redirects to 127.0.0.1
    r2 = alice.get("/cli/auth?port=4567&state=xyz&challenge=#{challenge}")
    r2.status_code.should eq(302)
    r2.headers["Location"].should start_with("http://127.0.0.1:4567/callback?code=")

    bad = HTTP::Client.post("#{base}/cli/token", body: {"code" => code, "verifier" => "wrong"}.to_json)
    bad.status_code.should eq(403)
    # a failed exchange burns the code; take the one from the loopback redirect
    code = r2.headers["Location"].match!(/code=([^&]+)/)[1]
    tok = HTTP::Client.post("#{base}/cli/token", body: {"code" => code, "verifier" => verifier, "label" => "spec"}.to_json)
    tok.status_code.should eq(200)
    token = JSON.parse(tok.body)["token"].as_s
    # code is single-use
    HTTP::Client.post("#{base}/cli/token", body: {"code" => code, "verifier" => verifier}.to_json).status_code.should eq(403)

    auth = HTTP::Headers{"Authorization" => "Bearer #{token}", "X-Clpaste-Client" => "spec"}
    who = HTTP::Client.get("#{base}/api/whoami", headers: auth)
    JSON.parse(who.body)["email"].should eq("alice@example.com")
    HTTP::Client.get("#{base}/api/whoami").status_code.should eq(401)

    io = IO::Memory.new
    b = HTTP::FormData::Builder.new(io)
    {"text" => "from cli", "visibility" => "private", "pin" => "9999", "password" => "pw", "emails" => "bob@example.com", "max_views" => ""}.each { |k, v| b.field(k, v) }
    b.file("files", IO::Memory.new("bin".to_slice), HTTP::FormData::FileMetadata.new(filename: "x.bin"))
    b.finish
    h = auth.dup
    h["Content-Type"] = b.content_type
    cr = HTTP::Client.post("#{base}/api/pastes", headers: h, body: io.to_s)
    cr.status_code.should eq(201)
    j = JSON.parse(cr.body)
    j["pin"].should eq("9999")
    j["flags"].as_a.map(&.as_s).should contain("password")
    id = j["id"].as_s

    HTTP::Client.get("#{base}/api/pastes/#{id}").status_code.should eq(401)                # need login
    HTTP::Client.get("#{base}/api/pastes/#{id}", headers: auth).status_code.should eq(403) # alice not in email list
    idp.email = "bob@example.com"
    bob = Browser.new(base)
    bob.login
    r = bob.get("/cli/auth?port=0&state=s&challenge=#{challenge}")
    code = r.body.match!(/user-select-all">([^<]+)</)[1].strip
    btoken = JSON.parse(HTTP::Client.post("#{base}/cli/token", body: {"code" => code, "verifier" => verifier}.to_json).body)["token"].as_s
    bauth = HTTP::Headers{"Authorization" => "Bearer #{btoken}"}
    HTTP::Client.get("#{base}/api/pastes/#{id}", headers: bauth).status_code.should eq(428)
    bauth["X-Clpaste-Pin"] = "9999"
    HTTP::Client.get("#{base}/api/pastes/#{id}", headers: bauth).status_code.should eq(428)
    bauth["X-Clpaste-Password"] = "pw"
    ok = HTTP::Client.get("#{base}/api/pastes/#{Clpaste::Ids.format(id)}", headers: bauth)
    ok.status_code.should eq(200)
    oj = JSON.parse(ok.body)
    oj["text"].should eq("from cli")
    Base64.decode_string(oj["files"][0]["data"].as_s).should eq("bin")
    oj["message"].as_s.should contain("Unlimited views")

    HTTP::Client.delete("#{base}/api/token", headers: bauth).status_code.should eq(200)
    HTTP::Client.get("#{base}/api/whoami", headers: bauth).status_code.should eq(401)
  end

  it "grants admin via HTTP basic auth and challenges on admin pages" do
    Superconf.admin_password = "hunter2"
    anon = Browser.new(base)
    r = anon.get("/admin")
    r.status_code.should eq(401)
    r.headers["WWW-Authenticate"].should contain("Basic")
    anon.get("/pastes").status_code.should eq(302) # OIDC is configured: non-admin pages redirect to OIDC
    good = HTTP::Headers{"Authorization" => "Basic " + Base64.strict_encode("admin:hunter2")}
    bad = HTTP::Headers{"Authorization" => "Basic " + Base64.strict_encode("admin:nope")}
    anon.get("/admin", bad).status_code.should eq(401)
    anon.get("/admin", good).headers["Location"].should eq("/pastes")
    ok = anon.get("/pastes", good)
    ok.status_code.should eq(200)
    ok.body.should contain("All pastes on this server")
    anon.get("/", good).body.should contain("New paste")
    anon.get("/login?basic=1").status_code.should eq(401)
    anon.get("/login?basic=1&next=/admin", good).headers["Location"].should eq("/admin")
    who = HTTP::Client.get("#{base}/api/whoami", headers: good)
    JSON.parse(who.body)["admin"].should be_true
    JSON.parse(who.body)["email"].should eq("admin@local")
    Superconf.admin_password = ""
    anon.get("/admin", good).headers["Location"].should start_with("/login") # basic auth off again => OIDC redirect
  end

  it "rate limits gate attempts" do
    Superconf.rate_limit = 3
    anon = Browser.new(base)
    3.times { anon.post("/p/1234567890", {"pin" => "1"}) }
    anon.post("/p/1234567890", {"pin" => "1"}).status_code.should eq(429)
    Superconf.rate_limit = 1000
  end

  it "lets anyone create public pastes in unprotected mode while the list stays admin-only" do
    Superconf.unprotected = true
    Superconf.admin_password = "hunter2"
    anon = Browser.new(base)
    form = anon.get("/")
    form.status_code.should eq(200)
    form.body.should contain("Create paste")
    form.body.should_not contain(%(id="vis_private"))
    form.body.should_not contain(%(name="team_meta"))
    # Private/team settings sent anyway are ignored: the paste comes out public and team-less.
    r = anon.multipart("/paste", {"text" => "open", "visibility" => "private", "team_meta" => "true", "pin" => "", "max_views" => "5"})
    r.status_code.should eq(200)
    r.body.should contain("Access:   public")
    id = must(r.body.match(/\/p\/(\d{3}-\d{3}-\d{3})/))[1]
    anon.get("/p/#{id}").body.should contain("open")
    api = HTTP::Client.post("#{base}/api/pastes", headers: HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}, body: "text=viaapi&visibility=private")
    api.status_code.should eq(201)
    JSON.parse(api.body)["flags"].as_a.map(&.as_s).should contain("public")
    anon.get("/pastes").headers["Location"].should start_with("/login")
    anon.get("/admin").status_code.should eq(401)
    good = HTTP::Headers{"Authorization" => "Basic " + Base64.strict_encode("admin:hunter2")}
    anon.get("/pastes", good).body.should contain("anonymous")
    # A signed-in non-admin member is not enough for the list in this mode.
    idp.email = "carol@example.com"
    idp.groups = [] of String
    member = Browser.new(base)
    member.login
    member.get("/pastes").status_code.should eq(403)
    Superconf.unprotected = false
    Superconf.admin_password = ""
  end

  it "shuts down" do
    http.close
    idp.close
  end
end
