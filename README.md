# clpaste

Clean, professional, encrypted paste service in one binary.

Creating pastes and the admin pages require signing in — through your OIDC
provider, or with the HTTP basic-auth admin account (the default when no
OIDC is configured). Retrieval is open to anyone, subject to whatever
restrictions the author put on the paste. Every option you set tightens
access; nothing loosens it. With `--unprotected` guests may create public
pastes without signing in; only the admin pages stay behind a login.

People fall into three categories: **admins**, **users** (signed in, not
admins) and **guests** (not signed in).

![New paste](screenshots/new-paste.png)
![Pastes](screenshots/pastes.png)
![Retrieval](screenshots/retrieve.png)

* **Web UI** (clean Bootstrap page, light/dark) and a **CLI** (`clpaste put` /
  `clpaste get`) that authenticates gcloud-style (`clpaste login` once).
* **Per-paste protection:** PIN (default on), password, max retrievals,
  expiry time, guest/user/admin visibility with an optional email
  restriction, IP/CIDR allowlist, CLI-only, expiry after N failed attempts.
* **Team options:** users may see a paste's metadata & audit log,
  and/or view the paste itself without consuming a retrieval (logged).
* **Audit log** of who retrieved what and when (identity from OIDC when
  available; IPs only if the author opted in). The log outlives the paste.
* **Expiry** immediately when a limit is hit, plus an hourly sweep
  for time-expired pastes. Retrievers are told what remains or that it is gone.
* **Pastes page:** users see their own and team-shared pastes with protection
  badges; admins see every paste, get peek-as-admin / view-as-guest /
  expire-now on the per-paste settings + log page. The navbar ID box says
  View and opens the paste; for admins it says Find and jumps to the
  paste's settings + log page.
* **Encrypted at rest:** AES-256-GCM envelope encryption; password-protected
  pastes wrap their key with the password, so admins cannot read them.
* SQLite or PostgreSQL. All settings via env vars / flags / config file.

## Quick start

Ad hoc, zero configuration:

```sh
shards build --release                 # needs: libssl, libsqlite3, libxml2, libyaml, libpcre2 (-dev) + pkg-config
bin/clpaste serve
```

That runs on http://localhost:8080 with SQLite in `./clpaste.db`, a master key
generated into `./clpaste.key` (back it up), and — since no OIDC provider is
configured — an `admin` user with a random password printed at startup
(HTTP basic auth; set `CLPASTE_ADMIN_PASSWORD` to make it permanent). The
browser prompts for it on the paste form and the admin pages; retrieving a
paste needs no login. Add `--unprotected` to let guests create public
pastes.

Production, with your identity provider:

```sh
export CLPASTE_MASTER_KEY=$(bin/clpaste keygen)
export CLPASTE_OIDC_ISSUER=https://login.example.com/realms/main
export CLPASTE_OIDC_CLIENT_ID=clpaste CLPASTE_OIDC_CLIENT_SECRET=...
export CLPASTE_ADMIN_EMAILS=you@example.com
bin/clpaste serve
```

Register `https://paste.example.com/auth/callback` as the redirect URI in your
OIDC provider (Keycloak, Authentik, Entra, Google, … — anything with standard
discovery works).

Clpaste needs no hostname configuration: links, the OIDC redirect URI and the
`Secure` cookie flag are derived from each request's `Host` header, and from
`X-Forwarded-Proto`/`X-Forwarded-Host` when the request comes from an IP in
`CLPASTE_TRUSTED_PROXIES` (so put your reverse proxy there when it terminates
TLS). Set `CLPASTE_BASE_URL` only to pin one canonical URL. A request without
a usable `Host` gets plain paths (`/p/123-456-789`) instead of absolute links.

Docker: `cp .env.example .env`, fill it in, `docker compose up -d`. The image
is a static Alpine build; data lives in the `/data` volume (SQLite) or in
PostgreSQL.

### PostgreSQL

Clpaste reads the standard libpq variables plus the usual `POSTGRES_*`
bootstrap secrets, so the settings you already have for other services work
unchanged:

| Variable | Meaning | Default |
|---|---|---|
| `PGHOST` | host, or a socket directory when it starts with `/` | `/var/run/postgresql` |
| `PGPORT` | port | `5432` |
| `PGUSER` | app role | `clpaste` |
| `POSTGRES_USER_PASSWORD` | app role password (`PGPASSWORD` / `~/.pgpass` also work) | — |
| `PGDATABASE` | database name | `clpaste` |
| `PGSSLMODE` | `disable`/`prefer`/`require`/… | `prefer` |
| `POSTGRES_USER`, `POSTGRES_PASSWORD` | superuser for bootstrap (optional) | `postgres`, — |

Setting any of these (with `CLPASTE_DB_URL` unset) selects PostgreSQL; an
explicit `CLPASTE_DB_URL=postgres://…` always wins. At startup:

1. if `POSTGRES_PASSWORD` is set, Clpaste connects as the superuser to
   `template1`, creates the app role if missing or converges it
   (`LOGIN CREATEDB PASSWORD …`, so a rotated secret takes effect), and
   creates the database owned by that role;
2. otherwise it connects as the app role and, if the database does not
   exist, creates it from `template1` itself (the role needs `CREATEDB`).

Tables are created on first connection. Nothing else is needed.

### Admin access without OIDC

`CLPASTE_ADMIN_USER` / `CLPASTE_ADMIN_PASSWORD` enable HTTP basic auth that
grants the admin role on every route (the pastes list, the paste form, the
JSON API via `curl -u`). With OIDC configured as well, `/admin` (an alias
that redirects to `/pastes`) and `/login?basic=1` challenge for basic auth
while everything else redirects to OIDC. Browsers cache basic credentials until the window is
closed — there is no server-side logout for them.

## CLI

```sh
clpaste login --server https://paste.example.com   # opens the browser; --no-browser prints a URL + asks for a code
clpaste whoami

echo "secret" | clpaste put                        # guests, PIN on, 24h, 1 retrieval (server defaults; users/admins default to unlimited)
clpaste put report.pdf notes.txt --text "see attached" --views 1 --ttl 2
clpaste put --guests --pin 4321 --password hunter2 --ips "203.0.113.0/24 198.51.100.7" --cli-only --max-failures 3
clpaste put --users --emails bob@example.com,eve@example.com --team-meta --team-view --log-ips
clpaste put --json ...                             # machine-readable {id, id_fmt, url, pin, ...}

clpaste get 123-456-789                          # prompts for PIN/password if needed; text -> stdout,
clpaste get 123456789 --pin 4321 -o ./downloads   # attachments -> files, status -> stderr
clpaste logout
```

Guest pastes need no login to `get`. Retrieval with plain `curl`:

```sh
curl -H 'X-Clpaste-Pin: 4321' https://paste.example.com/api/pastes/123456789
```

(`X-Clpaste-Client: anything` marks a request as CLI for `--cli-only` pastes;
`Authorization: Bearer <token>` for private ones.)

## Configuration

Every option is available as an env var (`CLPASTE_<KEY>`), a flag
(`--<key>`), and a key in `~/.config/clpaste/config.yml` (or `--config FILE`);
`clpaste config` prints the effective values with their sources. The full
list with defaults is in [`clpaste --help`](#reference-clpaste---help) below.
Notable ones:

* `master_key` / `key_file` — the 32-byte key everything is encrypted with.
  **Losing it loses every paste.** Generate with `clpaste keygen`.
* `unprotected` — guests may create *public* pastes without signing in;
  Private/Team options disappear; `/pastes`, paste details and manual
  expiry require an admin. Guest creation is rate limited like retrieval.
* `admin_emails` / `admin_domains` / `admin_claim` — who gets the admin role
  on OIDC login (any rule suffices). With `admin_domains` set, every other
  signed-in user is a *plain user*: they may create pastes and retrieve them
  like any guest, but the team options and the `/pastes` pages are gone.
* `default_max_views_public` / `_private` (`1` / unlimited),
  `default_ttl_hours` (`24`), `default_pin` (on), `default_max_failures`
  (`3`) — what the form and CLI start with.
* `base_url` — normally empty (derived from the request); `trusted_proxies`
  — CIDRs whose `X-Forwarded-*` headers are honoured.
* `theme_dir` — override templates and static files at runtime.
* `show_meta` (on) — retrievers are told who a paste is from and since when,
  and expired pastes say why and when they expired; off makes both generic.
* `show_version` (on) — print the clpaste version in the page footer.

## How it works

* **IDs** are random decimal numbers (9 digits by default), shown as
  `123-456-789`; dashes and spaces are ignored on input, anywhere.
* **Storage** is deliberately opaque: `pastes(id, state, created_at,
  expires_at, meta, body)`. `meta` is JSON (settings, hashed PIN, wrapped
  key, counters) encrypted with the master key; `body` is JSON (text +
  base64 attachments) encrypted with a per-paste random key. The key is
  wrapped with the master key — or with a PBKDF2-derived key when the paste
  has a password, in which case nobody without the password can read it, admins
  included. Only `state` and `expires_at` are queryable; everything else is
  parsed in the app, so SQLite and PostgreSQL behave identically.
* **Retrieval** (`/p/ID`, `/api/pastes/ID`) checks, in order: already expired?
  past its time limit? CLI-only? IP allowed? login/admin/email required? PIN? password? Then
  the view is counted, the paste expires if the limit is reached, and
  the retriever is told what remains. Wrong PIN/password bumps a failure
  counter — per `(paste, IP)` if the paste logs IPs, per paste otherwise —
  and expires the paste when it reaches the paste's limit. Every retrieval
  attempt — web or API, valid ID or not — counts against `rate_limit`
  (per client IP per minute, default 10; admins are exempt), so the ID
  space cannot be scanned.
* **Peeks** (`/pastes/ID/view`) and **admin peeks** (`/pastes/ID/admin-view`) show
  the content without counting a retrieval; they are logged. The team is every user and admin who can log in —
  unless `admin_domains` is set, in which case there is no team (plain
  users only create and retrieve) and these views — and setting the team
  options on a new paste — are admin-only; a
  paste's creator always sees their own pastes; other users see a paste
  in `/pastes` only if "team can see metadata" is on, and its content only if
  "team can view" is on. (Audit rows written before 0.2.0 use the old
  action names `team_meta`/`team_view` and creator `anonymous` instead of
  `user_meta`/`user_view` and `guest`.)
* **Expiry** deletes the body, the wrapped key and all settings; what
  remains is the creator, timestamps, the reason, the team-metadata flag
  (to gate the log) and the log itself. Later access attempts are logged
  as denied.
* **CLI login** mirrors `gcloud auth login`: the CLI opens
  `BASE_URL/cli/auth?port=…&state=…&challenge=…`, the *server* runs the
  OIDC flow (the CLI never holds OIDC secrets), then redirects the browser
  to `127.0.0.1:<port>/callback?code=…`. The CLI exchanges the one-time
  code plus the PKCE-style verifier for a bearer token (`token_ttl`). With
  `--no-browser` the server shows the code on a page instead.
* **OIDC** uses discovery and the authorization-code flow over the
  back-channel; the id_token comes straight from the token endpoint over
  TLS, so its `iss`/`aud`/`exp`/`nonce` are validated and identity is
  confirmed via `userinfo` (OIDC Core §3.1.3.7 permits skipping signature
  verification in this case).
* **Limits of "CLI-only"**: it is enforced by requiring the
  `X-Clpaste-Client` header, which any HTTP client can send. Treat it as a
  convenience to keep casual browser access out, not as a security boundary.

## Theming

Copy any of `templates/*.html` (Jinja2 syntax via Crinja) or the files under
`assets/` into `CLPASTE_THEME_DIR` (templates at the top level, static files
under `static/`); files found there win over the built-in ones. The layout
uses Bootstrap 5.3's `data-bs-theme` for colour modes.

## Development

```sh
shards install
crystal spec            # unit + service + HTTP specs (with a built-in fake OIDC provider)
crystal build src/clpaste.cr -o bin/clpaste
```

On Debian/Ubuntu the build needs `pkg-config libssl-dev libsqlite3-dev
libxml2-dev libyaml-dev libpcre2-dev`. A fully static binary is easiest on
Alpine (see `Dockerfile`).

## License

AGPL-3.0 — see [LICENSE](LICENSE).

## Reference: `clpaste --help`

```
clpaste 0.2.0 — encrypted paste service

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
Server options (flags for `clpaste serve`; also environment variables, or keys in ~/.config/clpaste/config.yml / --config FILE):
  --config FILE            Load a YAML/JSON config file
  --dump-config [FORMAT]   Print the effective configuration (yaml|json|env|pretty|report) and exit

  --admin-claim VALUE                           CLPASTE_ADMIN_CLAIM                Alternative admin rule: CLAIM=VALUE (e.g. groups=clpaste-admins); matched against id_token/userinfo [default: empty]
  --admin-domains VALUE                         CLPASTE_ADMIN_DOMAINS              Comma-separated email domains whose users are admins. When set, other signed-in users are plain users: they may create pastes and retrieve them like guests, but get no team pages [default: empty]
  --admin-emails VALUE                          CLPASTE_ADMIN_EMAILS               Comma-separated emails with admin rights [default: empty]
  --admin-password VALUE                        CLPASTE_ADMIN_PASSWORD             HTTP basic-auth admin password (enables basic auth; auto-generated and printed at startup when OIDC is not configured) [default: empty]
  --admin-user VALUE                            CLPASTE_ADMIN_USER                 HTTP basic-auth admin user [default: admin]
  --base-url VALUE                              CLPASTE_BASE_URL                   Public URL override (e.g. https://paste.example.com). Empty = derived per request from the Host header (and X-Forwarded-Proto/Host from trusted proxies) [default: empty]
  --bind VALUE                                  CLPASTE_BIND                       Address to listen on [default: 0.0.0.0]
  --cli-header VALUE                            CLPASTE_CLI_HEADER                 Header a CLI client must send to retrieve cli-only pastes [default: X-Clpaste-Client]
  --color-mode VALUE                            CLPASTE_COLOR_MODE                 Bootstrap color mode: auto|light|dark [default: auto]
  --credentials-file VALUE                      CLPASTE_CREDENTIALS_FILE           (CLI) Path of the credentials file (default ~/.config/clpaste/credentials.json) [default: empty]
  --db-url VALUE                                CLPASTE_DB_URL                     Database URL (sqlite3://PATH or postgres://user:pass@host/db). Empty = PostgreSQL from PG*/POSTGRES_* vars if any are set, else sqlite3://./clpaste.db [default: empty]
  --default-max-failures VALUE                  CLPASTE_DEFAULT_MAX_FAILURES       Default number of failed PIN/password attempts before expiry (0 = unlimited) [default: 3]
  --default-max-views-private VALUE             CLPASTE_DEFAULT_MAX_VIEWS_PRIVATE  Default maximum retrievals for user/admin pastes (0 = unlimited) [default: 0]
  --default-max-views-public VALUE              CLPASTE_DEFAULT_MAX_VIEWS_PUBLIC   Default maximum retrievals for guest (no-login) pastes (0 = unlimited) [default: 1]
  --default-pin / --no-default-pin              CLPASTE_DEFAULT_PIN                Whether the PIN option is on by default in the form [default: true]
  --default-team-meta / --no-default-team-meta  CLPASTE_DEFAULT_TEAM_META          Whether 'users can see metadata & audit log' is on by default [default: true]
  --default-ttl-hours VALUE                     CLPASTE_DEFAULT_TTL_HOURS          Default expiry in hours (0 = never) [default: 24.0]
  --id-digits VALUE                             CLPASTE_ID_DIGITS                  Number of decimal digits in paste IDs [default: 9]
  --key-file VALUE                              CLPASTE_KEY_FILE                   Where the master key is stored/generated when master_key is not set [default: clpaste.key]
  --log-level VALUE                             CLPASTE_LOG_LEVEL                  Log level (trace|debug|info|warn|error) [default: info]
  --master-key VALUE                            CLPASTE_MASTER_KEY                 32-byte master encryption key, hex (64 chars) or base64. Empty = load/generate key_file. [default: empty]
  --max-attachments VALUE                       CLPASTE_MAX_ATTACHMENTS            Maximum number of attachments per paste [default: 10]
  --max-attachment-size VALUE                   CLPASTE_MAX_ATTACHMENT_SIZE        Maximum size of a single attachment in bytes [default: 104857600]
  --max-body-size VALUE                         CLPASTE_MAX_BODY_SIZE              Maximum total size of one paste in bytes (text + all attachments) [default: 104857600]
  --oidc-auth-method VALUE                      CLPASTE_OIDC_AUTH_METHOD           Token endpoint auth: basic|post [default: basic]
  --oidc-client-id VALUE                        CLPASTE_OIDC_CLIENT_ID             OIDC client id [default: empty]
  --oidc-client-secret VALUE                    CLPASTE_OIDC_CLIENT_SECRET         OIDC client secret [default: empty]
  --oidc-issuer VALUE                           CLPASTE_OIDC_ISSUER                OIDC issuer URL (discovery at ISSUER/.well-known/openid-configuration) [default: empty]
  --oidc-scopes VALUE                           CLPASTE_OIDC_SCOPES                OIDC scopes [default: openid email profile]
  --port VALUE                                  CLPASTE_PORT                       Port to listen on [default: 8080]
  --rate-limit VALUE                            CLPASTE_RATE_LIMIT                 Max retrieval attempts per client IP per minute for non-admins (admins are exempt; 0 = unlimited) [default: 10]
  --server VALUE                                CLPASTE_SERVER                     (CLI) Server URL; defaults to the one saved by `clpaste login` [default: empty]
  --session-ttl VALUE                           CLPASTE_SESSION_TTL                Web session lifetime [default: 43200]
  --show-meta / --no-show-meta                  CLPASTE_SHOW_META                  Tell retrievers who a paste is from and since when, and why/when an expired paste expired [default: true]
  --show-version / --no-show-version            CLPASTE_SHOW_VERSION               Show the clpaste version in the page footer [default: true]
  --site-name VALUE                             CLPASTE_SITE_NAME                  Site name shown in the UI [default: clpaste]
  --sweep-interval VALUE                        CLPASTE_SWEEP_INTERVAL             How often expired pastes are purged [default: 3600]
  --theme-dir VALUE                             CLPASTE_THEME_DIR                  Directory overriding built-in templates (*.html) and static files (static/*) [default: empty]
  --ticket-ttl VALUE                            CLPASTE_TICKET_TTL                 How long attachment download links stay valid after a successful web retrieval [default: 600]
  --token-ttl VALUE                             CLPASTE_TOKEN_TTL                  CLI token lifetime [default: 7776000]
  --trusted-proxies VALUE                       CLPASTE_TRUSTED_PROXIES            Comma-separated IPs/CIDRs whose X-Forwarded-For is trusted [default: empty]
  --unprotected / --no-unprotected              CLPASTE_UNPROTECTED                Guests can create public pastes without signing in; private/team features are hidden and listing pastes requires an admin [default: false]
  --pg-database VALUE                           PGDATABASE                         Database name (default clpaste); created if missing [default: empty]
  --pg-host VALUE                               PGHOST                             PostgreSQL host, or socket directory when it starts with / (default /var/run/postgresql) [default: empty]
  --pg-port VALUE                               PGPORT                             PostgreSQL port [default: 5432]
  --pg-sslmode VALUE                            PGSSLMODE                          disable|prefer|require|verify-ca|verify-full [default: empty]
  --pg-user VALUE                               PGUSER                             PostgreSQL app role (default clpaste) [default: empty]
  --pg-superuser-password VALUE                 POSTGRES_PASSWORD                  If set, the app role (LOGIN CREATEDB, password converged) and the database are created as the superuser at startup [default: empty]
  --pg-superuser VALUE                          POSTGRES_USER                      Superuser role used for bootstrap [default: postgres]
  --pg-password VALUE                           POSTGRES_USER_PASSWORD             App role password (PGPASSWORD and ~/.pgpass are honoured too) [default: empty]

$ clpaste put --help
Usage: clpaste put [FILE...] [options]
Text is read from stdin unless --text is given.
    -t, --text TEXT                  Paste text (instead of stdin)
    --no-text                        Attach files only, don't read stdin
    --title T                        Title
    --guests                         Guest paste: no login needed to retrieve (default)
    --users                          Retrieval requires a signed-in user
    --admins                         Retrieval requires an admin
    --public                         Alias for --guests
    --private                        Alias for --users
    --emails LIST                    Users/Admins only: restrict to these emails, comma-separated (empty = unrestricted)
    --ips LIST                       Allowed IPs/CIDRs, space-separated (quote the list)
    --pin PIN                        PIN (4-8 digits; default: random 4-digit PIN)
    --no-pin                         Disable PIN
    --password PW                    Password-protect (also hides content from admins)
    --views N                        Max retrievals (0 = unlimited; server default: unlimited for private, 1 for public)
    --ttl HOURS                      Expiry in hours (0 = never; default from server)
    --max-failures N                 Max retrieval (PIN/password) failures before expiry (0 = no limit)
    --cli-only                       Retrievable only via CLI
    --team-meta                      Users may see metadata & audit log (server default: on)
    --no-team-meta                   Hide metadata & audit log from other users
    --team-view                      Users may view the content (uncounted, logged)
    --log-ips                        Record retriever IPs in the audit log
    --json                           Machine-readable output
    -h, --help                       Help

$ clpaste get --help
Usage: clpaste get ID [options]
Text goes to stdout, status to stderr, attachments to files.
    --pin PIN                        PIN (prompted if needed)
    --password PW                    Password (prompted if needed)
    -o, --out DIR                    Directory for attachments (default .)
    -f, --force                      Overwrite existing files
    --text-only                      Don't save attachments
    --json                           Print the raw JSON response
    -h, --help                       Help
```
