require "db"
require "sqlite3"
require "pg"

module Clpaste
  # Thin persistence layer. Schema is deliberately opaque: id + state +
  # expiry (queryable) + encrypted metadata + encrypted body. Everything else
  # is parsed in-app. Times are stored as epoch seconds so both drivers
  # behave identically.
  class Repo
    getter db : DB::Database
    getter? pg : Bool

    def initialize(url : String)
      @pg = url.starts_with?("postgres")
      @db = DB.open(url)
      migrate!
    end

    def close
      @db.close
    end

    # Rewrite `?` placeholders to `$n` for PostgreSQL.
    private def q(sql : String) : String
      return sql unless @pg
      n = 0
      sql.gsub("?") { "$#{n += 1}" }
    end

    private def migrate!
      blob = @pg ? "BYTEA" : "BLOB"
      serial = @pg ? "BIGSERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY AUTOINCREMENT"
      @db.exec "PRAGMA journal_mode=WAL" unless @pg
      @db.exec "PRAGMA busy_timeout=5000" unless @pg
      @db.exec <<-SQL
        CREATE TABLE IF NOT EXISTS pastes (
          id         TEXT PRIMARY KEY,
          state      TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          expires_at BIGINT,
          meta       #{blob} NOT NULL,
          body       #{blob}
        )
        SQL
      @db.exec "CREATE INDEX IF NOT EXISTS pastes_expiry ON pastes (state, expires_at)"
      @db.exec <<-SQL
        CREATE TABLE IF NOT EXISTS log (
          id        #{serial},
          paste_id  TEXT NOT NULL,
          at        BIGINT NOT NULL,
          action    TEXT NOT NULL,
          identity  TEXT,
          ip        TEXT,
          ua        TEXT,
          channel   TEXT NOT NULL,
          detail    TEXT
        )
        SQL
      @db.exec "CREATE INDEX IF NOT EXISTS log_paste ON log (paste_id, at)"
      @db.exec <<-SQL
        CREATE TABLE IF NOT EXISTS attempts (
          paste_id TEXT NOT NULL,
          ipkey    TEXT NOT NULL,
          count    BIGINT NOT NULL,
          PRIMARY KEY (paste_id, ipkey)
        )
        SQL
      @db.exec <<-SQL
        CREATE TABLE IF NOT EXISTS sessions (
          id         TEXT PRIMARY KEY,
          kind       TEXT NOT NULL,
          email      TEXT NOT NULL,
          name       TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          expires_at BIGINT NOT NULL,
          label      TEXT NOT NULL,
          admin      BIGINT NOT NULL DEFAULT 0
        )
        SQL
    end

    # ---- pastes -------------------------------------------------------------

    record Row, id : String, state : String, created_at : Time, expires_at : Time?, meta : Bytes, body : Bytes?

    def insert_paste(id : String, expires_at : Time?, meta : Bytes, body : Bytes) : Bool
      @db.exec q("INSERT INTO pastes (id, state, created_at, expires_at, meta, body) VALUES (?, 'live', ?, ?, ?, ?)"),
        id, Time.utc.to_unix, expires_at.try(&.to_unix), meta, body
      true
    rescue ex : Exception
      # Drivers differ: SQLite3::Exception < DB::Error, but PQ::PQError < Exception.
      raise ex unless ex.message.to_s =~ /UNIQUE|unique|duplicate key/
      false
    end

    def get_paste(id : String) : Row?
      @db.query_one?(q("SELECT id, state, created_at, expires_at, meta, body FROM pastes WHERE id = ?"), id,
        as: {String, String, Int64, Int64?, Bytes, Bytes?}).try do |row|
        Row.new(row[0], row[1], Time.unix(row[2]), row[3].try { |unix| Time.unix(unix) }, row[4], row[5])
      end
    end

    def update_meta(id : String, meta : Bytes)
      @db.exec q("UPDATE pastes SET meta = ? WHERE id = ?"), meta, id
    end

    def expire_paste(id : String, residual_meta : Bytes)
      @db.exec q("UPDATE pastes SET state = 'expired', body = NULL, expires_at = NULL, meta = ? WHERE id = ?"), residual_meta, id
      @db.exec q("DELETE FROM attempts WHERE paste_id = ?"), id
    end

    def expired_ids(now : Time = Time.utc) : Array(String)
      @db.query_all q("SELECT id FROM pastes WHERE state = 'live' AND expires_at IS NOT NULL AND expires_at <= ?"), now.to_unix, as: String
    end

    def all_pastes : Array(Row)
      @db.query_all(q("SELECT id, state, created_at, expires_at, meta, body FROM pastes ORDER BY created_at DESC"),
        as: {String, String, Int64, Int64?, Bytes, Bytes?}).map do |row|
        Row.new(row[0], row[1], Time.unix(row[2]), row[3].try { |unix| Time.unix(unix) }, row[4], row[5])
      end
    end

    # ---- attempts -----------------------------------------------------------

    def bump_attempts(id : String, ipkey : String) : Int32
      @db.exec q("INSERT INTO attempts (paste_id, ipkey, count) VALUES (?, ?, 1) ON CONFLICT (paste_id, ipkey) DO UPDATE SET count = attempts.count + 1"), id, ipkey
      @db.query_one(q("SELECT count FROM attempts WHERE paste_id = ? AND ipkey = ?"), id, ipkey, as: Int64).to_i32
    end

    def clear_attempts(id : String, ipkey : String)
      @db.exec q("DELETE FROM attempts WHERE paste_id = ? AND ipkey = ?"), id, ipkey
    end

    # ---- log ----------------------------------------------------------------

    def log(paste_id : String, action : String, identity : String?, ip : String?, ua : String?, channel : String, detail : String? = nil)
      @db.exec q("INSERT INTO log (paste_id, at, action, identity, ip, ua, channel, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
        paste_id, Time.utc.to_unix, action, identity, ip, ua.try(&.[0, 200]), channel, detail
    end

    def log_for(paste_id : String) : Array(LogEntry)
      @db.query_all(q("SELECT id, paste_id, at, action, identity, ip, ua, channel, detail FROM log WHERE paste_id = ? ORDER BY at ASC, id ASC"), paste_id,
        as: {Int64, String, Int64, String, String?, String?, String?, String, String?}).map do |row|
        LogEntry.new(row[0], row[1], Time.unix(row[2]), row[3], row[4], row[5], row[6], row[7], row[8])
      end
    end

    # ---- sessions -----------------------------------------------------------

    def create_session(kind : String, email : String, name : String, admin : Bool, ttl : Time::Span, label : String = "") : Session
      id = Crypto.token(32)
      now = Time.utc
      @db.exec q("INSERT INTO sessions (id, kind, email, name, created_at, expires_at, label, admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
        Crypto.sha256_hex(id), kind, email, name, now.to_unix, (now + ttl).to_unix, label, admin ? 1_i64 : 0_i64
      Session.new(id, kind, email, name, now, now + ttl, label, admin)
    end

    def find_session(id : String) : Session?
      @db.query_one?(q("SELECT id, kind, email, name, created_at, expires_at, label, admin FROM sessions WHERE id = ?"), Crypto.sha256_hex(id),
        as: {String, String, String, String, Int64, Int64, String, Int64}).try do |row|
        exp = Time.unix(row[5])
        next if exp <= Time.utc
        Session.new(id, row[1], row[2], row[3], Time.unix(row[4]), exp, row[6], row[7] != 0)
      end
    end

    def delete_session(id : String)
      @db.exec q("DELETE FROM sessions WHERE id = ?"), Crypto.sha256_hex(id)
    end

    def purge_sessions(now : Time = Time.utc)
      @db.exec q("DELETE FROM sessions WHERE expires_at <= ?"), now.to_unix
    end
  end
end
