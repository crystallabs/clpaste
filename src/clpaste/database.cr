require "db"
require "pg"
require "uri"

module Clpaste
  # Picks the database URL and makes sure a PostgreSQL database exists,
  #   * libpq variables PGHOST/PGPORT/PGUSER/PGDATABASE (+PGPASSWORD/.pgpass);
  #   * POSTGRES_USER_PASSWORD is the app role's password;
  #   * if POSTGRES_PASSWORD (superuser) is given, the app role is created or
  #     converged (LOGIN CREATEDB PASSWORD …) and the database created;
  #   * otherwise the app role, which has CREATEDB, creates its database
  #     from template1 itself.
  module Database
    Log = ::Log.for("clpaste.db")

    DEFAULT_SQLITE = "sqlite3://./clpaste.db"

    def self.resolve : String
      url = Superconf.db_url.presence || (pg_configured? ? pg_url : DEFAULT_SQLITE)
      ensure!(url)
      url
    end

    def self.pg_configured? : Bool
      [Superconf.pg_host, Superconf.pg_user, Superconf.pg_password, Superconf.pg_database, Superconf.pg_superuser_password].any?(&.presence)
    end

    def self.pg_url(user : String? = nil, password : String? = nil, database : String? = nil) : String
      build_url(
        Superconf.pg_host.presence || "/var/run/postgresql",
        Superconf.pg_port,
        user || Superconf.pg_user.presence || "clpaste",
        password || Superconf.pg_password.presence,
        database || Superconf.pg_database.presence || "clpaste",
        Superconf.pg_sslmode.presence,
      )
    end

    def self.build_url(host : String, port : Int32, user : String, password : String?, database : String, sslmode : String? = nil) : String
      uri = URI.new("postgres")
      uri.user = user
      uri.password = password
      params = URI::Params.new
      if host.starts_with?('/')
        params["host"] = host
      else
        uri.host = host
        uri.port = port
      end
      params["sslmode"] = sslmode if sslmode
      uri.path = "/#{database}"
      uri.query = params.to_s unless params.empty?
      uri.to_s
    end

    private def self.with_db(uri : URI, database : String, user : String? = nil, password : String? = nil, &)
      u = uri.dup
      u.path = "/#{database}"
      if user
        u.user = user
        u.password = password
      end
      DB.open(u.to_s) { |db| yield db }
    end

    # crystal-db wraps driver errors (DB::ConnectionRefused → PQ::PQError);
    # collect every message up the cause chain.
    def self.error_text(e : Exception) : String
      msgs = [] of String
      cur = e
      while cur
        msgs << cur.message.to_s
        cur = cur.cause
      end
      msgs.join(" <- ")
    end

    def self.ident(name : String) : String
      %("#{name.gsub('"', "\"\"")}")
    end

    def self.literal(s : String) : String
      "'#{s.gsub("'", "''")}'"
    end

    private def self.database_exists?(db, name : String) : Bool
      !db.query_one?("SELECT 1 FROM pg_database WHERE datname = $1", name, as: Int32).nil?
    end

    # Idempotent. Returns quietly for SQLite URLs.
    def self.ensure!(url : String) : Nil
      return unless url.starts_with?("postgres")
      uri = URI.parse(url)
      dbname = URI.decode(uri.path.lstrip('/'))
      raise "invalid PostgreSQL database name #{dbname.inspect}" unless dbname =~ /\A[A-Za-z_][A-Za-z0-9_\-]*\z/
      role = uri.user.presence || "clpaste"

      if spw = Superconf.pg_superuser_password.presence
        begin
          with_db(uri, "template1", Superconf.pg_superuser, spw) do |db|
            rolepw = uri.password.presence || Superconf.pg_password
            attrs = "LOGIN CREATEDB PASSWORD #{rolepw.empty? ? "NULL" : literal(rolepw)}"
            if db.query_one?("SELECT 1 FROM pg_roles WHERE rolname = $1", role, as: Int32)
              db.exec "ALTER ROLE #{ident(role)} #{attrs}"
            else
              db.exec "CREATE ROLE #{ident(role)} #{attrs}"
              Log.info { "created role #{role}" }
            end
            unless database_exists?(db, dbname)
              db.exec "CREATE DATABASE #{ident(dbname)} OWNER #{ident(role)} TEMPLATE template1"
              Log.info { "created database #{dbname} (as superuser)" }
            end
          end
          return
        rescue e
          Log.warn { "superuser bootstrap as #{Superconf.pg_superuser} failed (#{error_text(e)}); continuing as #{role}" }
        end
      end

      # Cheapest check: can we simply connect?
      begin
        DB.open(url, &.scalar("SELECT 1"))
        return
      rescue e
        raise e unless error_text(e).includes?("does not exist")
      end

      # Create it as the app role (needs CREATEDB), via a maintenance DB.
      last = nil
      {"postgres", "template1"}.each do |maint|
        with_db(uri, maint) do |db|
          unless database_exists?(db, dbname)
            db.exec "CREATE DATABASE #{ident(dbname)} TEMPLATE template1"
            Log.info { "created database #{dbname} (as #{role})" }
          end
        end
        return
      rescue e
        last = e
      end
      raise "could not create database #{dbname} as #{role}: #{last.try { |x| error_text(x) }}"
    end
  end
end
