require "./spec_helper"

describe Clpaste::Database do
  it "builds URLs for TCP and socket hosts" do
    Clpaste::Database.build_url("db.example.com", 5433, "u", "p@:/w", "clpaste").should eq("postgres://u:p%40%3A%2Fw@db.example.com:5433/clpaste")
    Clpaste::Database.build_url("/var/run/postgresql", 5432, "u", nil, "clpaste", "require").should eq("postgres://u@/clpaste?host=%2Fvar%2Frun%2Fpostgresql&sslmode=require")
    uri = URI.parse(Clpaste::Database.build_url("h", 5432, "u", "p@:/w", "d"))
    uri.password.should eq("p@:/w")
  end

  it "quotes identifiers and literals" do
    Clpaste::Database.ident(%(we"ird)).should eq(%("we""ird"))
    Clpaste::Database.literal("it's").should eq("'it''s'")
  end

  it "ignores sqlite URLs" do
    Clpaste::Database.ensure!("sqlite3://x.db")
  end

  # Live PostgreSQL tests: CLPASTE_SPEC_PG_HOST=127.0.0.1 CLPASTE_SPEC_PG_PASSWORD=… (app role `clpaste`, CREATEDB)
  # and optionally CLPASTE_SPEC_PG_SUPER=user:password for the superuser path.
  pg_host = ENV["CLPASTE_SPEC_PG_HOST"]?.presence
  if pg_host
    it "creates a missing database as the app role" do
      name = "clpaste_spec_#{Random::Secure.hex(3)}"
      url = Clpaste::Database.build_url(pg_host, 5432, "clpaste", ENV["CLPASTE_SPEC_PG_PASSWORD"]?, name)
      Clpaste::Database.ensure!(url)
      Clpaste::Database.ensure!(url) # idempotent
      DB.open(url) { |db| db.scalar("SELECT current_database()").should eq(name) }
      Clpaste::Repo.new(url).close
      DB.open(url.sub("/#{name}", "/postgres")) { |db| db.exec "DROP DATABASE #{Clpaste::Database.ident(name)}" }
    end

    if sup = ENV["CLPASTE_SPEC_PG_SUPER"]?
      it "creates role and database as superuser when POSTGRES_PASSWORD is set" do
        suser, _, spw = sup.partition(':')
        role = "clpaste_spec_role_#{Random::Secure.hex(3)}"
        name = "clpaste_spec_db_#{Random::Secure.hex(3)}"
        Superconf.pg_superuser = suser
        Superconf.pg_superuser_password = spw
        url = Clpaste::Database.build_url(pg_host, 5432, role, "rolepw1", name)
        Clpaste::Database.ensure!(url)
        DB.open(url) { |db| db.scalar("SELECT current_user").should eq(role) }
        # password rotation converges
        url2 = Clpaste::Database.build_url(pg_host, 5432, role, "rolepw2", name)
        Clpaste::Database.ensure!(url2)
        DB.open(url2, &.scalar("SELECT 1"))
        Superconf.pg_superuser_password = ""
        DB.open(Clpaste::Database.build_url(pg_host, 5432, suser, spw, "postgres")) do |db|
          db.exec "DROP DATABASE #{Clpaste::Database.ident(name)}"
          db.exec "DROP ROLE #{Clpaste::Database.ident(role)}"
        end
      end
    end
  end
end
