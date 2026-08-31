require "./spec_helper"

describe Clpaste::Service do
  alice = ident("alice@example.com")
  bob = ident("bob@example.com")
  root = ident("root@example.com", admin: true)

  it "restricts admins-only pastes to admins and maps legacy visibility values" do
    svc = Clpaste::Service.new(fresh_repo("aud"), MASTER)
    c = svc.create(input("top", visibility: "admins"), alice, sreq(alice))
    c.meta.audience.should eq("admins")
    expect_error("need_login") { svc.retrieve(c.id, sreq(nil), false) }
    expect_error("not_allowed") { svc.retrieve(c.id, sreq(bob), false) }
    svc.retrieve(c.id, sreq(root), false).body.text.should eq("top")
    # Legacy values still parse: public -> guests, private -> users.
    legacy = svc.create(input("old", visibility: "public"), alice, sreq(alice))
    legacy.meta.audience.should eq("guests")
    legacy.meta.flags.first.should eq("guests")
    Clpaste::Meta.audience("private").should eq("users")
    expect_error("invalid") { svc.create(input("x", visibility: "everyone"), alice, sreq(alice)) }
  end

  it "creates and retrieves a private paste, counting views and expireing" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    c = svc.create(input("hi", max_views: 2, title: "T"), alice, sreq(alice))
    c.id.size.should eq(9)
    c.meta.flags.should contain("views:2")

    expect_error("need_login") { svc.retrieve(c.id, sreq(nil), false) }
    r = svc.retrieve(c.id, sreq(bob), false)
    r.body.text.should eq("hi")
    r.expired_now.should be_false
    r.meta.remaining_views.should eq(1)
    Clpaste::Service.status_message(r.meta, false).should contain("1 of 2 views remaining")

    r2 = svc.retrieve(c.id, sreq(bob), false)
    r2.expired_now.should be_true
    expect_error("expired") { svc.retrieve(c.id, sreq(bob), false) }

    row, meta = must(svc.meta_for(c.id))
    row.state.should eq("expired")
    row.body.should be_nil
    meta.expired?.should be_true
    meta.expiry_reason.should eq("view limit reached")
    meta.creator.should eq("alice@example.com")
    meta.key_wrap.should eq("") # residual only
    meta.views.should eq(2)     # usage survives expiry
    meta.max_views.should eq(2)
    meta.title.should eq("T")

    actions = svc.repo.log_for(c.id).map(&.action)
    actions.should eq(["created", "denied", "view", "view", "expired", "denied"])
    svc.repo.log_for(c.id).compact_map(&.ip).should be_empty # log_ips off
  end

  it "enforces email allowlists, IP lists and cli-only" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    c = svc.create(input(emails: ["bob@example.com"], ips: ["10.0.0.0/8"], cli_only: true), alice, sreq(alice))
    expect_error("cli_only") { svc.retrieve(c.id, sreq(bob), false) }
    expect_error("ip_blocked") { svc.retrieve(c.id, sreq(bob, ip: "8.8.8.8", cli: true), false) }
    expect_error("not_allowed") { svc.retrieve(c.id, sreq(alice, cli: true), false) }
    svc.retrieve(c.id, sreq(bob, cli: true), false).body.text.should eq("hello")
  end

  it "gates on PIN and password, expires after max failures, and hides password pastes from admin" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    c = svc.create(input(visibility: "public", pin: "1234", password: "s3cret", max_failures: 3), alice, sreq(alice))
    expect_error("need_pin") { svc.retrieve(c.id, sreq(nil), false) }
    expect_error("need_password") { svc.retrieve(c.id, sreq(nil, pin: "1234"), false) }
    expect_error("bad_pin") { svc.retrieve(c.id, sreq(nil, pin: "0000", password: "s3cret"), false) }
    expect_error("bad_password") { svc.retrieve(c.id, sreq(nil, pin: "1234", password: "nope"), false) }
    # admin cannot open without password
    expect_error("need_password") { svc.view_uncounted(c.id, sreq(root), "admin_view", false) }
    expect_error("bad_password") { svc.view_uncounted(c.id, sreq(root, password: "x"), "admin_view", false) }
    # correct secrets reset the counter
    svc.retrieve(c.id, sreq(nil, pin: "1234", password: "s3cret"), false).body.text.should eq("hello")
    expect_error("bad_pin") { svc.retrieve(c.id, sreq(nil, pin: "1", password: "s3cret"), false) }
    expect_error("bad_pin") { svc.retrieve(c.id, sreq(nil, pin: "2", password: "s3cret"), false) }
    expect_error("expired") { svc.retrieve(c.id, sreq(nil, pin: "3", password: "s3cret"), false) }
    expect_error("expired") { svc.retrieve(c.id, sreq(nil, pin: "1234", password: "s3cret"), false) }
    must(svc.meta_for(c.id))[1].expiry_reason.should eq("too many failed attempts")
  end

  it "counts failures per IP only when IP logging is on" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    a = svc.create(input(visibility: "public", pin: "1234", max_failures: 2, log_ips: false), alice, sreq(alice))
    expect_error("bad_pin") { svc.retrieve(a.id, sreq(nil, ip: "1.1.1.1", pin: "0"), false) }
    expect_error("expired") { svc.retrieve(a.id, sreq(nil, ip: "2.2.2.2", pin: "0"), false) }

    b = svc.create(input(visibility: "public", pin: "1234", max_failures: 2, log_ips: true), alice, sreq(alice))
    expect_error("bad_pin") { svc.retrieve(b.id, sreq(nil, ip: "1.1.1.1", pin: "0"), false) }
    expect_error("bad_pin") { svc.retrieve(b.id, sreq(nil, ip: "2.2.2.2", pin: "0"), false) }
    expect_error("expired") { svc.retrieve(b.id, sreq(nil, ip: "1.1.1.1", pin: "0"), false) }
    svc.repo.log_for(b.id).compact_map(&.ip).should contain("1.1.1.1")
  end

  it "peek views are uncounted but logged; expiry expires via sweep" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    c = svc.create(input(max_views: 1, ttl_hours: 0.0), alice, sreq(alice))
    c.meta.expires_at.should be_nil
    r = svc.view_uncounted(c.id, sreq(bob), "user_view", false)
    r.counted.should be_false
    must(svc.meta_for(c.id))[1].views.should eq(0)
    svc.repo.log_for(c.id).map(&.action).should eq(["created", "user_view"])

    e = svc.create(input(ttl_hours: 0.0001), alice, sreq(alice))
    sleep 0.5.seconds
    svc.sweep
    must(svc.meta_for(e.id))[0].state.should eq("expired")
    svc.repo.log_for(e.id).last.detail.should eq("time limit reached")
    expect_error("expired") { svc.retrieve(e.id, sreq(alice), false) }
  end

  it "round-trips attachments and issues tickets" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    data = Random::Secure.random_bytes(5000)
    files = [Clpaste::Attachment.new("a.bin", "application/octet-stream", data)]
    c = svc.create(input("", files: files, visibility: "public"), alice, sreq(alice))
    c.meta.attachments.first.size.should eq(5000)
    r = svc.retrieve(c.id, sreq(nil), true)
    r.body.files.first.data.should eq(data)
    t = must(r.ticket)
    must(svc.ticket(t, c.id)).files.first.name.should eq("a.bin")
    svc.ticket(t, "0000000000").should be_nil
  end

  it "deletes every trace per the deletion rule" do
    svc = Clpaste::Service.new(fresh_repo("del"), MASTER)

    # 0 h after last retrieval: gone the moment it is retrieved.
    a = svc.create(input("burn", visibility: "public", delete_after_hours: 0.0, delete_on_retrieval: true), alice, sreq(alice))
    a.meta.delete_desc.should eq("immediately after last view")
    svc.retrieve(a.id, sreq(nil), false).body.text.should eq("burn")
    svc.meta_for(a.id).should be_nil
    svc.repo.log_for(a.id).should be_empty
    expect_error("not_found") { svc.retrieve(a.id, sreq(nil), false) }

    # N h after last retrieval: each successful retrieval restarts the timer.
    b = svc.create(input("later", visibility: "public", delete_after_hours: 1.0, delete_on_retrieval: true), alice, sreq(alice))
    must(svc.meta_for(b.id))[1].delete_at.should be_nil # not armed until retrieved
    svc.retrieve(b.id, sreq(nil), false)
    first = must(must(svc.meta_for(b.id))[1].delete_at)
    (first - Time.utc).should be_close(1.hour, 5.seconds)
    svc.retrieve(b.id, sreq(nil), false)
    must(must(svc.meta_for(b.id))[1].delete_at).should be >= first
    svc.sweep
    svc.meta_for(b.id).should_not be_nil # not due yet

    # 0 h after expiry: the record disappears as the paste expires.
    c = svc.create(input("gone", delete_after_hours: 0.0), alice, sreq(alice))
    svc.expire(c.id, "expired by spec", sreq(alice))
    svc.meta_for(c.id).should be_nil
    svc.repo.log_for(c.id).should be_empty

    # N h after expiry: armed when the view limit expires it, swept when due.
    d = svc.create(input("keep", visibility: "public", max_views: 1, delete_after_hours: 2.0), alice, sreq(alice))
    d.meta.delete_desc.should eq("2 h after expiry")
    svc.retrieve(d.id, sreq(nil), false).expired_now.should be_true
    row, meta = must(svc.meta_for(d.id))
    row.state.should eq("expired")
    (must(meta.delete_at) - Time.utc).should be_close(2.hours, 5.seconds)
    svc.sweep
    svc.meta_for(d.id).should_not be_nil

    # No deletion rule: expiry leaves the residual record alone.
    e = svc.create(input("stay"), alice, sreq(alice))
    svc.expire(e.id, "expired by spec", sreq(alice))
    svc.sweep
    must(svc.meta_for(e.id))[0].state.should eq("expired")
  end

  it "validates input" do
    svc = Clpaste::Service.new(fresh_repo("svc"), MASTER)
    expect_error("invalid") { svc.create(input(""), alice, sreq(alice)) }
    expect_error("invalid") { svc.create(input(pin: "12"), alice, sreq(alice)) }
    expect_error("invalid") { svc.create(input(emails: ["nope"]), alice, sreq(alice)) }
    expect_error("invalid") { svc.create(input(ips: ["1.2.3.4/99"]), alice, sreq(alice)) }
    Superconf.max_attachment_size = 10
    big = [Clpaste::Attachment.new("big.bin", "application/octet-stream", Bytes.new(11))]
    expect_error("invalid") { svc.create(input("", files: big), alice, sreq(alice)) }
    Superconf.max_attachment_size = 100_i64 * 1024 * 1024
  end
end
