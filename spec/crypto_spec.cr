require "./spec_helper"

describe Clpaste::Crypto do
  it "seals and opens with AAD" do
    k = Clpaste::Crypto.random_key
    blob = Clpaste::Crypto.seal(k, "secret".to_slice, "ctx")
    String.new(Clpaste::Crypto.open(k, blob, "ctx")).should eq("secret")
  end

  it "rejects tampering, wrong key and wrong AAD" do
    k = Clpaste::Crypto.random_key
    blob = Clpaste::Crypto.seal(k, "secret".to_slice, "ctx")
    expect_raises(Clpaste::Crypto::Error) { Clpaste::Crypto.open(k, blob, "other") }
    expect_raises(Clpaste::Crypto::Error) { Clpaste::Crypto.open(Clpaste::Crypto.random_key, blob, "ctx") }
    blob[blob.size - 1] ^= 0x01
    expect_raises(Clpaste::Crypto::Error) { Clpaste::Crypto.open(k, blob, "ctx") }
  end

  it "handles empty plaintext and large data" do
    k = Clpaste::Crypto.random_key
    Clpaste::Crypto.open(k, Clpaste::Crypto.seal(k, Bytes.empty)).size.should eq(0)
    big = Random::Secure.random_bytes(1_000_000)
    Clpaste::Crypto.open(k, Clpaste::Crypto.seal(k, big)).should eq(big)
  end

  it "parses hex and base64 master keys" do
    k = Clpaste::Crypto.random_key
    Clpaste::Crypto.parse_key(k.hexstring).should eq(k)
    Clpaste::Crypto.parse_key(Base64.strict_encode(k)).should eq(k)
    expect_raises(Clpaste::Crypto::Error) { Clpaste::Crypto.parse_key("short") }
  end

  it "derives stable keys and hashes secrets" do
    salt = Bytes.new(16, 1_u8)
    Clpaste::Crypto.derive("pw", salt).should eq(Clpaste::Crypto.derive("pw", salt))
    Clpaste::Crypto.derive("pw", salt).should_not eq(Clpaste::Crypto.derive("pw2", salt))
    h = Clpaste::Crypto.hash_secret("1234", cost: 4)
    Clpaste::Crypto.verify_secret("1234", h).should be_true
    Clpaste::Crypto.verify_secret("1235", h).should be_false
  end
end

describe Clpaste::Ids do
  it "generates, normalises and formats" do
    id = Clpaste::Ids.generate(10)
    id.size.should eq(10)
    id[0].should_not eq('0')
    Clpaste::Ids.format("1234567890").should eq("123-456-789-0")
    Clpaste::Ids.format("123456789").should eq("123-456-789")
    Clpaste::Ids.normalize("12-3456 78-90").should eq("1234567890")
    Clpaste::Ids.normalize("1-2-3-4-5-6-7-8-9-0").should eq("1234567890")
    Clpaste::Ids.normalize("12").should be_nil
  end
end

describe Clpaste::Config do
  it "splits lists on spaces and/or commas" do
    Clpaste::Config.list("10.0.0.0/8 192.168.1.1,  ::1 ,").should eq(["10.0.0.0/8", "192.168.1.1", "::1"])
    Clpaste::Config.list("").should be_empty
  end
end

describe Clpaste::Net do
  it "matches IPv4/IPv6 CIDRs" do
    Clpaste::Net.cidr_match?("10.0.0.0/8", "10.20.30.40").should be_true
    Clpaste::Net.cidr_match?("10.0.0.0/8", "11.0.0.1").should be_false
    Clpaste::Net.cidr_match?("192.168.1.5", "192.168.1.5").should be_true
    Clpaste::Net.cidr_match?("192.168.1.0/25", "192.168.1.127").should be_true
    Clpaste::Net.cidr_match?("192.168.1.0/25", "192.168.1.128").should be_false
    Clpaste::Net.cidr_match?("2001:db8::/32", "2001:db8:1::5").should be_true
    Clpaste::Net.cidr_match?("2001:db8::/32", "2001:db9::1").should be_false
    Clpaste::Net.cidr_match?("10.0.0.1", "::ffff:10.0.0.1").should be_true
    Clpaste::Net.cidr_match?("garbage", "10.0.0.1").should be_false
    Clpaste::Net.valid_cidr?("10.0.0.0/33").should be_false
    Clpaste::Net.valid_cidr?("::1").should be_true
  end

  it "derives the client IP from trusted proxies only" do
    req = HTTP::Request.new("GET", "/", HTTP::Headers{"X-Forwarded-For" => "203.0.113.9, 10.0.0.2"})
    req.remote_address = Socket::IPAddress.new("10.0.0.1", 1234)
    Clpaste::Net.client_ip(req, [] of String).should eq("10.0.0.1")
    Clpaste::Net.client_ip(req, ["10.0.0.0/8"]).should eq("203.0.113.9")
    Clpaste::Net.client_ip(req, ["192.168.0.0/16"]).should eq("10.0.0.1")
  end

  it "derives the public base URL from Host and trusted forwarded headers" do
    req = HTTP::Request.new("GET", "/", HTTP::Headers{"Host" => "paste.internal:8080", "X-Forwarded-Proto" => "https", "X-Forwarded-Host" => "paste.example.com"})
    req.remote_address = Socket::IPAddress.new("10.0.0.1", 1234)
    Clpaste::Net.request_base_url(req, [] of String).should eq("http://paste.internal:8080")
    Clpaste::Net.request_base_url(req, ["10.0.0.0/8"]).should eq("https://paste.example.com")
    Clpaste::Net.request_base_url(HTTP::Request.new("GET", "/"), [] of String).should be_nil
    bad = HTTP::Request.new("GET", "/", HTTP::Headers{"Host" => "evil.example/x?y"})
    Clpaste::Net.request_base_url(bad, [] of String).should be_nil
  end
end
