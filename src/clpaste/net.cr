require "socket"

module Clpaste::Net
  # IPv4 => 4 bytes, IPv6 => 16 bytes; IPv4-mapped IPv6 is normalised to v4.
  def self.ip_bytes(ip : String) : Bytes?
    ip = ip.strip
    ip = ip[1..-2] if ip.starts_with?('[') && ip.ends_with?(']')
    if v4 = Socket::IPAddress.parse_v4_fields?(ip)
      return Bytes.new(4) { |i| v4[i] }
    end
    if v6 = Socket::IPAddress.parse_v6_fields?(ip)
      b = Bytes.new(16)
      8.times do |i|
        b[i * 2] = (v6[i] >> 8).to_u8
        b[i * 2 + 1] = (v6[i] & 0xff).to_u8
      end
      # ::ffff:a.b.c.d
      if b[0, 10].all?(&.zero?) && b[10] == 0xff && b[11] == 0xff
        return b[12, 4]
      end
      return b
    end
    nil
  end

  # "1.2.3.4", "1.2.3.0/24", "2001:db8::/32". Returns false on malformed spec.
  def self.cidr_match?(spec : String, ip : String) : Bool
    ipb = ip_bytes(ip) || return false
    addr, _, len = spec.strip.partition('/')
    netb = ip_bytes(addr) || return false
    return false unless netb.size == ipb.size
    bits = len.empty? ? netb.size * 8 : (len.to_i? || return false)
    return false if bits < 0 || bits > netb.size * 8
    full, rem = bits.divmod(8)
    return false unless netb[0, full] == ipb[0, full]
    return true if rem == 0
    mask = (0xff << (8 - rem)) & 0xff
    (netb[full] & mask) == (ipb[full] & mask)
  end

  def self.valid_cidr?(spec : String) : Bool
    addr, _, len = spec.strip.partition('/')
    b = ip_bytes(addr) || return false
    return true if len.empty?
    n = len.to_i? || return false
    n >= 0 && n <= b.size * 8
  end

  def self.any_match?(specs : Array(String), ip : String) : Bool
    specs.any? { |spec| cidr_match?(spec, ip) }
  end

  def self.peer_ip(request : HTTP::Request) : String
    request.remote_address.as?(Socket::IPAddress).try(&.address) || "0.0.0.0"
  end

  # True when the TCP peer is one of the configured trusted proxies.
  def self.trusted_peer?(request : HTTP::Request, trusted : Array(String)) : Bool
    !trusted.empty? && any_match?(trusted, peer_ip(request))
  end

  # Public base URL ("scheme://host[:port]", no trailing slash) as seen by the
  # client, or nil when the request carries no Host header. X-Forwarded-Proto
  # and X-Forwarded-Host are honoured only from trusted proxies.
  def self.request_base_url(request : HTTP::Request, trusted : Array(String)) : String?
    fwd = trusted_peer?(request, trusted)
    host = nil
    host = request.headers["X-Forwarded-Host"]?.try(&.split(',').first.strip.presence) if fwd
    host ||= request.headers["Host"]?.try(&.strip.presence)
    return unless host
    return unless host =~ /\A[A-Za-z0-9.\-\[\]:_]+\z/ # no header injection into links
    scheme = nil
    scheme = request.headers["X-Forwarded-Proto"]?.try(&.split(',').first.strip.downcase.presence) if fwd
    scheme = "http" unless scheme == "https" || scheme == "http"
    "#{scheme}://#{host}"
  end

  # Client IP honouring X-Forwarded-For only when the peer is a trusted proxy.
  def self.client_ip(request : HTTP::Request, trusted : Array(String)) : String
    peer = peer_ip(request)
    return peer unless trusted_peer?(request, trusted)
    xff = request.headers["X-Forwarded-For"]?
    return peer unless xff
    hops = xff.split(',').map(&.strip).reject(&.empty?)
    # Walk from the right, skipping trusted proxies; first untrusted hop is the client.
    hops.reverse_each do |hop|
      return hop unless any_match?(trusted, hop)
    end
    hops.first? || peer
  end
end
