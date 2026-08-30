require "http/client"
require "json"
require "uri"

module Clpaste
  # Minimal OpenID Connect relying party: discovery + authorization code flow
  # over the back-channel. The id_token is obtained directly from the token
  # endpoint over TLS, so per OIDC Core 3.1.3.7 its signature need not be
  # re-validated; we validate iss/aud/exp/nonce and confirm via userinfo.
  class OIDC
    Log = ::Log.for("clpaste.oidc")

    record Discovery, authorization_endpoint : String, token_endpoint : String, userinfo_endpoint : String?, issuer : String

    record User, email : String, name : String, claims : JSON::Any

    getter issuer : String
    getter client_id : String
    @client_secret : String
    @scopes : String
    @auth_method : String
    @disc : Discovery?

    def initialize(@issuer, @client_id, @client_secret, @scopes, @auth_method)
    end

    def configured? : Bool
      !@issuer.empty? && !@client_id.empty?
    end

    def discovery : Discovery
      @disc ||= begin
        url = @issuer.rstrip('/') + "/.well-known/openid-configuration"
        res = HTTP::Client.get(url)
        raise "OIDC discovery failed: #{url} => #{res.status_code}" unless res.success?
        j = JSON.parse(res.body)
        Discovery.new(
          j["authorization_endpoint"].as_s,
          j["token_endpoint"].as_s,
          j["userinfo_endpoint"]?.try(&.as_s?),
          j["issuer"]?.try(&.as_s?) || @issuer,
        )
      end
    end

    # redirect_uri is the absolute callback URL for the site the browser is
    # on; the same value must be sent again to exchange the resulting code.
    def authorize_url(state : String, nonce : String, redirect_uri : String) : String
      params = URI::Params.build do |query|
        query.add "response_type", "code"
        query.add "client_id", @client_id
        query.add "redirect_uri", redirect_uri
        query.add "scope", @scopes
        query.add "state", state
        query.add "nonce", nonce
      end
      ep = discovery.authorization_endpoint
      ep + (ep.includes?('?') ? "&" : "?") + params
    end

    def exchange(code : String, nonce : String, redirect_uri : String) : User
      form = URI::Params.build do |query|
        query.add "grant_type", "authorization_code"
        query.add "code", code
        query.add "redirect_uri", redirect_uri
        if @auth_method == "post"
          query.add "client_id", @client_id
          query.add "client_secret", @client_secret
        end
      end
      headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded", "Accept" => "application/json"}
      if @auth_method != "post"
        headers["Authorization"] = "Basic " + Base64.strict_encode("#{URI.encode_www_form(@client_id)}:#{URI.encode_www_form(@client_secret)}")
      end
      res = HTTP::Client.post(discovery.token_endpoint, headers: headers, body: form)
      raise "token endpoint returned #{res.status_code}: #{res.body[0, 300]}" unless res.success?
      tok = JSON.parse(res.body)
      id_token = tok["id_token"]?.try(&.as_s?) || raise "no id_token in token response"
      claims = decode_jwt_payload(id_token)

      iss = claims["iss"]?.try(&.as_s?) || ""
      raise "id_token issuer mismatch (#{iss})" unless iss.rstrip('/') == discovery.issuer.rstrip('/') || iss.rstrip('/') == @issuer.rstrip('/')
      aud = claims["aud"]?
      aud_ok = case raw = aud.try(&.raw)
               when String then raw == @client_id
               when Array  then raw.any? { |a| a.as_s? == @client_id }
               else             false
               end
      raise "id_token audience mismatch" unless aud_ok
      exp = claims["exp"]?.try(&.as_i64?) || 0_i64
      raise "id_token expired" if Time.unix(exp) <= Time.utc
      raise "id_token nonce mismatch" unless claims["nonce"]?.try(&.as_s?) == nonce

      merged = claims.as_h.dup
      if (ui = discovery.userinfo_endpoint) && (at = tok["access_token"]?.try(&.as_s?))
        begin
          r = HTTP::Client.get(ui, headers: HTTP::Headers{"Authorization" => "Bearer #{at}", "Accept" => "application/json"})
          if r.success?
            info = JSON.parse(r.body).as_h
            # userinfo `sub` must match the id_token's
            if info["sub"]?.try(&.as_s?) == claims["sub"]?.try(&.as_s?)
              info.each { |k, v| merged[k] = v }
            end
          end
        rescue e
          Log.warn(exception: e) { "userinfo fetch failed" }
        end
      end
      all = JSON::Any.new(merged)
      email = all["email"]?.try(&.as_s?).presence || all["preferred_username"]?.try(&.as_s?).presence ||
              raise "identity provider returned no email"
      name = all["name"]?.try(&.as_s?).presence || all["preferred_username"]?.try(&.as_s?).presence || email
      User.new(email.downcase, name, all)
    end

    def self.decode_jwt_payload(jwt : String) : JSON::Any
      parts = jwt.split('.')
      raise "malformed id_token" unless parts.size == 3
      JSON.parse(String.new(Base64.decode(parts[1].tr("-_", "+/") + "=" * ((4 - parts[1].size % 4) % 4))))
    end

    def decode_jwt_payload(jwt : String) : JSON::Any
      self.class.decode_jwt_payload(jwt)
    end

    # "groups=clpaste-admins" matched against claims (string or array).
    def self.claim_match?(rule : String, claims : JSON::Any) : Bool
      return false if rule.empty?
      key, _, val = rule.partition('=')
      c = claims[key.strip]? || return false
      case raw = c.raw
      when String then raw == val.strip
      when Array  then raw.any? { |x| x.as_s? == val.strip }
      when Bool   then raw.to_s == val.strip
      else             false
      end
    end
  end
end
