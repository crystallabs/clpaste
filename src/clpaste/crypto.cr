require "openssl"
require "openssl/pkcs5"
require "crypto/bcrypt/password"
require "digest/sha256"
require "base64"
require "random/secure"

# The stdlib cipher wrapper lacks AEAD tag control; bind the one missing call.
lib LibCrypto
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : Int32, arg : Int32, ptr : Void*) : Int32
end

class OpenSSL::Cipher
  EVP_CTRL_AEAD_GET_TAG = 0x10
  EVP_CTRL_AEAD_SET_TAG = 0x11

  def auth_tag(size : Int32 = 16) : Bytes
    tag = Bytes.new(size)
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, EVP_CTRL_AEAD_GET_TAG, size, tag.to_unsafe.as(Void*)) != 1
      raise Error.new "EVP_CIPHER_CTX_ctrl(GET_TAG)"
    end
    tag
  end

  def auth_tag=(tag : Bytes)
    if LibCrypto.evp_cipher_ctx_ctrl(@ctx, EVP_CTRL_AEAD_SET_TAG, tag.size, tag.to_unsafe.as(Void*)) != 1
      raise Error.new "EVP_CIPHER_CTX_ctrl(SET_TAG)"
    end
    tag
  end

  # Feed additional authenticated data (not encrypted, but covered by the tag).
  def auth_data=(aad : Bytes)
    return aad if aad.empty?
    len = 0
    if LibCrypto.evp_cipherupdate(@ctx, nil, pointerof(len), aad, aad.size) != 1
      raise Error.new "EVP_CipherUpdate(AAD)"
    end
    aad
  end
end

module Clpaste::Crypto
  class Error < Exception; end

  IV_LEN  = 12
  TAG_LEN = 16
  KEY_LEN = 32
  # For new pastes (OWASP figure for PBKDF2-HMAC-SHA256). Existing pastes
  # unwrap with the count stored in their metadata (Meta#kdf_iterations).
  PBKDF2_ITERATIONS = 600_000

  # Sealed blob layout: iv(12) || tag(16) || ciphertext
  def self.seal(key : Bytes, plaintext : Bytes, aad : String = "") : Bytes
    raise Error.new("bad key length") unless key.size == KEY_LEN
    c = OpenSSL::Cipher.new("aes-256-gcm")
    c.encrypt
    c.key = key
    iv = Random::Secure.random_bytes(IV_LEN)
    c.iv = iv
    c.auth_data = aad.to_slice
    ct = c.update(plaintext)
    fin = c.final
    tag = c.auth_tag(TAG_LEN)
    buf = Bytes.new(IV_LEN + TAG_LEN + ct.size + fin.size)
    buf.copy_from(iv)
    tag.copy_to(buf + IV_LEN)
    ct.copy_to(buf + IV_LEN + TAG_LEN)
    fin.copy_to(buf + IV_LEN + TAG_LEN + ct.size)
    buf
  end

  def self.open(key : Bytes, blob : Bytes, aad : String = "") : Bytes
    raise Error.new("bad key length") unless key.size == KEY_LEN
    raise Error.new("ciphertext too short") if blob.size < IV_LEN + TAG_LEN
    c = OpenSSL::Cipher.new("aes-256-gcm")
    c.decrypt
    c.key = key
    c.iv = blob[0, IV_LEN]
    c.auth_data = aad.to_slice
    pt = c.update(blob[IV_LEN + TAG_LEN, blob.size - IV_LEN - TAG_LEN])
    c.auth_tag = blob[IV_LEN, TAG_LEN]
    fin = begin
      c.final
    rescue OpenSSL::Cipher::Error
      raise Error.new("decryption failed (wrong key or corrupted data)")
    end
    return pt if fin.empty?
    buf = Bytes.new(pt.size + fin.size)
    buf.copy_from(pt)
    fin.copy_to(buf + pt.size)
    buf
  end

  def self.random_key : Bytes
    Random::Secure.random_bytes(KEY_LEN)
  end

  # Random URL-safe token (for sessions, tickets, CLI handshakes).
  def self.token(bytes : Int32 = 32) : String
    Base64.urlsafe_encode(Random::Secure.random_bytes(bytes), padding: false)
  end

  def self.sha256_hex(s : String) : String
    Digest::SHA256.hexdigest(s)
  end

  def self.sha256_b64url(s : String) : String
    Base64.urlsafe_encode(Digest::SHA256.digest(s), padding: false)
  end

  def self.derive(password : String, salt : Bytes, iterations : Int32 = PBKDF2_ITERATIONS) : Bytes
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, OpenSSL::Algorithm::SHA256, KEY_LEN)
  end

  def self.hash_secret(secret : String, cost : Int32 = 10) : String
    ::Crypto::Bcrypt::Password.create(secret, cost: cost).to_s
  end

  def self.verify_secret(secret : String, hash : String) : Bool
    ::Crypto::Bcrypt::Password.new(hash).verify(secret)
  rescue
    false
  end

  # Accepts 64 hex chars or base64 (standard/urlsafe) for a 32-byte key.
  def self.parse_key(s : String) : Bytes
    s = s.strip
    if s.size == 64 && s =~ /\A[0-9a-fA-F]+\z/
      return s.hexbytes
    end
    begin
      b = Base64.decode(s)
      return b if b.size == KEY_LEN
    rescue
    end
    raise Error.new("master key must be 32 bytes as 64 hex chars or base64 (got #{s.size} chars)")
  end

  def self.generate_master_key : String
    random_key.hexstring
  end

  def self.constant_equal?(a : String, b : String) : Bool
    ::Crypto::Subtle.constant_time_compare(a.to_slice, b.to_slice)
  end
end
