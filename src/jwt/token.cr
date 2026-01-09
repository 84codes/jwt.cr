require "base64"
require "json"
require "openssl"
require "./lib_crypto"

module JWT
  class Error < Exception; end

  class DecodeError < Error; end

  class VerificationError < Error; end

  class PasswordFormatError < Error; end

  class ExpiredKeysError < VerificationError; end

  struct Token
    getter header : JSON::Any
    getter payload : JSON::Any
    getter signature : Bytes

    def initialize(@header, @payload, @signature)
    end

    def [](key : String)
      @payload[key]
    end

    def []?(key : String)
      @payload[key]?
    end
  end

  class RS256Parser
    def self.decode_header(token : String) : JSON::Any
      parts = token.split('.')
      raise DecodeError.new("Invalid JWT format: expected 3 parts") unless parts.size == 3
      JSON.parse(base64url_decode(parts[0]))
    end

    def self.decode(token : String, public_key : String, verify : Bool = true) : Token
      parts = token.split('.')
      raise DecodeError.new("Invalid JWT format: expected 3 parts") unless parts.size == 3

      header_json = base64url_decode(parts[0])
      payload_json = base64url_decode(parts[1])
      signature = base64url_decode_bytes(parts[2])

      header = JSON.parse(header_json)
      payload = JSON.parse(payload_json)

      alg = header["alg"]?.try(&.as_s)
      raise DecodeError.new("Missing algorithm in header") unless alg
      raise DecodeError.new("Expected RS256, got #{alg}") unless alg == "RS256"

      if verify
        signing_input = "#{parts[0]}.#{parts[1]}"
        verify_signature(signing_input, signature, public_key)
      end

      Token.new(header, payload, signature)
    end

    def self.base64url_decode(str : String) : String
      base64 = str.tr("-_", "+/")

      case base64.size % 4
      when 0
      when 2
        base64 += "=="
      when 3
        base64 += "="
      else
        raise DecodeError.new("Invalid base64url encoding")
      end

      Base64.decode_string(base64)
    end

    def self.base64url_decode_bytes(str : String) : Bytes
      base64 = str.tr("-_", "+/")

      case base64.size % 4
      when 0
      when 2
        base64 += "=="
      when 3
        base64 += "="
      else
        raise DecodeError.new("Invalid base64url encoding")
      end

      Base64.decode(base64)
    end

    private def self.verify_signature(data : String, signature : Bytes, public_key_pem : String)
      bio = LibCrypto.BIO_new(LibCrypto.bio_s_mem)
      raise "Failed to create BIO" if bio.null?

      begin
        pem_bytes = public_key_pem.to_slice
        written = LibCrypto.bio_write(bio, pem_bytes, pem_bytes.size)
        raise VerificationError.new("Failed to write PEM to BIO") if written <= 0

        pkey = LibCrypto.pem_read_bio_pubkey(bio, nil, nil, nil)
        raise VerificationError.new("Failed to read public key from PEM") if pkey.null?

        begin
          md_ctx = LibCrypto.evp_md_ctx_new
          raise "Failed to create digest context" if md_ctx.null?

          begin
            result = LibCrypto.evp_digestverify_init(md_ctx, nil, LibCrypto.evp_sha256, nil, pkey)
            raise VerificationError.new("Failed to initialize verification") unless result == 1

            result = LibCrypto.evp_digestverify(md_ctx, signature, signature.size, data.to_slice, data.bytesize)
            raise VerificationError.new("Signature verification failed") unless result == 1
          ensure
            LibCrypto.evp_md_ctx_free(md_ctx)
          end
        ensure
          LibCrypto.evp_pkey_free(pkey)
        end
      ensure
        LibCrypto.BIO_free(bio)
      end
    end
  end
end
