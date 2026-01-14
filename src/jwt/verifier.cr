require "./token"
require "./public_keys"

module JWT
  struct VerifierConfig
    property expected_issuer : String?
    property expected_audience : String?
    property verify_audience : Bool = false
    property time_tolerance : Time::Span = 200.milliseconds
    property time_source : Proc(Time) = -> { Time.utc }

    def initialize(
      @expected_issuer = nil,
      @expected_audience = nil,
      @verify_audience = false,
      @time_tolerance = 200.milliseconds,
      @time_source = -> { Time.utc },
    )
    end
  end

  class Verifier
    def initialize(@config : VerifierConfig, @public_keys : PublicKeys)
    end

    def verify(token : String) : Token
      prevalidate_token(token)
      verified_token = verify_with_public_key(token)
      validate_claims(verified_token)
      verified_token
    end

    private def prevalidate_token(token : String)
      raise PasswordFormatError.new("Invalid JWT format") unless token.starts_with?("ey")

      parts = token.split('.', 4)
      raise PasswordFormatError.new("Invalid JWT format") unless parts.size == 3

      header = RS256Parser.decode_header(token)
      alg = header["alg"]?.try(&.as_s)
      raise DecodeError.new("Missing algorithm in header") unless alg
      raise DecodeError.new("Expected RS256, got #{alg}") unless alg == "RS256"

      payload_str = RS256Parser.base64url_decode(parts[1])
      payload = JSON.parse(payload_str)

      now = @config.time_source.call

      exp = payload["exp"]?.try(&.as_i64?)
      raise DecodeError.new("Missing exp claim in token") unless exp
      raise VerificationError.new("Token has expired") if Time.unix(exp) <= now

      if iat = payload["iat"]?.try(&.as_i64?)
        raise DecodeError.new("Token issued in the future") if Time.unix(iat) > now + @config.time_tolerance
      end

      if nbf = payload["nbf"]?.try(&.as_i64?)
        raise DecodeError.new("Token not yet valid") if Time.unix(nbf) > now
      end
    end

    private def verify_with_public_key(token : String) : Token
      @public_keys.decode(token)
    end

    private def validate_claims(token : Token)
      validate_issuer(token.payload) if @config.expected_issuer
      validate_audience(token.payload) if @config.verify_audience
    end

    private def validate_issuer(payload)
      expected = @config.expected_issuer
      return unless expected

      issuer = payload["iss"]?.try(&.as_s?)
      raise DecodeError.new("Missing or invalid iss claim in token") unless issuer

      if issuer.chomp("/") != expected.chomp("/")
        raise VerificationError.new("Token issuer does not match the expected issuer")
      end
    end

    private def validate_audience(payload)
      expected = @config.expected_audience
      return unless expected && !expected.empty?

      aud = payload["aud"]?
      return unless aud

      audiences = case aud
                  when .as_a? then aud.as_a.map(&.as_s)
                  when .as_s? then [aud.as_s]
                  else             return
                  end

      unless audiences.includes?(expected)
        raise VerificationError.new("Token audience does not match expected value")
      end
    end
  end
end
