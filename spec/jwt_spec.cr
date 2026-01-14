require "./spec_helper"

describe JWT do
  describe "RS256Parser" do
    describe ".base64url_decode" do
      it "decodes standard base64url" do
        JWT::RS256Parser.base64url_decode("SGVsbG8gV29ybGQ").should eq("Hello World")
      end

      it "decodes base64url with padding" do
        JWT::RS256Parser.base64url_decode("SGVsbG8").should eq("Hello")
      end

      it "handles URL-safe characters" do
        # Base64url uses - and _ instead of + and /
        input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        result = JWT::RS256Parser.base64url_decode(input)
        result.should contain("RS256")
      end
    end

    describe ".decode_header" do
      it "decodes JWT header" do
        # Sample JWT header: {"alg":"RS256","typ":"JWT"}
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        header = JWT::RS256Parser.decode_header(token)
        header["alg"].as_s.should eq("RS256")
        header["typ"].as_s.should eq("JWT")
      end

      it "raises on invalid format" do
        expect_raises(JWT::DecodeError, "Invalid JWT format") do
          JWT::RS256Parser.decode_header("invalid")
        end
      end
    end

    describe ".decode" do
      it "raises on non-RS256 algorithm" do
        # Header with HS256: {"alg":"HS256","typ":"JWT"}
        # Payload: {"sub":"1234567890"}
        # Signature: dummy base64url string
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
        expect_raises(JWT::DecodeError, "Expected RS256") do
          JWT::RS256Parser.decode(token, "", verify: false)
        end
      end

      it "raises on missing algorithm" do
        # Header without alg: {"typ":"JWT"}
        # Payload: {"sub":"1234567890"}
        # Signature: dummy base64url string
        token = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
        expect_raises(JWT::DecodeError, "Missing algorithm") do
          JWT::RS256Parser.decode(token, "", verify: false)
        end
      end

      it "decodes without verification" do
        # Valid RS256 token structure
        # Header: {"alg":"RS256","typ":"JWT"}
        # Payload: {"sub":"1234567890","name":"John Doe"}
        # Signature: dummy base64url string
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dGVzdHNpZ25hdHVyZQ"
        result = JWT::RS256Parser.decode(token, "", verify: false)
        result.should be_a(JWT::Token)
        result.payload["sub"].as_s.should eq("1234567890")
        result.payload["name"].as_s.should eq("John Doe")
      end
    end
  end

  describe "Token" do
    it "allows accessing payload claims" do
      token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dGVzdHNpZ25hdHVyZQ"
      result = JWT::RS256Parser.decode(token, "", verify: false)
      result["sub"].as_s.should eq("1234567890")
      result["name"].as_s.should eq("John Doe")
      result["missing"]?.should be_nil
    end
  end

  describe "PublicKeys" do
    it "starts empty" do
      keys = JWT::PublicKeys.new
      keys.get?.should be_nil
    end

    it "stores and retrieves keys" do
      keys = JWT::PublicKeys.new
      test_keys = {"key1" => "pem1", "key2" => "pem2"}
      keys.update(test_keys, 1.hour)
      keys.get?.should eq(test_keys)
    end

    it "returns nil for expired keys" do
      keys = JWT::PublicKeys.new
      test_keys = {"key1" => "pem1"}
      keys.update(test_keys, 0.seconds) # Immediate expiration
      sleep 0.01.seconds # Small delay to ensure expiration
      keys.get?.should be_nil
    end

    it "can be cleared" do
      keys = JWT::PublicKeys.new
      keys.update({"key1" => "pem1"}, 1.hour)
      keys.clear
      keys.get?.should be_nil
    end
  end

  describe "VerifierConfig" do
    it "has sensible defaults" do
      config = JWT::VerifierConfig.new
      config.expected_issuer.should be_nil
      config.expected_audience.should be_nil
      config.verify_audience.should be_false
      config.time_tolerance.should eq(200.milliseconds)
    end

    it "can be configured" do
      config = JWT::VerifierConfig.new(
        expected_issuer: "https://auth.example.com",
        expected_audience: "my-api",
        verify_audience: true
      )
      config.expected_issuer.should eq("https://auth.example.com")
      config.expected_audience.should eq("my-api")
      config.verify_audience.should be_true
    end
  end
end
