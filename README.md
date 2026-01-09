# JWT

A Crystal library for JWT (JSON Web Token) parsing, verification, and JWKS (JSON Web Key Set) handling with RS256 signature support.

Extracted from [LavinMQ](https://github.com/cloudamqp/lavinmq)'s OAuth implementation and made into a standalone, reusable shard.

## Features

- **JWT Parsing**: Decode JWT tokens with RS256 signature verification
- **JWKS Support**: Automatic fetching and caching of public keys from OIDC providers
- **Standard Claims Validation**: Validates `exp`, `iat`, `nbf`, `iss`, and `aud` claims
- **Thread-Safe**: Public key caching with mutex protection
- **Background Refresh**: Automatic JWKS refresh with configurable TTL
- **OIDC Discovery**: Automatic discovery of JWKS endpoint from OIDC configuration

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: 84codes/jwt
```

Then run:

```bash
shards install
```

## Usage

### Basic JWT Verification with JWKS

```crystal
require "jwt"

# Create JWKS fetcher for your OAuth provider
fetcher = JWT::JWKSFetcher.new(
  issuer_url: "https://auth.example.com",
  default_cache_ttl: 1.hour
)

# Start background refresh loop in a separate fiber
spawn { fetcher.refresh_loop }

# Configure the verifier
config = JWT::VerifierConfig.new(
  expected_issuer: "https://auth.example.com",
  expected_audience: "my-api",
  verify_audience: true
)

verifier = JWT::Verifier.new(config, fetcher.public_keys)

# Verify a JWT token
begin
  token = verifier.verify(jwt_string)
  puts token.payload["sub"]  # Access subject claim
  puts token.payload["email"] # Access email claim
rescue ex : JWT::VerificationError
  puts "Invalid token: #{ex.message}"
end
```

### Manual JWT Decoding with a Public Key

If you already have the RSA public key in PEM format:

```crystal
require "jwt"

public_key = <<-PEM
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
PEM

begin
  token = JWT::RS256Parser.decode(jwt_string, public_key)
  puts token.payload
  puts token.header
rescue ex : JWT::DecodeError
  puts "Invalid JWT: #{ex.message}"
end
```

### Decoding Without Verification (for testing only)

```crystal
require "jwt"

# Decode without signature verification (NOT RECOMMENDED FOR PRODUCTION)
token = JWT::RS256Parser.decode(jwt_string, "", verify: false)
puts token.payload["sub"]
```

### Public Key Management

You can manage public keys manually:

```crystal
require "jwt"

keys = JWT::PublicKeys.new

# Add keys with TTL
public_keys = {
  "key-id-1" => "-----BEGIN PUBLIC KEY-----\n...",
  "key-id-2" => "-----BEGIN PUBLIC KEY-----\n..."
}
keys.update(public_keys, 1.hour)

# Decode and verify token
token = keys.decode(jwt_string)
```

## Configuration

### VerifierConfig Options

```crystal
config = JWT::VerifierConfig.new(
  expected_issuer: "https://auth.example.com",  # Expected iss claim
  expected_audience: "my-api",                   # Expected aud claim
  verify_audience: true,                         # Enable audience validation
  time_tolerance: 200.milliseconds               # Clock skew tolerance for iat
)
```

### JWKSFetcher Options

```crystal
fetcher = JWT::JWKSFetcher.new(
  issuer_url: "https://auth.example.com",  # OIDC issuer URL
  default_cache_ttl: 1.hour                # Default cache TTL (can be overridden by Cache-Control)
)
```

## Error Handling

The library provides specific exception types:

- `JWT::Error` - Base exception class
- `JWT::DecodeError` - Invalid JWT format or encoding issues
- `JWT::VerificationError` - Signature verification failed or claims invalid
- `JWT::ExpiredKeysError` - Public keys unavailable or expired

Example:

```crystal
begin
  token = verifier.verify(jwt_string)
rescue ex : JWT::ExpiredKeysError
  # Keys expired, wait for refresh
  puts "Public keys expired"
rescue ex : JWT::VerificationError
  # Signature or claims invalid
  puts "Token verification failed: #{ex.message}"
rescue ex : JWT::DecodeError
  # Invalid JWT format
  puts "Invalid JWT format: #{ex.message}"
end
```

## OIDC Discovery

The JWKS fetcher automatically discovers the JWKS endpoint using OIDC Discovery:

1. Fetches `{issuer_url}/.well-known/openid-configuration`
2. Extracts `jwks_uri` from the configuration
3. Fetches public keys from the JWKS endpoint
4. Respects `Cache-Control` headers for TTL

## Security Features

- **Algorithm Enforcement**: Only RS256 is accepted (prevents algorithm confusion attacks)
- **Issuer Validation**: Verifies token issuer matches configuration
- **Audience Validation**: Optional validation of audience claim
- **Time Claims Validation**:
  - `exp`: Token must not be expired
  - `iat`: Token must not be issued in the future (with configurable tolerance)
  - `nbf`: Token must not be used before its "not before" time
- **Signature Verification**: RS256 with RSA public keys from JWKS
- **Key Rotation**: Supports multiple keys and kid (Key ID) lookup
- **Fail Closed**: All errors result in verification failure

## Testing

Run the test suite:

```bash
crystal spec
```

## Development

The library uses standard Crystal development tools:

```bash
# Install dependencies
shards install

# Run tests
crystal spec

# Format code
crystal tool format

# Build
shards build
```

## Contributing

1. Fork it (<https://github.com/84codes/jwt/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

Apache License 2.0

## Credits

Extracted from [LavinMQ](https://github.com/cloudamqp/lavinmq) by [84codes](https://www.84codes.com).

Original implementation by the LavinMQ team.
