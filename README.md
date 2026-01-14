# JWT

A Crystal library for JWT verification with RS256 and automatic JWKS fetching from OIDC providers.

## Features

- RS256 signature verification
- Automatic JWKS fetching and caching with OIDC discovery
- Standard claims validation (`exp`, `iat`, `nbf`, `iss`, `aud`)
- Thread-safe public key caching
- Automatic JWKS refresh with configurable TTL

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  jwt:
    github: 84codes/jwt.cr
```

Then run:

```bash
shards install
```

## Usage

### Basic JWT Verification with JWKS

```crystal
require "jwt"

# Create JWKS fetcher and start background refresh
fetcher = JWT::JWKSFetcher.new(
  issuer_url: "https://auth.example.com",
  default_cache_ttl: 1.hour
)
spawn { fetcher.refresh_loop }

# Configure and create verifier
config = JWT::VerifierConfig.new(
  expected_issuer: "https://auth.example.com",
  expected_audience: "my-api",
  verify_audience: true
)
verifier = JWT::Verifier.new(config, fetcher.public_keys)

# Verify tokens
token = verifier.verify(jwt_string)
puts token.payload["sub"]
```

The JWKS fetcher automatically:

1. Fetches `{issuer_url}/.well-known/openid-configuration`
2. Fetches public keys from the `jwks_uri`
3. Refreshes keys based on `Cache-Control` headers or `default_cache_ttl`

### Manual Decoding with Public Key

```crystal
require "jwt"

# With verification
token = JWT::RS256Parser.decode(jwt_string, public_key_pem)

# Without verification (testing only)
token = JWT::RS256Parser.decode(jwt_string, "", verify: false)
```

### Configuration

```crystal
# VerifierConfig
config = JWT::VerifierConfig.new(
  expected_issuer: "https://auth.example.com",
  expected_audience: "my-api",
  verify_audience: true,
  time_tolerance: 200.milliseconds  # Clock skew tolerance for iat validation
)

# JWKSFetcher
fetcher = JWT::JWKSFetcher.new(
  issuer_url: "https://auth.example.com",
  default_cache_ttl: 1.hour  # Used if no Cache-Control header
)

# Stop the refresh loop gracefully
fetcher.stop

# Manually trigger a refresh
fetcher.trigger_refresh
```

## Security

- Only RS256 algorithm accepted (prevents algorithm confusion attacks)
- Validates `exp`, `iat`, `nbf` time claims
- Optional `iss` and `aud` claim validation
- Supports multiple keys with `kid` (Key ID) lookup
- Thread-safe key caching

## Testing

```bash
crystal spec
```

## License

Apache License 2.0
