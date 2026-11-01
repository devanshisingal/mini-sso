# ADR 005: Asymmetric RS256 JWTs with JWKS and Graceful Key Rotation

## Status
Accepted

## Context
In Single Sign-On and OpenID Connect systems, the Identity Provider issues ID Tokens to client applications to prove user identity. There are two primary architectural patterns for JWT signing:
1. Symmetric signing (HS256): A shared secret is distributed to all client apps.
2. Asymmetric signing (RS256): The IdP signs tokens using a private RSA key; client apps verify tokens using the IdP's public key published at `/.well-known/jwks.json`.

## Decision
We chose **Asymmetric RS256** with **RFC 7517 JSON Web Key Sets (JWKS)** and graceful key rotation:
1. The IdP generates 2048-bit RSA key pairs (`kid`, PEM private key, PEM public key).
2. The active private key is retained exclusively inside the IdP database and memory.
3. The public key is converted to standard JWK format (`kty="RSA"`, `alg="RS256"`, `use="sig"`, `kid`, and big-endian base64url-encoded modulus `n` and exponent `e`).
4. Client applications verify incoming ID tokens by fetching `/.well-known/jwks.json` and matching the token's header `kid`.
5. When the IdP rotates its signing key via `POST /admin/keys/rotate`:
   - A new key pair is generated and marked active.
   - The previous key is marked retired (`retired_at = now()`).
   - The `/.well-known/jwks.json` endpoint continues publishing both active and retired keys so existing in-flight tokens verify seamlessly until expiration.

## Rationale
1. **Zero Secret Sharing**: Client applications never receive or store the private key. Even if a client app (or its database) is completely compromised, an attacker cannot forge ID tokens for other applications.
2. **Standardized Decoupling**: Client applications do not require proprietary SDKs. Any compliant OIDC library (e.g. `jose`, `pyjwt`, Spring Security, Google OIDC client) can automatically discover and verify tokens.
3. **Graceful Rotation**: Cryptographic keys must be rotated periodically. Publishing multiple keys in the JWKS array allows new tokens to use the new key while older active tokens remain valid until expiration without downtime.

## Consequences
- Requires asymmetric math operations (RSA 2048-bit sign and verify) which require slightly more CPU cycles than HMAC-SHA256, but remain under 1ms per operation on modern hardware.
