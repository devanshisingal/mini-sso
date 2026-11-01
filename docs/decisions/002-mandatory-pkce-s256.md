# ADR 002: Mandatory PKCE S256 for Public Clients

## Status
Accepted

## Context
In OAuth 2.0 (RFC 6749), Single Page Applications (SPAs) and mobile native apps are classified as *public clients* because they execute in an untrusted browser or client environment and cannot securely hold a client secret (`client_secret`).
Historically, public clients used the *Implicit Grant* (returning tokens directly in the URL hash fragment) or authorization code flow without PKCE. Both approaches are vulnerable to authorization code interception, browser history leakage, and referrer header leakage.

## Decision
We enforce **Mandatory PKCE (Proof Key for Code Exchange, RFC 7636)** with the **`S256`** code challenge method across all authorization requests.
- `code_challenge_method=plain` is strictly rejected.
- The `code_verifier` must be between 43 and 128 unreserved ASCII characters (`[A-Za-z0-9\-._~]`).
- Implicit grant (`response_type=token`) and password grants are disabled.

## Rationale
1. **Mathematical Pre-image Resistance**: `S256` uses SHA-256: `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`. An attacker intercepting the authorization request only observes the one-way SHA-256 digest (`code_challenge`), from which they cannot compute `code_verifier`.
2. **Elimination of `plain` Method**: If `code_challenge_method=plain` were permitted, an eavesdropper intercepting the initial `/authorize` query string would capture the raw verifier, neutralizing the defense.
3. **Alignment with OAuth 2.1 & BCP**: The IETF OAuth 2.1 specification and OAuth 2.0 Security Best Current Practice (BCP) deprecate the Implicit Flow and mandate PKCE for all authorization code flows.

## Consequences
- Single Page Applications like our `demo-app` generate a random 64-character unreserved verifier in browser `sessionStorage`, compute the SHA-256 challenge using Web Crypto `crypto.subtle.digest`, and pass it to `/authorize`.
- Even if an attacker intercepts the authorization code in flight, they cannot exchange it at `/token` without the high-entropy `code_verifier`.
