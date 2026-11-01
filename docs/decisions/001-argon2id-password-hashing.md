# ADR 001: Argon2id Password Hashing

## Status
Accepted

## Context
A primary responsibility of an Identity Provider is securely storing user authentication credentials. Passwords must never be stored in plaintext. Historically, algorithms like MD5, SHA-1, SHA-256, PBKDF2, and bcrypt have been used. However, modern GPU and ASIC hardware can compute billions of SHA-256 or MD5 hashes per second, making traditional hashing trivially vulnerable to offline dictionary and rainbow table attacks.

## Decision
We chose **Argon2id** (the hybrid variant of Argon2, winner of the Password Hashing Competition and specified in RFC 9106) using the `argon2-cffi` implementation.
- Parameters:
  - Memory cost: `65,536 KiB` (64 MiB)
  - Time iterations: `3`
  - Parallelism: `4` threads
- Input constraint: Maximum password length of `128` characters enforced at Pydantic schema validation.

## Rationale
1. **Memory-hardness**: Unlike bcrypt (which uses only 4 KB of memory) or PBKDF2 (CPU-bound only), Argon2id forces the hashing process to consume significant memory (64 MiB). This drastically increases the cost and memory bus requirements for custom ASIC or GPU brute-force clusters.
2. **Side-channel resistance**: Argon2i protects against side-channel timing attacks by data-independent memory addressing, while Argon2d maximizes resistance against GPU cracking by data-dependent addressing. Argon2id combines both approaches: using data-independent addressing for the first pass and data-dependent for subsequent passes.
3. **DoS Prevention via Length Capping**: Because Argon2 is intentionally resource-intensive, accepting an arbitrary-length password (e.g., 10 MB payload) would allow an unauthenticated attacker to exhaust server CPU and RAM. Capping password length to 128 characters rejects malicious payloads before hashing.

## Consequences
- Requires ~60–100ms of CPU time per password verification, which is ideal for interactive human logins while thwarting offline brute-force.
- Slightly higher memory footprint on the API server compared to legacy algorithms, which is readily accommodated by standard containers (256MB–512MB RAM).
