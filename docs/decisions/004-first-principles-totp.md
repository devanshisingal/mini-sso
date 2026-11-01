# ADR 004: First-Principles RFC 6238 TOTP Implementation

## Status
Accepted

## Context
Two-factor authentication (2FA) is essential for modern Single Sign-On platforms. Time-Based One-Time Passwords (TOTP, RFC 6238) are the global standard used by authenticator applications (Google Authenticator, Microsoft Authenticator, 1Password, Authy). In Python, developers often import black-box libraries like `pyotp`. However, building authentication infrastructure for an engineering pathway requires deep algorithmic mastery and defensibility: understanding HMAC-SHA1/SHA256/SHA512, Big-Endian integer packing, Dynamic Truncation, clock drift windows, and replay prevention.

## Decision
We implemented RFC 6238 TOTP and RFC 4226 HOTP **from first principles** in `app/core/totp.py` using Python's standard library (`hmac`, `hashlib`, `struct`, `base64`):
1. **Time Counter**: $T = \lfloor \frac{\text{epoch\_seconds} - T_0}{X} \rfloor$ with $X = 30$ seconds and $T_0 = 0$.
2. **Big-Endian Packing**: $T$ packed as an 8-byte unsigned integer `>Q` via `struct.pack(">Q", counter)`.
3. **HMAC Digest**: $\text{HS} = \text{HMAC-SHA1}(K, C)$.
4. **Dynamic Truncation**:
   - `offset = HS[19] & 0x0f` (lowest 4 bits of the last byte).
   - `binary_code = (HS[offset] & 0x7f) << 24 | (HS[offset+1] & 0xff) << 16 | (HS[offset+2] & 0xff) << 8 | (HS[offset+3] & 0xff)`.
   - `code = (binary_code % 10^digits).zfill(digits)`.
5. **Clock Drift Tolerance**: Validates steps $T - 1$, $T$, and $T + 1$ to tolerate $\pm 30$ seconds of client clock skew.
6. **Anti-Replay Protection**: Stores `last_used_step` in `totp_credentials`. If a code is presented within the valid window but corresponds to $T \le \text{last\_used\_step}$, it is rejected.
7. **RFC Test Vectors**: Verified against all RFC 6238 Appendix B test vectors for SHA-1, SHA-256, and SHA-512.

## Rationale
1. **Explainability**: Every calculation is readable, transparent, and completely free of third-party baggage or vulnerabilities.
2. **Deterministic Security**: Direct control over key decryption, constant-time verification comparisons, and database replay state updates.
3. **Standards Compliance**: Verified against the published RFC test vectors, while correctly accounting for published RFC Errata ID 2866 in test suites.

## Consequences
- Requires rigorous unit test coverage against boundary cases ($T-1, T, T+1, T+2$) and clock drift simulations, which we implemented in `tests/test_totp.py` and `tests/test_security_properties.py`.
