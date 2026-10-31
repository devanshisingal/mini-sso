import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as jose from 'jose';
import { handleCallback } from '../utils/oidc';

describe('Demo App OIDC Security & Failure-Case Verification', () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('aborts login when returned state does not match stored state (CSRF mitigation)', async () => {
    sessionStorage.setItem('oidc_state', 'expected-state-value');
    sessionStorage.setItem('oidc_verifier', 'dummy-verifier-43-chars-long-1234567890123');

    await expect(
      handleCallback('auth-code-123', 'tampered-or-attacker-state')
    ).rejects.toThrow(/Invalid state parameter: possible CSRF attack/);
  });

  it('aborts login when code_verifier is missing from session storage', async () => {
    sessionStorage.setItem('oidc_state', 'valid-state');
    // oidc_verifier is NOT set in sessionStorage

    await expect(
      handleCallback('auth-code-123', 'valid-state')
    ).rejects.toThrow(/Missing code_verifier in browser session/);
  });

  it('rejects ID token with wrong audience or issuer using jose', async () => {
    // Generate RSA key pair for testing
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');

    // Create token signed with wrong audience
    const invalidAudienceToken = await new jose.SignJWT({
      sub: 'user-123',
      email: 'alice@example.com',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
      .setIssuer('http://localhost:8000')
      .setAudience('wrong-client-app') // Not demo-client-app
      .setExpirationTime('1h')
      .sign(privateKey);

    await expect(
      jose.jwtVerify(invalidAudienceToken, publicKey, {
        issuer: 'http://localhost:8000',
        audience: 'demo-client-app',
      })
    ).rejects.toThrow();
  });

  it('rejects expired ID token using jose', async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');

    const expiredToken = await new jose.SignJWT({
      sub: 'user-123',
      email: 'alice@example.com',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
      .setIssuer('http://localhost:8000')
      .setAudience('demo-client-app')
      .setExpirationTime('1s ago')
      .sign(privateKey);

    await expect(
      jose.jwtVerify(expiredToken, publicKey, {
        issuer: 'http://localhost:8000',
        audience: 'demo-client-app',
      })
    ).rejects.toThrow();
  });
});
