import { describe, it, expect } from 'vitest';
import { calculateCodeChallenge, generateRandomString } from '../utils/pkce';

describe('PKCE S256 Utilities in Demo App', () => {
  it('generates unreserved random strings of requested length', () => {
    const str = generateRandomString(64);
    expect(str).toHaveLength(64);
    expect(/^[A-Za-z0-9\-._~]+$/.test(str)).toBe(true);
  });

  it('matches RFC 7636 Appendix B test vector for S256 challenge', async () => {
    // RFC 7636 Appendix B:
    // verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await calculateCodeChallenge(verifier);
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});
