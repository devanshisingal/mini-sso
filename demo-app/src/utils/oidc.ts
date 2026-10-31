import * as jose from 'jose';
import { calculateCodeChallenge, generateRandomString } from './pkce';

export const OIDC_CONFIG = {
  clientId: 'demo-client-app',
  issuer: import.meta.env.VITE_IDP_ISSUER || 'http://localhost:8000',
  redirectUri: typeof window !== 'undefined'
    ? `${window.location.origin}/callback`
    : 'http://localhost:5174/callback',
  scope: 'openid profile email',
};

export interface AuthSession {
  userinfo: {
    sub: string;
    email: string;
    email_verified: boolean;
  };
  idTokenPayload: Record<string, unknown>;
  tokens: {
    access_token: string;
    id_token: string;
    token_type: string;
    expires_in: number;
  };
}

export async function initiateLogin(): Promise<void> {
  const codeVerifier = generateRandomString(64);
  const codeChallenge = await calculateCodeChallenge(codeVerifier);
  const state = generateRandomString(32);
  const nonce = generateRandomString(32);

  // Store in sessionStorage to verify during /callback
  sessionStorage.setItem('oidc_verifier', codeVerifier);
  sessionStorage.setItem('oidc_state', state);
  sessionStorage.setItem('oidc_nonce', nonce);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: OIDC_CONFIG.clientId,
    redirect_uri: OIDC_CONFIG.redirectUri,
    scope: OIDC_CONFIG.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    nonce,
  });

  const authorizeUrl = `${OIDC_CONFIG.issuer}/authorize?${params.toString()}`;
  window.location.href = authorizeUrl;
}

export async function handleCallback(code: string, returnedState: string): Promise<AuthSession> {
  const savedState = sessionStorage.getItem('oidc_state');
  const codeVerifier = sessionStorage.getItem('oidc_verifier');
  const expectedNonce = sessionStorage.getItem('oidc_nonce');

  // Clear state from storage to avoid replay
  sessionStorage.removeItem('oidc_state');
  sessionStorage.removeItem('oidc_verifier');
  sessionStorage.removeItem('oidc_nonce');

  if (!savedState || returnedState !== savedState) {
    throw new Error('Invalid state parameter: possible CSRF attack.');
  }

  if (!codeVerifier) {
    throw new Error('Missing code_verifier in browser session.');
  }

  // 1. Swap authorization code + code_verifier for tokens at /token
  const tokenEndpoint = `${OIDC_CONFIG.issuer}/token`;
  const tokenResponse = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: OIDC_CONFIG.redirectUri,
      client_id: OIDC_CONFIG.clientId,
      code_verifier: codeVerifier,
    }),
  });

  const tokens = await tokenResponse.json();
  if (!tokenResponse.ok) {
    throw new Error(tokens.detail || 'Failed to exchange authorization code for tokens');
  }

  // 2. Fetch JWKS and verify RS256 signature of the ID token
  const jwksUri = new URL(`${OIDC_CONFIG.issuer}/.well-known/jwks.json`);
  const JWKS = jose.createRemoteJWKSet(jwksUri);

  const { payload } = await jose.jwtVerify(tokens.id_token, JWKS, {
    issuer: OIDC_CONFIG.issuer,
    audience: OIDC_CONFIG.clientId,
  });

  // 3. Verify nonce claim
  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw new Error('ID Token nonce claim mismatch');
  }

  // 4. Fetch profile from /userinfo with Access Token
  const userinfoEndpoint = `${OIDC_CONFIG.issuer}/userinfo`;
  const userinfoResponse = await fetch(userinfoEndpoint, {
    headers: {
      Authorization: `Bearer ${tokens.access_token}`,
      Accept: 'application/json',
    },
  });

  const userinfo = await userinfoResponse.json();
  if (!userinfoResponse.ok) {
    throw new Error(userinfo.detail || 'Failed to fetch userinfo');
  }

  const session: AuthSession = {
    userinfo,
    idTokenPayload: payload as Record<string, unknown>,
    tokens,
  };

  localStorage.setItem('demo_auth_session', JSON.stringify(session));
  return session;
}

export function getStoredSession(): AuthSession | null {
  const raw = localStorage.getItem('demo_auth_session');
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearStoredSession(): void {
  localStorage.removeItem('demo_auth_session');
}
