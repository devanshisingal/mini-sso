import React, { useEffect, useState } from 'react';
import { AuthSession, clearStoredSession, getStoredSession, initiateLogin } from '../utils/oidc';

export const Home: React.FC = () => {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [showRawTokens, setShowRawTokens] = useState(false);

  useEffect(() => {
    const s = getStoredSession();
    setSession(s);
  }, []);

  const handleSignIn = async () => {
    setLoading(true);
    try {
      await initiateLogin();
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  const handleSignOut = () => {
    clearStoredSession();
    setSession(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Navigation Bar */}
        <div className="flex justify-between items-center bg-white p-4 rounded-2xl shadow-sm border border-slate-200">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-gradient-to-tr from-emerald-600 to-teal-700 text-white rounded-xl flex items-center justify-center font-bold text-lg shadow-sm">
              APP
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900">Demo Client Application</h1>
              <p className="text-xs text-slate-500">OpenID Connect Relying Party with PKCE</p>
            </div>
          </div>

          <div>
            {session ? (
              <button
                onClick={handleSignOut}
                className="px-3.5 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-semibold transition"
              >
                Sign Out
              </button>
            ) : (
              <span className="text-xs text-slate-400 font-mono">Status: Unauthenticated</span>
            )}
          </div>
        </div>

        {/* Unauthenticated View */}
        {!session ? (
          <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-8 sm:p-12 text-center space-y-8">
            <div className="max-w-xl mx-auto space-y-4">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-emerald-50 rounded-2xl text-emerald-600 mb-2">
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                </svg>
              </div>
              <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight">
                Single Sign-On Integration
              </h2>
              <p className="text-slate-600 text-sm leading-relaxed">
                Experience enterprise SSO modeled after HENNGE One. This demo relies on our custom
                OpenID Connect IdP featuring Argon2id password security, RFC 6238 TOTP two-factor authentication, and S256 PKCE authorization code exchange.
              </p>
            </div>

            {/* SSO Sign In Button */}
            <div className="flex justify-center">
              <button
                onClick={handleSignIn}
                disabled={loading}
                className="px-8 py-3.5 bg-blue-700 hover:bg-blue-800 text-white rounded-xl text-sm font-semibold shadow-md hover:shadow-lg transition duration-150 flex items-center space-x-3 disabled:opacity-50"
              >
                <svg className="w-5 h-5 text-blue-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span>{loading ? 'Redirecting to IdP...' : 'Sign in with Mini SSO'}</span>
              </button>
            </div>

            {/* Flow Details Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left pt-8 border-t border-slate-100">
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-xs font-bold text-blue-700 uppercase block mb-1">1. PKCE (S256)</span>
                <p className="text-xs text-slate-600">
                  A high-entropy random code_verifier is generated in the browser. Its SHA-256 code_challenge is passed to /authorize.
                </p>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-xs font-bold text-indigo-700 uppercase block mb-1">2. 2FA Authentication</span>
                <p className="text-xs text-slate-600">
                  User validates password with Argon2id and completes TOTP verification. IdP issues single-use authorization code.
                </p>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-xs font-bold text-emerald-700 uppercase block mb-1">3. JWKS Verification</span>
                <p className="text-xs text-slate-600">
                  Browser client exchanges code with verifier at /token, then validates RS256 signature using IdP's public keys.
                </p>
              </div>
            </div>
          </div>
        ) : (
          /* Authenticated Profile View */
          <div className="space-y-6">
            <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-8 space-y-6">
              <div className="flex justify-between items-start border-b border-slate-100 pb-6">
                <div>
                  <div className="flex items-center space-x-2">
                    <h2 className="text-2xl font-bold text-slate-900">Welcome, {session.userinfo.email}</h2>
                    <span className="px-2.5 py-0.5 bg-green-100 text-green-800 text-xs font-semibold rounded-full">
                      SSO Authenticated
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    Successfully authenticated through OpenID Connect with PKCE & TOTP MFA.
                  </p>
                </div>
              </div>

              {/* Userinfo Overview */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                  <span className="text-xs font-semibold text-slate-500 block">Email</span>
                  <span className="text-sm font-medium text-slate-900">{session.userinfo.email}</span>
                </div>
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                  <span className="text-xs font-semibold text-slate-500 block">Subject ID (sub)</span>
                  <span className="text-xs font-mono text-slate-700 break-all">{session.userinfo.sub}</span>
                </div>
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
                  <span className="text-xs font-semibold text-slate-500 block">Email Verified</span>
                  <span className="text-sm font-semibold text-green-700">
                    {session.userinfo.email_verified ? 'Verified (true)' : 'False'}
                  </span>
                </div>
              </div>

              {/* Decoded ID Token Claims */}
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <h3 className="text-sm font-bold text-slate-900">
                    Verified ID Token Claims (RS256 Signature Validated)
                  </h3>
                  <span className="text-[11px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                    iss: {session.idTokenPayload.iss as string}
                  </span>
                </div>
                <pre className="p-4 bg-slate-900 text-emerald-400 rounded-xl text-xs font-mono overflow-x-auto shadow-inner">
                  {JSON.stringify(session.idTokenPayload, null, 2)}
                </pre>
              </div>

              {/* Collapsible Raw Tokens */}
              <div className="border-t border-slate-100 pt-4">
                <button
                  onClick={() => setShowRawTokens(!showRawTokens)}
                  className="text-xs font-semibold text-blue-700 hover:text-blue-800 flex items-center"
                >
                  <span>{showRawTokens ? 'Hide Raw Tokens' : 'Inspect Raw RS256 Tokens'}</span>
                  <svg className={`w-3.5 h-3.5 ml-1 transform transition ${showRawTokens ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {showRawTokens && (
                  <div className="mt-4 space-y-4">
                    <div>
                      <span className="text-xs font-semibold text-slate-500 block mb-1">ID Token (Signed RS256 JWT):</span>
                      <textarea
                        readOnly
                        rows={3}
                        value={session.tokens.id_token}
                        className="w-full p-2.5 bg-slate-50 font-mono text-xs rounded-lg border border-slate-200 text-slate-700"
                      />
                    </div>
                    <div>
                      <span className="text-xs font-semibold text-slate-500 block mb-1">Access Token:</span>
                      <textarea
                        readOnly
                        rows={3}
                        value={session.tokens.access_token}
                        className="w-full p-2.5 bg-slate-50 font-mono text-xs rounded-lg border border-slate-200 text-slate-700"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
