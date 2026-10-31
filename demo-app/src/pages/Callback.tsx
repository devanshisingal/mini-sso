import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { handleCallback } from '../utils/oidc';

export const Callback: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const processCallback = async () => {
      const params = new URLSearchParams(location.search);
      const code = params.get('code');
      const state = params.get('state');

      if (!code || !state) {
        setError('Missing code or state parameter in authorization response.');
        return;
      }

      try {
        await handleCallback(code, state);
        navigate('/', { replace: true });
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Failed to complete OpenID Connect token exchange.');
        }
      }
    };

    processCallback();
  }, [location.search, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl border border-slate-200 p-8 text-center space-y-6">
        {error ? (
          <>
            <div className="inline-flex items-center justify-center w-12 h-12 bg-red-100 rounded-full text-red-600 mb-2">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-xl font-bold text-slate-900">Authentication Error</h2>
            <p className="text-sm text-red-600 bg-red-50 p-3 rounded-lg border border-red-200 text-left font-mono">
              {error}
            </p>
            <div>
              <Link
                to="/"
                className="inline-block px-5 py-2.5 bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold rounded-lg transition"
              >
                Return to Demo App
              </Link>
            </div>
          </>
        ) : (
          <>
            <div className="animate-spin inline-block w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full mb-2"></div>
            <h2 className="text-lg font-bold text-slate-900">Verifying Security Credentials</h2>
            <p className="text-xs text-slate-500">
              Validating PKCE verifier, exchanging authorization code, and verifying RS256 signature against IdP JWKS...
            </p>
          </>
        )}
      </div>
    </div>
  );
};
