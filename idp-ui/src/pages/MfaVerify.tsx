import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export const MfaVerify: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);

  const [mode, setMode] = useState<'totp' | 'recovery'>('totp');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const clientId = queryParams.get('client_id');
  const redirectUri = queryParams.get('redirect_uri');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = mode === 'totp'
        ? await api.verifyMfa(totpCode)
        : await api.verifyRecoveryCode(recoveryCode);

      if (clientId && redirectUri) {
        window.location.href = `http://localhost:8000/authorize?${queryParams.toString()}`;
        return;
      }

      if (res.user?.is_admin) {
        navigate('/admin');
      } else {
        navigate('/account');
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Verification failed. Invalid or expired code.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 p-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-700 to-indigo-800 p-6 text-white text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-white/10 rounded-xl mb-3 backdrop-blur-sm">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Two-Factor Authentication</h1>
          <p className="text-blue-100 text-sm mt-1">
            {mode === 'totp' ? 'Enter code from your authenticator app' : 'Enter one of your 10 backup recovery codes'}
          </p>
        </div>

        <div className="p-8">
          {error && (
            <div role="alert" className="mb-5 p-3.5 bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg flex items-start">
              <svg className="w-5 h-5 text-red-500 mr-2 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {mode === 'totp' ? (
              <div>
                <label htmlFor="mfa-totp-code" className="block text-sm font-medium text-slate-700 mb-2 text-center">
                  6-Digit Security Code
                </label>
                <input
                  id="mfa-totp-code"
                  type="text"
                  autoFocus
                  required
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  onPaste={(e) => {
                    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
                    if (pasted) {
                      e.preventDefault();
                      setTotpCode(pasted);
                    }
                  }}
                  placeholder="000000"
                  className="w-full text-center tracking-widest text-3xl font-mono py-3 px-4 rounded-xl border border-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 shadow-sm"
                />
                <p className="text-xs text-slate-500 mt-2 text-center">
                  Protected by anti-replay step verification (RFC 6238)
                </p>
              </div>
            ) : (
              <div>
                <label htmlFor="mfa-recovery-code" className="block text-sm font-medium text-slate-700 mb-2 text-center">
                  Backup Recovery Code
                </label>
                <input
                  id="mfa-recovery-code"
                  type="text"
                  autoFocus
                  required
                  autoCapitalize="characters"
                  maxLength={16}
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                  placeholder="ABCD-EFGH"
                  className="w-full text-center tracking-wider text-xl font-mono py-3 px-4 rounded-xl border border-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 shadow-sm uppercase"
                />
                <p className="text-xs text-slate-500 mt-2 text-center">
                  Each backup code can be used exactly once.
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || (mode === 'totp' ? totpCode.length !== 6 : recoveryCode.length < 6)}
              className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:ring-blue-200 text-white font-medium rounded-lg text-sm transition duration-150 flex items-center justify-center disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify & Continue'}
            </button>
          </form>

          {/* Mode toggle */}
          <div className="mt-6 pt-4 border-t border-slate-200 text-center">
            {mode === 'totp' ? (
              <button
                type="button"
                onClick={() => { setMode('recovery'); setError(null); }}
                className="text-xs font-semibold text-blue-700 hover:text-blue-900 focus:outline-none underline"
              >
                Lost your phone? Use a backup recovery code
              </button>
            ) : (
              <button
                type="button"
                onClick={() => { setMode('totp'); setError(null); }}
                className="text-xs font-semibold text-blue-700 hover:text-blue-900 focus:outline-none underline"
              >
                Back to Authenticator app code
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
