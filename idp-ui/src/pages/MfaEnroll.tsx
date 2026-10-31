import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export const MfaEnroll: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);

  const [loading, setLoading] = useState(true);
  const [secret, setSecret] = useState('');
  const [qrCodeSvg, setQrCodeSvg] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [copied, setCopied] = useState(false);

  const clientId = queryParams.get('client_id');
  const redirectUri = queryParams.get('redirect_uri');

  useEffect(() => {
    const enroll = async () => {
      try {
        const data = await api.enrollMfa();
        setSecret(data.secret);
        setQrCodeSvg(data.qr_code_svg);
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Failed to load MFA enrollment QR code.');
        }
      } finally {
        setLoading(false);
      }
    };
    enroll();
  }, []);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setVerifying(true);

    try {
      await api.verifyMfa(code);

      // Successfully confirmed 2FA!
      if (clientId && redirectUri) {
        // Resume OIDC authorization flow
        window.location.href = `http://localhost:8000/authorize?${queryParams.toString()}`;
        return;
      }

      navigate('/account');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Verification failed. Please check the 6-digit code.');
      }
    } finally {
      setVerifying(false);
    }
  };

  const copySecret = () => {
    navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 p-4">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-700 to-indigo-800 p-6 text-white text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-white/10 rounded-xl mb-3 backdrop-blur-sm">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Set Up Authenticator</h1>
          <p className="text-blue-100 text-sm mt-1">RFC 6238 Time-Based One-Time Password (TOTP)</p>
        </div>

        <div className="p-8">
          {error && (
            <div className="mb-5 p-3.5 bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg flex items-start">
              <svg className="w-5 h-5 text-red-500 mr-2 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div className="py-12 text-center text-slate-500">
              <div className="animate-spin inline-block w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full mb-3"></div>
              <p>Generating cryptographically secure secret...</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* QR Code Container */}
              <div className="flex flex-col items-center">
                <div className="p-3 bg-white border border-slate-200 rounded-xl shadow-inner">
                  <img src={qrCodeSvg} alt="TOTP QR Code" className="w-48 h-48" />
                </div>
                <p className="text-xs text-slate-500 mt-2 text-center">
                  Scan this QR code with Google Authenticator, 1Password, or Authy.
                </p>
              </div>

              {/* Secret Key Manual Entry */}
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
                  Or enter secret key manually
                </label>
                <div className="flex rounded-lg shadow-sm">
                  <input
                    type="text"
                    readOnly
                    value={secret}
                    className="flex-1 min-w-0 block w-full px-3 py-2 rounded-l-lg border border-slate-300 bg-slate-50 text-xs font-mono text-slate-800 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={copySecret}
                    className="inline-flex items-center px-3 py-2 border border-l-0 border-slate-300 rounded-r-lg bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Code Verification Form */}
              <form onSubmit={handleVerify} className="space-y-4 pt-2 border-t border-slate-100">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">
                    Enter the 6-digit code from your app
                  </label>
                  <input
                    type="text"
                    required
                    maxLength={6}
                    pattern="[0-9]{6}"
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="w-full text-center tracking-widest text-2xl font-mono px-3 py-2 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={verifying || code.length !== 6}
                  className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white font-medium rounded-lg text-sm transition duration-150 flex items-center justify-center disabled:opacity-50"
                >
                  {verifying ? 'Verifying Code...' : 'Activate 2FA & Continue'}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
