import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api, User } from '../api/client';

export const Account: React.FC = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const u = await api.getMe();
        setUser(u);
      } catch {
        navigate('/login');
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, [navigate]);

  const handleLogout = async () => {
    await api.logout();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="animate-spin w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full"></div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="min-h-screen bg-slate-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl mx-auto">
        {/* Navigation Bar */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-700 text-white rounded-xl flex items-center justify-center font-bold text-lg">
              SSO
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900">Mini SSO IdP</h1>
              <p className="text-xs text-slate-500">Identity & Access Management</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            {user.is_admin && (
              <Link
                to="/admin"
                className="px-3 py-1.5 bg-indigo-50 border border-indigo-200 text-indigo-700 rounded-lg text-xs font-semibold hover:bg-indigo-100 transition"
              >
                Admin Console
              </Link>
            )}
            <button
              onClick={handleLogout}
              className="px-3 py-1.5 bg-slate-200 text-slate-700 rounded-lg text-xs font-semibold hover:bg-slate-300 transition"
            >
              Sign Out
            </button>
          </div>
        </div>

        {/* Profile Card */}
        <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-8 space-y-6">
          <div className="border-b border-slate-100 pb-6 flex justify-between items-start">
            <div>
              <h2 className="text-xl font-bold text-slate-900">Your Account</h2>
              <p className="text-sm text-slate-500">Manage security credentials and single sign-on access</p>
            </div>
            {user.is_admin && (
              <span className="px-2.5 py-1 bg-purple-100 text-purple-800 rounded-full text-xs font-semibold">
                Administrator
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-xs font-semibold text-slate-500 block">Email Address</span>
              <span className="text-sm font-medium text-slate-900 break-all">{user.email}</span>
            </div>

            <div className="p-4 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-xs font-semibold text-slate-500 block">User ID (Subject)</span>
              <span className="text-xs font-mono text-slate-700 break-all">{user.id}</span>
            </div>
          </div>

          {/* MFA Security Status */}
          <div className="p-5 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-100 rounded-xl flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center ${user.has_mfa ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700'}`}>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Two-Factor Authentication (TOTP)
                </h3>
                <p className="text-xs text-slate-500">
                  {user.has_mfa ? 'Active and protecting your account' : 'Not configured. Recommended for security.'}
                </p>
              </div>
            </div>

            <div>
              {user.has_mfa ? (
                <span className="px-3 py-1 bg-green-100 text-green-800 text-xs font-semibold rounded-full">
                  Enabled
                </span>
              ) : (
                <Link
                  to="/mfa-enroll"
                  className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white rounded-lg text-xs font-semibold transition"
                >
                  Set up 2FA
                </Link>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
