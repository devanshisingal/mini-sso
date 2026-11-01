import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  api,
  ClientApp,
  AuditLogItem,
  AuditVerificationResult,
  KeyRotationResult,
  MaintenanceCleanupResult,
} from '../api/client';

export const AdminDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [tab, setTab] = useState<'audit' | 'clients'>('audit');
  const [clients, setClients] = useState<ClientApp[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Security & maintenance states
  const [verification, setVerification] = useState<AuditVerificationResult | null>(null);
  const [verifyingAudit, setVerifyingAudit] = useState(false);
  const [keyRotation, setKeyRotation] = useState<KeyRotationResult | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);
  const [cleanup, setCleanup] = useState<MaintenanceCleanupResult | null>(null);
  const [cleaningUp, setCleaningUp] = useState(false);

  // New Client Form state
  const [showAddClient, setShowAddClient] = useState(false);
  const [newClientId, setNewClientId] = useState('');
  const [newClientName, setNewClientName] = useState('');
  const [newRedirectUris, setNewRedirectUris] = useState('');
  const [newAllowedCidrs, setNewAllowedCidrs] = useState('');
  const [submittingClient, setSubmittingClient] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [clientsData, auditData] = await Promise.all([
        api.listClients(),
        api.getAuditLogs(),
      ]);
      setClients(clientsData);
      setAuditLogs(auditData);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to fetch admin data.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleVerifyAuditChain = async () => {
    setVerifyingAudit(true);
    setError(null);
    try {
      const res = await api.verifyAuditLog();
      setVerification(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Audit verification failed.');
      }
    } finally {
      setVerifyingAudit(false);
    }
  };

  const handleRotateKey = async () => {
    if (!window.confirm('Are you sure you want to rotate the RSA signing key? Existing valid tokens will continue verifying through JWKS.')) {
      return;
    }
    setRotatingKey(true);
    setError(null);
    try {
      const res = await api.rotateSigningKey();
      setKeyRotation(res);
      await fetchData();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Key rotation failed.');
      }
    } finally {
      setRotatingKey(false);
    }
  };

  const handleMaintenanceCleanup = async () => {
    setCleaningUp(true);
    setError(null);
    try {
      const res = await api.cleanupMaintenance();
      setCleanup(res);
      await fetchData();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Maintenance cleanup failed.');
      }
    } finally {
      setCleaningUp(false);
    }
  };

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittingClient(true);
    setError(null);

    const redirectList = newRedirectUris.split(',').map((u) => u.trim()).filter(Boolean);
    const cidrList = newAllowedCidrs.split(',').map((c) => c.trim()).filter(Boolean);

    try {
      await api.createClient({
        client_id: newClientId,
        name: newClientName,
        redirect_uris: redirectList,
        allowed_cidrs: cidrList.length ? cidrList : undefined,
      });

      setShowAddClient(false);
      setNewClientId('');
      setNewClientName('');
      setNewRedirectUris('');
      setNewAllowedCidrs('');
      await fetchData();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to register client application.');
      }
    } finally {
      setSubmittingClient(false);
    }
  };

  const handleLogout = async () => {
    await api.logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Top Navigation */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 bg-indigo-700 text-white rounded-lg flex items-center justify-center font-bold text-sm">
                SSO
              </div>
              <div>
                <span className="font-bold text-slate-900 text-base">Mini SSO</span>
                <span className="ml-2 text-xs px-2 py-0.5 bg-indigo-100 text-indigo-800 rounded font-semibold">
                  Admin Console
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <Link
                to="/account"
                className="text-xs text-slate-600 hover:text-slate-900 font-medium px-3 py-1.5 rounded-lg hover:bg-slate-100 transition"
              >
                User Profile
              </Link>
              <button
                onClick={handleLogout}
                className="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium px-3 py-1.5 rounded-lg transition"
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Notification */}
        {error && (
          <div role="alert" className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm flex justify-between items-center">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-red-500 font-bold ml-4">✕</button>
          </div>
        )}

        {/* Security & Cryptographic Operations Bar */}
        <div className="mb-6 bg-white p-4 rounded-2xl border border-slate-200 shadow-sm flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Security Controls:
            </span>
            <button
              onClick={handleVerifyAuditChain}
              disabled={verifyingAudit}
              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold flex items-center shadow-sm disabled:opacity-50 transition"
            >
              <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              {verifyingAudit ? 'Verifying Hashes...' : 'Verify Audit Hash Chain'}
            </button>

            <button
              onClick={handleRotateKey}
              disabled={rotatingKey}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center shadow-sm disabled:opacity-50 transition"
            >
              <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {rotatingKey ? 'Rotating Key...' : 'Rotate RSA Signing Key'}
            </button>

            <button
              onClick={handleMaintenanceCleanup}
              disabled={cleaningUp}
              className="px-3 py-1.5 bg-slate-700 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold flex items-center shadow-sm disabled:opacity-50 transition"
            >
              <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              {cleaningUp ? 'Sweeping...' : 'Sweep Expired Records'}
            </button>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={fetchData}
              className="px-3 py-1.5 border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 rounded-lg text-xs font-semibold flex items-center transition"
            >
              Refresh
            </button>
            {tab === 'clients' && (
              <button
                onClick={() => setShowAddClient(true)}
                className="px-3 py-1.5 bg-blue-700 hover:bg-blue-800 text-white rounded-lg text-xs font-semibold transition"
              >
                + Register Client App
              </button>
            )}
          </div>
        </div>

        {/* Verification Result Banner */}
        {verification && (
          <div className={`mb-6 p-4 rounded-2xl border flex items-start justify-between shadow-sm ${verification.valid ? 'bg-emerald-50 border-emerald-300 text-emerald-900' : 'bg-red-50 border-red-300 text-red-900'}`}>
            <div className="flex items-start space-x-3">
              <span className="text-2xl">{verification.valid ? '🛡️' : '⚠️'}</span>
              <div>
                <h3 className="font-bold text-sm">
                  {verification.valid ? 'Cryptographic Integrity Verified' : 'Cryptographic Tampering Detected!'}
                </h3>
                <p className="text-xs mt-0.5">{verification.message || verification.reason}</p>
                {verification.latest_hash && (
                  <p className="text-[11px] font-mono mt-1 text-slate-600 truncate max-w-2xl">
                    Latest SHA-256 Chain Hash: {verification.latest_hash}
                  </p>
                )}
                {verification.tampered_id && (
                  <p className="text-xs font-bold text-red-700 mt-1">
                    Tampered Record ID: #{verification.tampered_id}
                  </p>
                )}
              </div>
            </div>
            <button onClick={() => setVerification(null)} className="text-slate-400 hover:text-slate-600">✕</button>
          </div>
        )}

        {/* Key Rotation Result Banner */}
        {keyRotation && (
          <div className="mb-6 p-4 rounded-2xl border bg-blue-50 border-blue-200 text-blue-900 flex items-start justify-between shadow-sm">
            <div>
              <h3 className="font-bold text-sm">{keyRotation.message}</h3>
              <p className="text-xs font-mono mt-1">New Kid: {keyRotation.new_kid} | Retired Kid: {keyRotation.previous_kid || 'None'}</p>
            </div>
            <button onClick={() => setKeyRotation(null)} className="text-blue-400 hover:text-blue-600">✕</button>
          </div>
        )}

        {/* Maintenance Cleanup Result Banner */}
        {cleanup && (
          <div className="mb-6 p-4 rounded-2xl border bg-slate-100 border-slate-300 text-slate-800 flex items-start justify-between shadow-sm">
            <div>
              <h3 className="font-bold text-sm">{cleanup.message}</h3>
              <p className="text-xs mt-1">Purged Auth Codes: {cleanup.purged_codes} | Purged Expired Sessions: {cleanup.purged_sessions}</p>
            </div>
            <button onClick={() => setCleanup(null)} className="text-slate-400 hover:text-slate-600">✕</button>
          </div>
        )}

        {/* Tab Controls */}
        <div className="flex justify-between items-center mb-6">
          <div className="flex space-x-1 bg-slate-200/70 p-1 rounded-xl">
            <button
              onClick={() => setTab('audit')}
              className={`px-4 py-2 text-xs font-semibold rounded-lg transition ${tab === 'audit' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Sign-in Audit Log ({auditLogs.length})
            </button>
            <button
              onClick={() => setTab('clients')}
              className={`px-4 py-2 text-xs font-semibold rounded-lg transition ${tab === 'clients' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Registered Clients ({clients.length})
            </button>
          </div>
        </div>

        {/* Audit Log View */}
        {tab === 'audit' && (
          <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-4 border-b border-slate-100 flex justify-between items-center">
              <div>
                <h2 className="text-base font-bold text-slate-900">Authentication & Security Audit Events</h2>
                <p className="text-xs text-slate-500">Cryptographically chained SHA-256 hash log of all authentication and authorization actions</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
                <thead className="bg-slate-50 text-slate-500 font-semibold uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Timestamp (UTC)</th>
                    <th className="py-3 px-4">Event</th>
                    <th className="py-3 px-4">Outcome</th>
                    <th className="py-3 px-4">User ID</th>
                    <th className="py-3 px-4">Client ID</th>
                    <th className="py-3 px-4">IP Address</th>
                    <th className="py-3 px-4">Chain Hash</th>
                    <th className="py-3 px-4">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-slate-700 font-normal">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-slate-400">
                        {loading ? 'Loading audit records...' : 'No audit events recorded yet.'}
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-50/80 transition">
                        <td className="py-3 px-4 font-mono text-[11px] whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-800">
                          {log.event}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded-full font-bold text-[10px] uppercase tracking-wide ${
                              log.outcome === 'success'
                                ? 'bg-green-100 text-green-800'
                                : log.outcome === 'blocked'
                                ? 'bg-amber-100 text-amber-800'
                                : 'bg-red-100 text-red-800'
                            }`}
                          >
                            {log.outcome}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-500">
                          {log.user_id ? log.user_id.slice(0, 8) + '...' : '-'}
                        </td>
                        <td className="py-3 px-4 font-medium text-slate-600">
                          {log.client_id || '-'}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-500">
                          {log.ip || '-'}
                        </td>
                        <td className="py-3 px-4 font-mono text-[10px] text-slate-400" title={log.entry_hash || ''}>
                          {log.entry_hash ? `${log.entry_hash.slice(0, 8)}...` : '-'}
                        </td>
                        <td className="py-3 px-4 text-slate-500 max-w-xs truncate" title={log.details || ''}>
                          {log.details || '-'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Registered Clients View */}
        {tab === 'clients' && (
          <div className="space-y-6">
            {/* Modal for Registering a New Client */}
            {showAddClient && (
              <div className="bg-white p-6 rounded-2xl border border-blue-200 shadow-md">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-sm font-bold text-slate-900">Register New OpenID Connect Client</h3>
                  <button onClick={() => setShowAddClient(false)} className="text-slate-400 hover:text-slate-600">✕</button>
                </div>
                <form onSubmit={handleCreateClient} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Client ID</label>
                    <input
                      type="text"
                      required
                      value={newClientId}
                      onChange={(e) => setNewClientId(e.target.value)}
                      placeholder="e.g. mobile-app, internal-portal"
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Application Name</label>
                    <input
                      type="text"
                      required
                      value={newClientName}
                      onChange={(e) => setNewClientName(e.target.value)}
                      placeholder="e.g. Internal Portal App"
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Exact Redirect URIs (Comma separated)
                    </label>
                    <input
                      type="text"
                      required
                      value={newRedirectUris}
                      onChange={(e) => setNewRedirectUris(e.target.value)}
                      placeholder="http://localhost:5174/callback, https://app.example.com/callback"
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-500"
                    />
                    <p className="text-[11px] text-slate-500 mt-1">Exact match enforced by OIDC spec to stop token interception.</p>
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Allowed IP CIDRs (Optional, comma separated)
                    </label>
                    <input
                      type="text"
                      value={newAllowedCidrs}
                      onChange={(e) => setNewAllowedCidrs(e.target.value)}
                      placeholder="e.g. 192.168.1.0/24, 10.0.0.0/8 (Leave empty for unrestricted)"
                      className="w-full px-3 py-2 text-xs rounded-lg border border-slate-300 focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div className="md:col-span-2 flex justify-end space-x-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowAddClient(false)}
                      className="px-3 py-2 text-xs text-slate-600 hover:text-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={submittingClient}
                      className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white rounded-lg text-xs font-semibold disabled:opacity-50"
                    >
                      {submittingClient ? 'Registering...' : 'Register Client'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {clients.map((c) => (
                <div key={c.id} className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="font-bold text-slate-900 text-sm">{c.name}</h3>
                      <span className="font-mono text-xs text-blue-700 font-semibold">{c.client_id}</span>
                    </div>
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-mono">
                      PKCE S256
                    </span>
                  </div>

                  <div>
                    <span className="text-xs font-semibold text-slate-500 block mb-1">Registered Redirect URIs:</span>
                    <ul className="space-y-1">
                      {c.redirect_uris.map((uri, idx) => (
                        <li key={idx} className="text-xs font-mono bg-slate-50 p-1.5 rounded border border-slate-100 text-slate-700 break-all">
                          {uri}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {c.allowed_cidrs && c.allowed_cidrs.length > 0 && (
                    <div>
                      <span className="text-xs font-semibold text-slate-500 block mb-1">IP CIDR Allowlist:</span>
                      <div className="flex flex-wrap gap-1">
                        {c.allowed_cidrs.map((cidr, idx) => (
                          <span key={idx} className="text-[11px] font-mono px-2 py-0.5 bg-amber-50 border border-amber-200 text-amber-800 rounded">
                            {cidr}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="text-[10px] text-slate-400 border-t border-slate-100 pt-3">
                    Created: {new Date(c.created_at).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
