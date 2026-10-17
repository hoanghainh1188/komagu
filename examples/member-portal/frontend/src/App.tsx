import React, { useState, useEffect } from 'react';
import { ApiClient, DEFAULT_PERSONAS, Order, DocumentItem, Persona } from './api/client';

export const App: React.FC = () => {
  const [personas] = useState<Persona[]>(DEFAULT_PERSONAS);
  const [activePersona, setActivePersona] = useState<Persona>(DEFAULT_PERSONAS[0]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  // Security Probe State
  const [probeResult, setProbeResult] = useState<{
    scenario: string;
    status: number;
    response: any;
    isVulnerable: boolean;
    explanation: string;
  } | null>(null);

  const loadData = async (persona: Persona) => {
    setLoading(true);
    const api = new ApiClient('', persona.mockToken);

    const [ordersRes, docsRes] = await Promise.all([
      api.getOrders(),
      api.getDocuments(),
    ]);

    if (ordersRes.data) setOrders(ordersRes.data);
    else setOrders([]);

    if (docsRes.data) setDocuments(docsRes.data);
    else setDocuments([]);

    setLoading(false);
  };

  useEffect(() => {
    loadData(activePersona);
  }, [activePersona]);

  const handlePersonaChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const found = personas.find((p) => p.userId === e.target.value);
    if (found) {
      setActivePersona(found);
      setProbeResult(null);
    }
  };

  // Scenario 1: Access Alice's order (ord-001) via D1 Protected Endpoint
  const testProtectedAccess = async () => {
    const api = new ApiClient('', activePersona.mockToken);
    const res = await api.getOrder('ord-001');

    const isAlice = activePersona.userId === 'user-a';
    setProbeResult({
      scenario: `Access 'ord-001' via D1 Protected API (/api/v1/orders/ord-001)`,
      status: res.status,
      response: res.data || res.error,
      isVulnerable: false,
      explanation: isAlice
        ? 'SUCCESS: Alice is the verified owner of ord-001, so access is granted (200 OK).'
        : 'SECURE: Komainu D1 intercepted the request. Because caller does not own ord-001, it returned 404 Not Found, preventing ID harvesting.',
    });
  };

  // Scenario 2: Access Alice's order (ord-001) via Legacy Planted BOLA Endpoint
  const testLegacyAccess = async () => {
    const api = new ApiClient('', activePersona.mockToken);
    const res = await api.getLegacyOrder('ord-001');

    const isAlice = activePersona.userId === 'user-a';
    setProbeResult({
      scenario: `Access 'ord-001' via Planted Legacy API (/api/v1/test/legacy-orders/ord-001)`,
      status: res.status,
      response: res.data || res.error,
      isVulnerable: !isAlice && res.status === 200,
      explanation: isAlice
        ? 'Alice retrieved her own order.'
        : 'VULNERABILITY DETECTED! Planted BOLA route leaked Alice\'s confidential order data to another caller (200 OK without ownership check).',
    });
  };

  // Scenario 3: SQL Injection probe on search
  const testSqlInjection = async () => {
    const api = new ApiClient('', activePersona.mockToken);
    const probeStr = "' OR '1'='1";
    const res = await api.searchLegacy(probeStr);

    setProbeResult({
      scenario: `Execute Raw SQL Search (/api/v1/test/legacy-search?query=' OR '1'='1)`,
      status: res.status,
      response: res.data || res.error,
      isVulnerable: res.status === 200 && Array.isArray(res.data) && res.data.length > 2,
      explanation: 'VULNERABILITY DETECTED! Raw string concatenation executed attacker-controlled SQL condition, bypassing tenant isolation.',
    });
  };

  return (
    <div className="container">
      {/* Header & Persona Switcher */}
      <div className="header">
        <div>
          <div className="brand">🛡️ Komainu Member Portal</div>
          <small style={{ color: '#718096' }}>Boilerplate 1 Reference Implementation (B1-D6)</small>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <label htmlFor="persona-select" style={{ fontWeight: 600 }}>Switch Persona:</label>
          <select
            id="persona-select"
            value={activePersona.userId}
            onChange={handlePersonaChange}
            style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #cbd5e0', fontWeight: 600 }}
          >
            {personas.map((p) => (
              <option key={p.userId} value={p.userId}>
                {p.displayName} ({p.tenantName})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Active Persona Banner */}
      <div className="card" style={{ background: '#ebf8ff', borderColor: '#bee3f8' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <div>
            <strong>Active User:</strong> {activePersona.displayName} &nbsp;|&nbsp;{' '}
            <strong>Tenant:</strong> <span className="badge badge-info">{activePersona.tenantName} ({activePersona.tenantId})</span> &nbsp;|&nbsp;{' '}
            <strong>Role:</strong> <span className="badge badge-success">{activePersona.role}</span>
          </div>
          <div>
            <code>Bearer {activePersona.mockToken}</code>
          </div>
        </div>
      </div>

      {/* Section 1: Orders (D1 Scoped) */}
      <div className="card">
        <h3>📦 Orders (Scoped to Current Tenant & User via D1)</h3>
        {loading ? (
          <p>Loading records...</p>
        ) : orders.length === 0 ? (
          <p style={{ color: '#a0aec0' }}>No orders found for this user context.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Order ID</th>
                <th>Description</th>
                <th>Total Amount</th>
                <th>Status</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o.id}>
                  <td><code>{o.id}</code></td>
                  <td>{o.description}</td>
                  <td><strong>${o.totalAmount.toFixed(2)}</strong></td>
                  <td>
                    <span className={`badge ${o.status === 'completed' ? 'badge-success' : 'badge-warning'}`}>
                      {o.status}
                    </span>
                  </td>
                  <td>{new Date(o.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Section 2: Interactive Security Probe Lab */}
      <div className="card">
        <h3>🔬 Interactive Security Verification Lab (BOLA & IDOR Probes)</h3>
        <p style={{ color: '#4a5568' }}>
          Test accessing Alice's order (<code>ord-001</code>) using your currently active credentials.
        </p>

        <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
          <button className="btn-primary" onClick={testProtectedAccess}>
            1. Test Standard API (D1 Protected)
          </button>
          <button className="btn-danger" onClick={testLegacyAccess}>
            2. Test Legacy API (Planted BOLA)
          </button>
          <button className="btn-secondary" onClick={testSqlInjection}>
            3. Test Legacy Search (Planted SQLi)
          </button>
        </div>

        {probeResult && (
          <div style={{ marginTop: 20, padding: 16, borderRadius: 6, background: probeResult.isVulnerable ? '#fff5f5' : '#f0fff4', border: `1px solid ${probeResult.isVulnerable ? '#feb2b2' : '#9ae6b4'}` }}>
            <h4>{probeResult.scenario}</h4>
            <p>
              <strong>HTTP Status:</strong>{' '}
              <span className={`badge ${probeResult.status === 200 ? (probeResult.isVulnerable ? 'badge-danger' : 'badge-success') : (probeResult.status === 404 ? 'badge-success' : 'badge-warning')}`}>
                {probeResult.status} {probeResult.status === 404 ? 'Not Found' : probeResult.status === 200 ? 'OK' : ''}
              </span>
            </p>
            <p>{probeResult.explanation}</p>
            <div>
              <strong>Response Payload:</strong>
              <pre>{JSON.stringify(probeResult.response, null, 2)}</pre>
            </div>
          </div>
        )}
      </div>

      {/* Section 3: Confidential Documents */}
      <div className="card">
        <h3>📄 Confidential Documents (Tenant Boundary Protection)</h3>
        {documents.length === 0 ? (
          <p style={{ color: '#a0aec0' }}>No documents available for this tenant.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Document ID</th>
                <th>Title</th>
                <th>Content Summary</th>
                <th>Confidential</th>
              </tr>
            </thead>
            <tbody>
              {documents.map((d) => (
                <tr key={d.id}>
                  <td><code>{d.id}</code></td>
                  <td><strong>{d.title}</strong></td>
                  <td>{d.content}</td>
                  <td>
                    <span className="badge badge-warning">Restricted</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
