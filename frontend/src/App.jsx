import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  BarChart3, 
  Share2, 
  BrainCircuit, 
  CheckCircle,
  Radio,
  Server
} from 'lucide-react';
import DashboardPage from './pages/DashboardPage.jsx';
import MetricsPage from './pages/MetricsPage.jsx';
import GraphPage from './pages/GraphPage.jsx';
import ExplainabilityPage from './pages/ExplainabilityPage.jsx';
import { getAlerts, checkBackendHealth, isBackendOnline } from './services/apiClient.js';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alertsCount, setAlertsCount] = useState(0);
  const [backendStatus, setBackendStatus] = useState(false);

  useEffect(() => {
    const updateState = async () => {
      const isOnline = await checkBackendHealth();
      setBackendStatus(isOnline);
      const list = await getAlerts();
      if (Array.isArray(list)) {
        setAlertsCount(list.length);
      }
    };

    updateState();
    const interval = setInterval(updateState, 3500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '2.5rem', padding: '0 0.5rem' }}>
          <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'linear-gradient(135deg, #6366f1 0%, #4338ca 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 12px rgba(99,102,241,0.4)' }}>
            <ShieldAlert size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.15rem', letterSpacing: '-0.02em' }} className="gradient-text">
              AegisGraph
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 500 }}>
              GNN Intrusion Detection
            </div>
          </div>
        </div>

        {/* Nav Links */}
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
          <button 
            className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <LayoutDashboard size={19} />
            <span>Overview</span>
          </button>

          <button 
            className={`nav-btn ${activeTab === 'metrics' ? 'active' : ''}`}
            onClick={() => setActiveTab('metrics')}
          >
            <BarChart3 size={19} />
            <span>Metrics & Models</span>
          </button>

          <button 
            className={`nav-btn ${activeTab === 'graph' ? 'active' : ''}`}
            onClick={() => setActiveTab('graph')}
          >
            <Share2 size={19} />
            <span>Graph Viewer</span>
          </button>

          <button 
            className={`nav-btn ${activeTab === 'explain' ? 'active' : ''}`}
            onClick={() => setActiveTab('explain')}
            style={{ position: 'relative' }}
          >
            <BrainCircuit size={19} />
            <span>Explainability</span>
            {alertsCount > 0 && (
              <span style={{ 
                marginLeft: 'auto', 
                background: '#ef4444', 
                color: '#fff', 
                borderRadius: '9999px', 
                padding: '0.1rem 0.45rem', 
                fontSize: '0.7rem', 
                fontWeight: 700 
              }}>
                {alertsCount}
              </span>
            )}
          </button>
        </nav>

        {/* Mode Indicator & Project info footer */}
        <div style={{ paddingTop: '1.25rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <div style={{ 
            marginBottom: '0.85rem', 
            padding: '0.45rem 0.6rem', 
            borderRadius: '6px', 
            background: backendStatus ? 'rgba(16, 185, 129, 0.1)' : 'rgba(99, 102, 241, 0.12)', 
            border: `1px solid ${backendStatus ? 'rgba(16, 185, 129, 0.25)' : 'rgba(99, 102, 241, 0.25)'}`,
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: backendStatus ? '#10b981' : '#818cf8',
              boxShadow: backendStatus ? '0 0 8px #10b981' : '0 0 8px #818cf8'
            }} />
            <span style={{ fontSize: '0.72rem', fontWeight: 600, color: backendStatus ? '#34d399' : '#c7d2fe' }}>
              {backendStatus ? 'Live FastAPI Backend' : 'Cloud Interactive Demo'}
            </span>
          </div>

          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.2rem' }}>
            Computer Networks Final
          </div>
          <div>Vishwakarma University</div>
          <div style={{ marginTop: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#34d399' }}>
            <CheckCircle size={13} />
            <span>5,000 Contiguous Flows</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'dashboard' && <DashboardPage setActiveTab={setActiveTab} />}
        {activeTab === 'metrics' && <MetricsPage />}
        {activeTab === 'graph' && <GraphPage />}
        {activeTab === 'explain' && <ExplainabilityPage />}
      </main>
    </div>
  );
}
