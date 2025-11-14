import React, { useState, useEffect } from 'react';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { api } from '../api';
import './Pages.css';

function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [threshold, setThreshold] = useState(0.85);

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, [threshold]);

  useEffect(() => {
    // Show toast notification for new high-risk alerts
    alerts.forEach(alert => {
      if (alert.score >= 0.9) {
        toast.error(`🚨 CRITICAL ALERT: ${alert.source_ip} - Score: ${alert.score.toFixed(4)}`, {
          position: 'top-right',
          autoClose: 5000
        });
      }
    });
  }, [alerts]);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const data = await api.getAlerts(threshold, 50);
      setAlerts(data.alerts || []);
    } catch (error) {
      console.error('Error loading alerts:', error);
      toast.error('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  const getRiskClass = (score) => {
    if (score >= 0.9) return 'critical';
    if (score >= 0.85) return 'high';
    if (score >= 0.75) return 'medium';
    return 'low';
  };

  const getRiskLabel = (score) => {
    if (score >= 0.9) return 'CRITICAL';
    if (score >= 0.85) return 'HIGH';
    if (score >= 0.75) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="page-container">
      <ToastContainer theme="dark" />
      <div className="page-header">
        <h1>Alerts</h1>
        <div className="filters">
          <input
            type="number"
            placeholder="Threshold..."
            step="0.05"
            min="0"
            max="1"
            value={threshold}
            onChange={(e) => setThreshold(parseFloat(e.target.value) || 0.85)}
            className="filter-input"
          />
          <button onClick={loadAlerts} className="refresh-btn">Refresh</button>
        </div>
      </div>

      {loading && <div className="loading">Loading alerts...</div>}

      <div style={{ marginBottom: '20px', color: '#a0aec0' }}>
        Showing {alerts.length} alerts with score ≥ {threshold.toFixed(2)}
      </div>

      <div>
        {alerts.map((alert) => (
          <div key={alert.id} className={`alert-card ${getRiskClass(alert.score)}`}>
            <div className="alert-header">
              <div>
                <span className="alert-ip">{alert.source_ip}</span>
                <span style={{ marginLeft: '12px', color: '#a0aec0' }}>{alert.country}</span>
              </div>
              <div className="alert-score">{alert.score.toFixed(4)}</div>
            </div>
            <div className="alert-details">
              <div><strong>Risk Level:</strong> {getRiskLabel(alert.score)}</div>
              <div><strong>Time:</strong> {new Date(alert.timestamp).toLocaleString()}</div>
              <div><strong>Action:</strong> {alert.action}</div>
              <div><strong>Service:</strong> {alert.service}</div>
              {alert.target_file && <div><strong>Target:</strong> {alert.target_file}</div>}
            </div>
          </div>
        ))}
        {alerts.length === 0 && !loading && (
          <div className="no-data">No alerts found (threshold: {threshold.toFixed(2)})</div>
        )}
      </div>
    </div>
  );
}

export default Alerts;

