import React, { useState, useEffect } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, PointElement, ArcElement, Title, Tooltip, Legend } from 'chart.js';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { api } from '../api';
import '../App.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

function Dashboard() {
  // ✅ Provide default object to prevent null access
  const [stats, setStats] = useState({
    total_logs: 0,
    unique_ips: 0,
    recent_activity_24h: 0,
    top_services: [],
    top_actions: [],
    top_countries: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    checkConnection();
    loadStats();
    const interval = setInterval(() => {
      checkConnection();
      loadStats();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const checkConnection = async () => {
    const connected = await api.checkHealth();
    setIsConnected(connected);
  };

  const loadStats = async () => {
    try {
      setError(null);
      const data = await api.getStats();
      // ✅ Defensive check in case backend returns empty object
      setStats(data?.statistics || {
        total_logs: 0,
        unique_ips: 0,
        recent_activity_24h: 0,
        top_services: [],
        top_actions: [],
        top_countries: []
      });
      setIsConnected(true);
    } catch (error) {
      console.error('Error loading stats:', error);
      setError(error.message);
      setIsConnected(false);
    } finally {
      setLoading(false);
    }
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#a0aec0',
          font: { size: 10 }
        }
      }
    },
    scales: {
      x: {
        grid: { color: '#4a5568' },
        ticks: { color: '#a0aec0', font: { size: 10 } }
      },
      y: {
        grid: { color: '#4a5568' },
        ticks: { color: '#a0aec0', font: { size: 10 } }
      }
    }
  };

  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#a0aec0',
          font: { size: 10 },
          padding: 15
        }
      }
    }
  };

  // ✅ If still loading
  if (loading) {
    return <div className="App"><div className="loading">Loading dashboard...</div></div>;
  }

  // ✅ Connection status badge
  const connectionStatus = (
    <div style={{
      position: 'fixed',
      top: '60px',
      right: '20px',
      padding: '8px 16px',
      background: isConnected ? '#22c55e' : '#ef4444',
      color: 'white',
      borderRadius: '4px',
      fontSize: '12px',
      zIndex: 1000,
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    }}>
      <span>{isConnected ? '🟢' : '🔴'}</span>
      <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
    </div>
  );

  // ✅ Use optional chaining & default fallbacks
  const honeypotBarData = {
    labels: stats?.top_services?.map(s => s.service) || [],
    datasets: [{
      label: 'Attacks',
      data: stats?.top_services?.map(s => s.count) || [],
      backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6']
    }]
  };

  const protocolBarData = {
    labels: stats?.top_actions?.slice(0, 6).map(a => a.action) || [],
    datasets: [{
      label: 'Attacks',
      data: stats?.top_actions?.slice(0, 6).map(a => a.count) || [],
      backgroundColor: ['#ef4444', '#3b82f6', '#22c55e', '#8b5cf6', '#eab308', '#f97316']
    }]
  };

  const countryPieData = {
    labels: stats?.top_countries?.slice(0, 10).map(c => c.country) || [],
    datasets: [{
      data: stats?.top_countries?.slice(0, 10).map(c => c.count) || [],
      backgroundColor: ['#8b5cf6', '#ec4899', '#22c55e', '#eab308', '#3b82f6', '#ef4444', '#f97316', '#06b6d4', '#f43f5e', '#10b981']
    }]
  };

  return (
    <div className="App">
      {connectionStatus}
      {error && (
        <div style={{
          background: '#7f1d1d',
          border: '1px solid #ef4444',
          color: '#fca5a5',
          padding: '16px',
          margin: '16px',
          borderRadius: '8px',
          textAlign: 'center'
        }}>
          <strong>⚠️ Backend Connection Error:</strong> {error}
        </div>
      )}

      <div className="main-content">
        <div className="grid-container">
          <div className="kibana-panel grid-3">
            <div className="kibana-panel-header">Total Attacks</div>
            <div className="kibana-panel-content">
              <div className="kibana-metric">
                <div className="kibana-metric-value" style={{ color: '#ef4444' }}>
                  {stats.total_logs?.toLocaleString() || 0}
                </div>
                <div className="kibana-metric-label">All Events Captured</div>
              </div>
            </div>
          </div>

          <div className="kibana-panel grid-3">
            <div className="kibana-panel-header">Unique Attacker IPs</div>
            <div className="kibana-panel-content">
              <div className="kibana-metric">
                <div className="kibana-metric-value" style={{ color: '#eab308' }}>
                  {stats.unique_ips?.toLocaleString() || 0}
                </div>
                <div className="kibana-metric-label">Distinct Sources</div>
              </div>
            </div>
          </div>

          <div className="kibana-panel grid-3">
            <div className="kibana-panel-header">Recent Activity (24h)</div>
            <div className="kibana-panel-content">
              <div className="kibana-metric">
                <div className="kibana-metric-value" style={{ color: '#22c55e' }}>
                  {stats.recent_activity_24h?.toLocaleString() || 0}
                </div>
                <div className="kibana-metric-label">Last 24 Hours</div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid-container">
          <div className="kibana-panel grid-4">
            <div className="kibana-panel-header">Attacks by Service</div>
            <div className="kibana-panel-content">
              <div className="chart-container">
                <Bar data={honeypotBarData} options={{
                  ...chartOptions,
                  indexAxis: 'y',
                  plugins: { legend: { display: false } }
                }} />
              </div>
            </div>
          </div>

          <div className="kibana-panel grid-4">
            <div className="kibana-panel-header">Attack Protocols</div>
            <div className="kibana-panel-content">
              <div className="chart-container">
                <Bar data={protocolBarData} options={{
                  ...chartOptions,
                  plugins: { legend: { display: false } }
                }} />
              </div>
            </div>
          </div>

          <div className="kibana-panel grid-4">
            <div className="kibana-panel-header">Attacks by Country</div>
            <div className="kibana-panel-content">
              <div className="chart-container">
                <Doughnut data={countryPieData} options={pieOptions} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
