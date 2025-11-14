import React, { useState, useEffect } from 'react';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { api } from '../api';
import './Pages.css';

function Analytics() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAnalytics();
    const interval = setInterval(loadAnalytics, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAnalytics = async () => {
    try {
      setLoading(true);
      const analytics = await api.getAnalytics();
      setData(analytics);
    } catch (error) {
      console.error('Error loading analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !data) {
    return <div className="page-container"><div className="loading">Loading analytics...</div></div>;
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#a0aec0', font: { size: 10 } }
      }
    },
    scales: {
      x: { grid: { color: '#4a5568' }, ticks: { color: '#a0aec0' } },
      y: { grid: { color: '#4a5568' }, ticks: { color: '#a0aec0' } }
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Analytics</h1>
        <button onClick={loadAnalytics} className="refresh-btn">Refresh</button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Attacks</h3>
          <div className="value" style={{ color: '#ef4444' }}>{data.total_attacks.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <h3>High-Risk Attacks</h3>
          <div className="value" style={{ color: '#f97316' }}>{data.high_risk_attacks.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <h3>Unique IPs</h3>
          <div className="value" style={{ color: '#4299e1' }}>{data.unique_ips.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <h3>Avg ML Score</h3>
          <div className="value" style={{ color: '#eab308' }}>{data.avg_ml_score.toFixed(4)}</div>
        </div>
      </div>

      <div className="chart-container">
        <div className="chart-title">Attacks Over Time (24h)</div>
        <Line
          data={{
            labels: data.time_series.map(t => new Date(t.time).toLocaleTimeString()),
            datasets: [{
              label: 'Attacks',
              data: data.time_series.map(t => t.count),
              borderColor: '#4299e1',
              backgroundColor: 'rgba(66, 153, 225, 0.1)',
              tension: 0.4,
              fill: true
            }]
          }}
          options={chartOptions}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div className="chart-container">
          <div className="chart-title">Top Countries</div>
          <Bar
            data={{
              labels: data.top_countries.map(c => c.country),
              datasets: [{
                label: 'Attacks',
                data: data.top_countries.map(c => c.count),
                backgroundColor: '#4299e1'
              }]
            }}
            options={chartOptions}
          />
        </div>

        <div className="chart-container">
          <div className="chart-title">Top IPs</div>
          <Bar
            data={{
              labels: data.top_ips.map(ip => ip.ip.substring(0, 15) + '...'),
              datasets: [{
                label: 'Attacks',
                data: data.top_ips.map(ip => ip.count),
                backgroundColor: '#ef4444'
              }]
            }}
            options={chartOptions}
          />
        </div>
      </div>

      <div className="chart-container">
        <div className="chart-title">Top Protocols</div>
        <Doughnut
          data={{
            labels: data.top_ports.map(p => p.port),
            datasets: [{
              data: data.top_ports.map(p => p.count),
              backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#4299e1', '#8b5cf6']
            }]
          }}
          options={{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { labels: { color: '#a0aec0' }, position: 'bottom' }
            }
          }}
        />
      </div>
    </div>
  );
}

export default Analytics;

