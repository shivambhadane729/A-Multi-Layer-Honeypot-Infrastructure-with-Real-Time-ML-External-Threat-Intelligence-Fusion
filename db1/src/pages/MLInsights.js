import React, { useState, useEffect } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { api } from '../api';
import './Pages.css';

function MLInsights() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadInsights();
    const interval = setInterval(loadInsights, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadInsights = async () => {
    try {
      setLoading(true);
      const insights = await api.getMLInsights();
      setData(insights);
    } catch (error) {
      console.error('Error loading ML insights:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !data) {
    return <div className="page-container"><div className="loading">Loading ML insights...</div></div>;
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
        <h1>ML Insights</h1>
        <button onClick={loadInsights} className="refresh-btn">Refresh</button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Average Anomaly Score</h3>
          <div className="value" style={{ color: '#eab308' }}>{data.avg_anomaly_score.toFixed(4)}</div>
        </div>
        <div className="stat-card">
          <h3>Total Anomalies</h3>
          <div className="value" style={{ color: '#ef4444' }}>{data.total_anomalies.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <h3>High-Score IPs</h3>
          <div className="value" style={{ color: '#f97316' }}>{data.high_score_ips.length}</div>
        </div>
      </div>

      <div className="chart-container">
        <div className="chart-title">Anomaly Score Trend (24h)</div>
        <Line
          data={{
            labels: data.anomaly_trend.map(t => new Date(t.time).toLocaleTimeString()),
            datasets: [{
              label: 'Average Score',
              data: data.anomaly_trend.map(t => t.avg_score),
              borderColor: '#eab308',
              backgroundColor: 'rgba(234, 179, 8, 0.1)',
              tension: 0.4,
              fill: true
            }, {
              label: 'Attack Count',
              data: data.anomaly_trend.map(t => t.count),
              borderColor: '#ef4444',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              tension: 0.4,
              fill: true,
              yAxisID: 'y1'
            }]
          }}
          options={{
            ...chartOptions,
            scales: {
              ...chartOptions.scales,
              y1: {
                type: 'linear',
                display: true,
                position: 'right',
                grid: { drawOnChartArea: false },
                ticks: { color: '#a0aec0' }
              }
            }
          }}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div className="chart-container">
          <div className="chart-title">High-Score IPs (Score ≥ 0.8)</div>
          <Bar
            data={{
              labels: data.high_score_ips.map(ip => ip.ip.substring(0, 15) + '...'),
              datasets: [{
                label: 'Average Score',
                data: data.high_score_ips.map(ip => ip.avg_score),
                backgroundColor: '#ef4444'
              }]
            }}
            options={chartOptions}
          />
        </div>

        <div className="chart-container">
          <div className="chart-title">Risk Level Distribution</div>
          <Doughnut
            data={{
              labels: data.risk_distribution.map(r => r.risk_level),
              datasets: [{
                data: data.risk_distribution.map(r => r.count),
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e']
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

      <div className="chart-container">
        <div className="chart-title">Top High-Score IPs Details</div>
        <table className="events-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Average Score</th>
              <th>Attack Count</th>
            </tr>
          </thead>
          <tbody>
            {data.high_score_ips.map((ip, index) => (
              <tr key={index}>
                <td className="ip-cell">{ip.ip}</td>
                <td>
                  <span style={{ color: ip.avg_score >= 0.8 ? '#ef4444' : '#f97316' }}>
                    {ip.avg_score.toFixed(4)}
                  </span>
                </td>
                <td>{ip.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default MLInsights;

