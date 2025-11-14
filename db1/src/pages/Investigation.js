import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Line } from 'react-chartjs-2';
import { api } from '../api';
import './Pages.css';

function Investigation() {
  const { ip } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchIp, setSearchIp] = useState(ip || '');

  useEffect(() => {
    if (ip) {
      loadInvestigation(ip);
    }
  }, [ip]);

  const loadInvestigation = async (targetIp) => {
    try {
      setLoading(true);
      const investigation = await api.investigateIP(targetIp);
      setData(investigation);
    } catch (error) {
      console.error('Error loading investigation:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (searchIp) {
      navigate(`/investigate/${searchIp}`);
    }
  };

  if (loading || !data) {
    return (
      <div className="page-container">
        <div className="page-header">
          <h1>Investigation</h1>
          <div className="filters">
            <input
              type="text"
              placeholder="Enter IP address..."
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              className="filter-input"
            />
            <button onClick={handleSearch} className="refresh-btn">Investigate</button>
          </div>
        </div>
        <div className="loading">Loading investigation data...</div>
      </div>
    );
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
        <h1>Investigation: {data.ip}</h1>
        <div className="filters">
          <input
            type="text"
            placeholder="Enter IP address..."
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            className="filter-input"
          />
          <button onClick={handleSearch} className="refresh-btn">Investigate</button>
        </div>
      </div>

      <div className="investigation-header">
        <h2 style={{ margin: '0 0 20px 0', color: '#f7fafc' }}>IP Information</h2>
        <div style={{ color: '#a0aec0', fontSize: '14px' }}>
          <div><strong>IP Address:</strong> <span style={{ fontFamily: 'monospace', color: '#4299e1' }}>{data.ip}</span></div>
          {data.geo_info.country && (
            <div><strong>Location:</strong> {data.geo_info.city}, {data.geo_info.region}, {data.geo_info.country}</div>
          )}
          {data.geo_info.isp && <div><strong>ISP:</strong> {data.geo_info.isp}</div>}
          {data.stats.first_seen && <div><strong>First Seen:</strong> {new Date(data.stats.first_seen).toLocaleString()}</div>}
          {data.stats.last_seen && <div><strong>Last Seen:</strong> {new Date(data.stats.last_seen).toLocaleString()}</div>}
        </div>

        <div className="investigation-stats">
          <div className="investigation-stat">
            <div className="investigation-stat-label">Total Attacks</div>
            <div className="investigation-stat-value" style={{ color: '#ef4444' }}>
              {data.stats.total_attacks}
            </div>
          </div>
          <div className="investigation-stat">
            <div className="investigation-stat-label">Avg ML Score</div>
            <div className="investigation-stat-value" style={{ color: '#eab308' }}>
              {data.stats.avg_score.toFixed(4)}
            </div>
          </div>
          <div className="investigation-stat">
            <div className="investigation-stat-label">Max ML Score</div>
            <div className="investigation-stat-value" style={{ color: '#f97316' }}>
              {data.stats.max_score.toFixed(4)}
            </div>
          </div>
          <div className="investigation-stat">
            <div className="investigation-stat-label">Unique Actions</div>
            <div className="investigation-stat-value" style={{ color: '#4299e1' }}>
              {data.stats.unique_actions}
            </div>
          </div>
          <div className="investigation-stat">
            <div className="investigation-stat-label">Target Services</div>
            <div className="investigation-stat-value" style={{ color: '#22c55e' }}>
              {data.stats.unique_services}
            </div>
          </div>
        </div>
      </div>

      {data.score_trend.length > 0 && (
        <div className="chart-container">
          <div className="chart-title">ML Score Trend Over Time</div>
          <Line
            data={{
              labels: data.score_trend.map(t => new Date(t.time).toLocaleString()),
              datasets: [{
                label: 'ML Score',
                data: data.score_trend.map(t => t.score),
                borderColor: '#eab308',
                backgroundColor: 'rgba(234, 179, 8, 0.1)',
                tension: 0.4,
                fill: true
              }]
            }}
            options={chartOptions}
          />
        </div>
      )}

      <div className="logs-list">
        <h2 style={{ margin: '0 0 20px 0', color: '#f7fafc' }}>Recent Activity ({data.logs.length} logs)</h2>
        {data.logs.map((log, index) => (
          <div key={index} className="log-item">
            <div className="log-item-header">
              <span className="log-item-time">{new Date(log.created_at).toLocaleString()}</span>
              <span className="log-item-action">{log.action}</span>
            </div>
            <div style={{ color: '#a0aec0', fontSize: '12px', marginTop: '4px' }}>
              <div><strong>Service:</strong> {log.target_service}</div>
              {log.target_file && <div><strong>Target:</strong> {log.target_file}</div>}
              {log.ml_score && (
                <div>
                  <strong>ML Score:</strong>{' '}
                  <span style={{ color: log.ml_score >= 0.8 ? '#ef4444' : '#eab308' }}>
                    {log.ml_score.toFixed(4)}
                  </span>
                </div>
              )}
              {log.user_agent && <div><strong>User Agent:</strong> {log.user_agent}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Investigation;

