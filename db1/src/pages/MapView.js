import React, { useState, useEffect } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker
} from 'react-simple-maps';
import { api } from '../api';
import './Pages.css';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

function MapView() {
  const [mapData, setMapData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedPoint, setSelectedPoint] = useState(null);

  useEffect(() => {
    loadMapData();
    const interval = setInterval(loadMapData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadMapData = async () => {
    try {
      setLoading(true);
      const data = await api.getMapData();
      setMapData(data);
    } catch (error) {
      console.error('Error loading map data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading || !mapData) {
    return <div className="page-container"><div className="loading">Loading map data...</div></div>;
  }

  const getMarkerColor = (score) => {
    if (score >= 0.8) return '#ef4444';
    if (score >= 0.6) return '#f97316';
    if (score >= 0.4) return '#eab308';
    return '#22c55e';
  };

  const getMarkerSize = (count) => {
    return Math.min(Math.max(count / 10, 3), 15);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Attack Map</h1>
        <button onClick={loadMapData} className="refresh-btn">Refresh</button>
      </div>

      <div className="map-container">
        <ComposableMap
          projectionConfig={{ scale: 147 }}
          style={{ width: '100%', height: '100%' }}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#2d3748"
                  stroke="#4a5568"
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: '#4a5568', outline: 'none' },
                    pressed: { outline: 'none' }
                  }}
                />
              ))
            }
          </Geographies>
          {mapData.points.map((point, index) => (
            <Marker
              key={index}
              coordinates={[point.lng, point.lat]}
              onClick={() => setSelectedPoint(point)}
            >
              <circle
                r={getMarkerSize(point.attack_count)}
                fill={getMarkerColor(point.avg_score)}
                stroke="#fff"
                strokeWidth={1}
                opacity={0.7}
                style={{ cursor: 'pointer' }}
              />
            </Marker>
          ))}
        </ComposableMap>

        {selectedPoint && (
          <div style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: '#1a202c',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid #2d3748',
            minWidth: '250px'
          }}>
            <h3 style={{ margin: '0 0 12px 0', color: '#f7fafc' }}>Attack Details</h3>
            <div style={{ color: '#a0aec0', fontSize: '13px', lineHeight: '1.6' }}>
              <div><strong>IP:</strong> <span style={{ fontFamily: 'monospace', color: '#4299e1' }}>{selectedPoint.ip}</span></div>
              <div><strong>Location:</strong> {selectedPoint.city}, {selectedPoint.country}</div>
              <div><strong>Attacks:</strong> {selectedPoint.attack_count}</div>
              <div><strong>Avg Score:</strong> <span style={{ color: getMarkerColor(selectedPoint.avg_score) }}>{selectedPoint.avg_score.toFixed(4)}</span></div>
            </div>
            <button
              onClick={() => setSelectedPoint(null)}
              style={{
                marginTop: '12px',
                padding: '6px 12px',
                background: '#4299e1',
                border: 'none',
                borderRadius: '4px',
                color: 'white',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              Close
            </button>
          </div>
        )}
      </div>

      <div className="stats-grid" style={{ marginTop: '20px' }}>
        {mapData.country_stats.slice(0, 10).map((country, index) => (
          <div key={index} className="stat-card">
            <h3>{country.country}</h3>
            <div className="value" style={{ color: '#4299e1' }}>{country.count.toLocaleString()}</div>
            <div style={{ color: '#a0aec0', fontSize: '12px', marginTop: '4px' }}>
              Avg Score: {country.avg_score.toFixed(4)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default MapView;

