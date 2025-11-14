import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import LiveEvents from './pages/LiveEvents';
import Analytics from './pages/Analytics';
import MapView from './pages/MapView';
import MLInsights from './pages/MLInsights';
import Alerts from './pages/Alerts';
import Investigation from './pages/Investigation';
import ConnectionStatus from './components/ConnectionStatus';
import './App.css';

function Navigation() {
  const location = useLocation();
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const menuItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/live-events', label: 'Live Events', icon: '⚡' },
    { path: '/analytics', label: 'Analytics', icon: '📈' },
    { path: '/map', label: 'Map View', icon: '🌍' },
    { path: '/ml-insights', label: 'ML Insights', icon: '🧠' },
    { path: '/alerts', label: 'Alerts', icon: '🚨' },
    { path: '/investigate', label: 'Investigation', icon: '🔍' }
  ];

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (isMenuOpen && !event.target.closest('.kibana-header')) {
        setIsMenuOpen(false);
      }
    };

    if (isMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isMenuOpen]);

  // Check if current path matches menu item (including investigation with IP)
  const isActive = (path) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    if (path === '/investigate') {
      return location.pathname.startsWith('/investigate');
    }
    return location.pathname === path;
  };

  return (
      <div className="kibana-header">
        <div className="header-content">
          <div className="header-left">
            <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div className="fsociety-logo">FSOCIETY</div>
              <span className="header-title">Honeypot Dashboard</span>
            </Link>
          </div>
          <div className="header-right">
            <ConnectionStatus />
            <button className="hamburger-menu" onClick={toggleMenu}>
              <div className="hamburger-line"></div>
              <div className="hamburger-line"></div>
              <div className="hamburger-line"></div>
            </button>
          </div>
          {isMenuOpen && (
            <div className="dropdown-menu">
              {menuItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`menu-item ${isActive(item.path) ? 'active' : ''}`}
                  onClick={() => setIsMenuOpen(false)}
                >
                  <span style={{ marginRight: '8px' }}>{item.icon}</span>
                  {item.label}
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
  );
}

function App() {
  return (
    <Router
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true
      }}
    >
      <div className="App">
        <Navigation />
        <div className="search-container">
          <input 
            type="text" 
            placeholder="Filter your data using KQL syntax..."
            className="kibana-search"
          />
        </div>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/live-events" element={<LiveEvents />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/map" element={<MapView />} />
          <Route path="/ml-insights" element={<MLInsights />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/investigate" element={<Investigation />} />
          <Route path="/investigate/:ip" element={<Investigation />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
