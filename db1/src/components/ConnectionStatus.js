import React, { useState, useEffect } from 'react';
import { api } from '../api';

function ConnectionStatus() {
  const [isConnected, setIsConnected] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const checkConnection = async () => {
    try {
      const connected = await api.checkHealth();
      setIsConnected(connected);
    } catch {
      setIsConnected(false);
    } finally {
      setChecking(false);
    }
  };

  if (checking) return null;

  return (
    <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
      <span className="connection-status__indicator">{isConnected ? '🟢' : '🔴'}</span>
      <span className="connection-status__label">
        {isConnected ? 'Backend Connected' : 'Backend Disconnected'}
      </span>
    </div>
  );
}

export default ConnectionStatus;

