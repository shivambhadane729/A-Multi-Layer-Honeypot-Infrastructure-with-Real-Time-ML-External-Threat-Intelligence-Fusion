#!/usr/bin/env python3
"""
Startup script for Logging Server
Starts the centralized logging server for honeypot events
"""

import subprocess
import sys
import os
import time

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        import requests
        import ipapi
        print("✅ Dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("💡 Install dependencies with: pip install Flask requests ipapi")
        return False

def start_logging_server():
    """Start the logging server"""
    print("📊 Starting Honeypot Logging Server...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check if logging_server.py exists
    if not os.path.exists('logging_server.py'):
        print("❌ logging_server.py not found!")
        print("💡 Make sure you're in the correct directory")
        sys.exit(1)
    
    # Start the service
    try:
        print("🚀 Starting Flask server on 0.0.0.0:5000...")
        print("📡 Ready to receive logs from honeypot services")
        print("🌐 Service will be accessible at: http://localhost:5000")
        print("🗄️  Database: honeypot.db (SQLite)")
        print("🌍 GeoIP: ipapi.co integration enabled")
        print("\n💡 Press Ctrl+C to stop the service")
        print("=" * 50)
        
        # Start the Flask application
        subprocess.run([sys.executable, 'logging_server.py'])
        
    except KeyboardInterrupt:
        print("\n🛑 Logging server stopped by user")
    except Exception as e:
        print(f"❌ Error starting logging server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_logging_server()
