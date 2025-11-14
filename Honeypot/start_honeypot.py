#!/usr/bin/env python3
"""
Startup script for Honeypot Services
Starts the consolidated honeypot service
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
        print("✅ Dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("💡 Install dependencies with: pip install Flask requests")
        return False

def start_honeypot():
    """Start the honeypot service"""
    print("🍯 Starting Honeypot Services...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check if honeypot_services.py exists
    if not os.path.exists('honeypot_services.py'):
        print("❌ honeypot_services.py not found!")
        print("💡 Make sure you're in the correct directory")
        sys.exit(1)
    
    # Start the service
    try:
        print("🚀 Starting Flask server on 0.0.0.0:8000...")
        print("📡 Logging server configured for: http://192.168.1.2:5000/log")
        print("🌐 Service will be accessible at: http://localhost:8000")
        print("\n💡 Press Ctrl+C to stop the service")
        print("=" * 50)
        
        # Start the Flask application
        subprocess.run([sys.executable, 'honeypot_services.py'])
        
    except KeyboardInterrupt:
        print("\n🛑 Honeypot service stopped by user")
    except Exception as e:
        print(f"❌ Error starting honeypot service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_honeypot()
