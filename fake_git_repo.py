#!/usr/bin/env python3
"""
Fake Git Repository Honeypot Service
Phase 2: Honeypot Deployment

This service simulates a Git repository with endpoints that attackers often target.
It captures attack details and forwards them to the logging server.
"""

from flask import Flask, request, jsonify, send_file
import json
import uuid
import requests
import os
from datetime import datetime
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Logging server endpoint - Updated to use the new enhanced logging server
LOGGING_SERVER_URL = "http://192.168.1.2:5000/log"  # Internal network IP as per Phase 1

# Session storage (in production, use Redis or database)
active_sessions = {}

def get_or_create_session(source_ip):
    """Get existing session or create new one for the source IP"""
    if source_ip not in active_sessions:
        active_sessions[source_ip] = str(uuid.uuid4())
    return active_sessions[source_ip]

def forward_log_to_server(log_data):
    """Forward log data to the logging server"""
    try:
        response = requests.post(
            LOGGING_SERVER_URL,
            json=log_data,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"Log forwarded successfully for session {log_data.get('session_id')}")
        else:
            logger.error(f"Failed to forward log: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding log: {e}")

def create_log_entry(source_ip, action, target_file=None, payload=None):
    """Create a standardized log entry"""
    session_id = get_or_create_session(source_ip)
    
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake Git Repository",
        "action": action,
        "target_file": target_file,
        "payload": payload,
        "headers": dict(request.headers),
        "session_id": session_id,
        "user_agent": request.headers.get('User-Agent', 'Unknown')
    }
    
    # Forward to logging server
    forward_log_to_server(log_data)
    
    return log_data

@app.route('/')
def index():
    """Main repository page - looks like a real Git repo"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "index_access")
    
    return """
    <html>
    <head><title>Git Repository - Honeypot</title></head>
    <body>
        <h1>🔒 Private Git Repository</h1>
        <p>This is a private repository. Authentication required.</p>
        <p>Available endpoints:</p>
        <ul>
            <li>POST /repo/push - Push commits</li>
            <li>POST /repo/pull - Pull changes</li>
            <li>GET /.env - Environment file</li>
            <li>GET /secrets.yml - Secrets file</li>
        </ul>
    </body>
    </html>
    """, 200, {'Content-Type': 'text/html'}

@app.route('/repo/push', methods=['POST'])
def git_push():
    """Simulate Git push operation"""
    source_ip = request.remote_addr
    
    try:
        # Extract push data from request
        push_data = request.get_json() or {}
        commit_message = push_data.get('commit_message', 'No message')
        branch = push_data.get('branch', 'main')
        files_changed = push_data.get('files_changed', [])
        
        # Create log entry
        payload = {
            "commit_message": commit_message,
            "branch": branch,
            "files_changed": files_changed,
            "push_data": push_data
        }
        
        create_log_entry(source_ip, "git_push", payload=payload)
        
        # Simulate successful push
        return jsonify({
            "status": "success",
            "message": "Push completed successfully",
            "commit_hash": f"abc{str(uuid.uuid4())[:8]}",
            "files_updated": len(files_changed)
        }), 200
        
    except Exception as e:
        logger.error(f"Error in git_push: {e}")
        return jsonify({"error": "Push failed"}), 500

@app.route('/repo/pull', methods=['POST'])
def git_pull():
    """Simulate Git pull operation"""
    source_ip = request.remote_addr
    
    try:
        # Extract pull data from request
        pull_data = request.get_json() or {}
        branch = pull_data.get('branch', 'main')
        
        # Create log entry
        payload = {
            "branch": branch,
            "pull_data": pull_data
        }
        
        create_log_entry(source_ip, "git_pull", payload=payload)
        
        # Simulate successful pull with fake changes
        fake_changes = [
            {"file": "src/main.py", "status": "modified"},
            {"file": "config/settings.json", "status": "added"},
            {"file": "README.md", "status": "modified"}
        ]
        
        return jsonify({
            "status": "success",
            "message": "Pull completed successfully",
            "changes": fake_changes,
            "last_commit": f"def{str(uuid.uuid4())[:8]}"
        }), 200
        
    except Exception as e:
        logger.error(f"Error in git_pull: {e}")
        return jsonify({"error": "Pull failed"}), 500

@app.route('/.env')
def get_env_file():
    """Serve fake .env file to lure attackers"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_access", target_file=".env")
    
    # Fake environment file with tempting secrets
    fake_env_content = """# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=production_db
DB_USER=admin
DB_PASSWORD=super_secret_password_123

# API Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# JWT Secret
JWT_SECRET=my_super_secret_jwt_key_that_should_not_be_here

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=redis_secret_pass

# External Services
STRIPE_SECRET_KEY=sk_test_51234567890abcdef
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_secret
"""
    
    return fake_env_content, 200, {'Content-Type': 'text/plain'}

@app.route('/secrets.yml')
def get_secrets_file():
    """Serve fake secrets.yml file to lure attackers"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_access", target_file="secrets.yml")
    
    # Fake secrets file
    fake_secrets_content = """# Production Secrets
database:
  host: "prod-db.internal"
  username: "prod_user"
  password: "ultra_secure_password_456"
  ssl: true

api_keys:
  stripe: "sk_live_51234567890abcdef"
  paypal: "live_client_id_here"
  github: "ghp_xxxxxxxxxxxxxxxxxxxx"
  
aws:
  access_key: "AKIAIOSFODNN7EXAMPLE"
  secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region: "us-east-1"

encryption:
  private_key: "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC..."
  public_key: "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
"""
    
    return fake_secrets_content, 200, {'Content-Type': 'text/yaml'}

@app.route('/config.json')
def get_config_file():
    """Serve fake config.json file"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_access", target_file="config.json")
    
    fake_config = {
        "app_name": "Production App",
        "version": "2.1.0",
        "debug": False,
        "database": {
            "host": "prod-db-cluster.internal",
            "port": 5432,
            "name": "production_app_db"
        },
        "redis": {
            "host": "redis-cluster.internal",
            "port": 6379,
            "password": "redis_prod_password"
        },
        "external_apis": {
            "payment_gateway": "https://api.stripe.com/v1",
            "email_service": "https://api.sendgrid.com/v3",
            "monitoring": "https://api.datadog.com/v1"
        }
    }
    
    return jsonify(fake_config), 200

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt to look more legitimate"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_access", target_file="robots.txt")
    
    return """User-agent: *
Disallow: /admin/
Disallow: /.env
Disallow: /secrets.yml
Disallow: /config.json
""", 200, {'Content-Type': 'text/plain'}

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors - log attempted access to non-existent files"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_not_found", target_file=request.path)
    
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource was not found"
    }), 404

if __name__ == '__main__':
    print("🚀 Starting Fake Git Repository Honeypot...")
    print("📍 Endpoints available:")
    print("   POST /repo/push")
    print("   POST /repo/pull") 
    print("   GET /.env")
    print("   GET /secrets.yml")
    print("   GET /config.json")
    print("   GET /robots.txt")
    print("📊 Logs will be forwarded to:", LOGGING_SERVER_URL)
    print("🌐 Server starting on http://localhost:8001")
    
    app.run(host='0.0.0.0', port=8001, debug=True)
