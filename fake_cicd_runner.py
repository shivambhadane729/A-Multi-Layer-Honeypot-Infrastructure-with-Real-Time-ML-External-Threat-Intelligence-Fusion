#!/usr/bin/env python3
"""
Fake CI/CD Runner Honeypot Service
Phase 2: Honeypot Deployment

This service simulates a CI/CD runner that attackers often target for credentials
and job execution. It captures attack details and forwards them to the logging server.
"""

from flask import Flask, request, jsonify
import json
import uuid
import requests
import os
import random
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
        "target_service": "Fake CI/CD Runner",
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

def generate_fake_job_log():
    """Generate a realistic-looking CI/CD job log"""
    job_id = str(uuid.uuid4())[:8]
    build_number = random.randint(1000, 9999)
    
    fake_log = f"""=== CI/CD Job Execution Log ===
Job ID: {job_id}
Build Number: #{build_number}
Status: SUCCESS
Duration: {random.randint(30, 300)}s

[INFO] Starting build process...
[INFO] Checking out repository...
[INFO] Installing dependencies...
[INFO] Running tests...
[INFO] Building application...
[INFO] Deploying to staging...
[INFO] Running integration tests...
[INFO] Deploying to production...
[SUCCESS] Build completed successfully!

=== Environment Variables ===
NODE_ENV=production
DATABASE_URL=postgresql://user:pass@db.internal:5432/app
REDIS_URL=redis://redis.internal:6379
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51234567890abcdef
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

=== Build Artifacts ===
- app.tar.gz (2.3MB)
- docker-image:latest
- test-results.xml
- coverage-report.html

=== Deployment Info ===
Target: production-cluster-1
Region: us-east-1
Instance Type: t3.large
Auto-scaling: enabled
"""
    
    return fake_log, job_id, build_number

@app.route('/')
def index():
    """Main CI/CD dashboard page"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "index_access")
    
    return """
    <html>
    <head><title>CI/CD Runner - Honeypot</title></head>
    <body>
        <h1>🚀 CI/CD Runner Dashboard</h1>
        <p>Welcome to the Continuous Integration/Deployment Runner</p>
        <p>Available endpoints:</p>
        <ul>
            <li>POST /ci/run - Execute CI/CD job</li>
            <li>GET /ci/status - Check job status</li>
            <li>GET /ci/logs - View job logs</li>
            <li>GET /ci/config - View configuration</li>
            <li>GET /ci/credentials - View credentials (admin only)</li>
        </ul>
    </body>
    </html>
    """, 200, {'Content-Type': 'text/html'}

@app.route('/ci/run', methods=['POST'])
def run_job():
    """Simulate CI/CD job execution"""
    source_ip = request.remote_addr
    
    try:
        # Extract job data from request
        job_data = request.get_json() or {}
        job_name = job_data.get('job_name', 'default-build')
        branch = job_data.get('branch', 'main')
        environment = job_data.get('environment', 'production')
        
        # Create log entry
        payload = {
            "job_name": job_name,
            "branch": branch,
            "environment": environment,
            "job_data": job_data
        }
        
        create_log_entry(source_ip, "ci_job_run", payload=payload)
        
        # Generate fake job log
        job_log, job_id, build_number = generate_fake_job_log()
        
        # Simulate job execution
        return jsonify({
            "status": "success",
            "message": "Job started successfully",
            "job_id": job_id,
            "build_number": build_number,
            "job_name": job_name,
            "branch": branch,
            "environment": environment,
            "estimated_duration": f"{random.randint(60, 300)}s",
            "log_url": f"/ci/logs/{job_id}"
        }), 200
        
    except Exception as e:
        logger.error(f"Error in run_job: {e}")
        return jsonify({"error": "Job execution failed"}), 500

@app.route('/ci/status')
def job_status():
    """Check CI/CD job status"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "ci_status_check")
    
    # Simulate various job statuses
    statuses = ["running", "success", "failed", "pending"]
    status = random.choice(statuses)
    
    return jsonify({
        "status": status,
        "active_jobs": random.randint(0, 5),
        "queued_jobs": random.randint(0, 3),
        "last_build": {
            "number": random.randint(1000, 9999),
            "status": status,
            "duration": f"{random.randint(30, 300)}s"
        }
    }), 200

@app.route('/ci/logs/<job_id>')
def get_job_logs(job_id):
    """Get job execution logs"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "ci_logs_access", target_file=f"logs/{job_id}")
    
    # Generate fake log for the job
    fake_log, _, _ = generate_fake_job_log()
    
    return fake_log, 200, {'Content-Type': 'text/plain'}

@app.route('/ci/config')
def get_config():
    """Get CI/CD configuration"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "ci_config_access", target_file="ci_config")
    
    fake_config = {
        "runner_name": "production-runner-01",
        "version": "2.1.0",
        "max_concurrent_jobs": 10,
        "timeout": 3600,
        "environments": ["staging", "production"],
        "notifications": {
            "slack": "https://hooks.slack.com/services/FAKE/WEBHOOK/URL_FOR_HONEYPOT_DEMO",
            "email": "ci-alerts@company.com"
        },
        "docker": {
            "registry": "registry.internal:5000",
            "username": "ci-user",
            "password": "ci_password_123"
        }
    }
    
    return jsonify(fake_config), 200

@app.route('/ci/credentials')
def get_credentials():
    """Get CI/CD credentials (admin only) - This is a honeypot!"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "ci_credentials_access", target_file="credentials")
    
    # Fake credentials to lure attackers
    fake_credentials = {
        "database": {
            "host": "prod-db-cluster.internal",
            "username": "ci_user",
            "password": "super_secure_ci_password_789",
            "port": 5432
        },
        "aws": {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        },
        "github": {
            "token": "ghp_xxxxxxxxxxxxxxxxxxxx",
            "webhook_secret": "webhook_secret_123"
        },
        "docker": {
            "registry": "registry.internal:5000",
            "username": "ci-user",
            "password": "docker_registry_password_456"
        },
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/FAKE/WEBHOOK/URL_FOR_HONEYPOT_DEMO",
            "bot_token": "xoxb-FAKE-BOT-TOKEN-FOR-HONEYPOT-DEMO-ONLY"
        }
    }
    
    return jsonify(fake_credentials), 200

@app.route('/ci/jobs')
def list_jobs():
    """List recent CI/CD jobs"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "ci_jobs_list")
    
    # Generate fake job list
    fake_jobs = []
    for i in range(10):
        fake_jobs.append({
            "id": str(uuid.uuid4())[:8],
            "name": f"build-{random.choice(['frontend', 'backend', 'api', 'mobile'])}",
            "status": random.choice(["success", "failed", "running", "pending"]),
            "branch": random.choice(["main", "develop", "feature/auth", "hotfix/bug-123"]),
            "created_at": datetime.now().isoformat(),
            "duration": f"{random.randint(30, 300)}s"
        })
    
    return jsonify({
        "jobs": fake_jobs,
        "total": len(fake_jobs)
    }), 200

@app.route('/ci/webhook', methods=['POST'])
def webhook():
    """Simulate webhook endpoint for CI/CD triggers"""
    source_ip = request.remote_addr
    
    try:
        webhook_data = request.get_json() or {}
        create_log_entry(source_ip, "ci_webhook", payload=webhook_data)
        
        return jsonify({
            "status": "success",
            "message": "Webhook received and processed"
        }), 200
        
    except Exception as e:
        logger.error(f"Error in webhook: {e}")
        return jsonify({"error": "Webhook processing failed"}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    source_ip = request.remote_addr
    create_log_entry(source_ip, "file_not_found", target_file=request.path)
    
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource was not found"
    }), 404

if __name__ == '__main__':
    print("🚀 Starting Fake CI/CD Runner Honeypot...")
    print("📍 Endpoints available:")
    print("   POST /ci/run")
    print("   GET /ci/status")
    print("   GET /ci/logs/<job_id>")
    print("   GET /ci/config")
    print("   GET /ci/credentials")
    print("   GET /ci/jobs")
    print("   POST /ci/webhook")
    print("📊 Logs will be forwarded to:", LOGGING_SERVER_URL)
    print("🌐 Server starting on http://localhost:8002")
    
    app.run(host='0.0.0.0', port=8002, debug=True)
