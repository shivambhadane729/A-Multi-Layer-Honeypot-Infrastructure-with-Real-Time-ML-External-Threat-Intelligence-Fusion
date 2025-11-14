#!/usr/bin/env python3
"""
Honeypot Services - Phase 2 Implementation
Consolidated fake Git repository and CI/CD runner services
"""

from flask import Flask, request, jsonify, send_from_directory
import requests
import json
import uuid
import hashlib
import datetime
import os
import random
import time

app = Flask(__name__)

# Configuration
LOGGING_SERVER_URL = "http://192.168.1.2:5000/log"  # Internal logging server IP
HONEYPOT_SERVICE_NAME = "Consolidated Honeypot Services"

def generate_session_id():
    """Generate a unique session ID for tracking attackers"""
    return str(uuid.uuid4())

def create_log_hash(log_data):
    """Create SHA256 hash for log integrity"""
    log_string = json.dumps(log_data, sort_keys=True)
    return hashlib.sha256(log_string.encode()).hexdigest()

def send_log(log_data):
    """Send captured attack data to the logging server"""
    try:
        # Add integrity hash
        log_data['log_hash'] = create_log_hash(log_data)
        
        # Send to logging server
        response = requests.post(
            LOGGING_SERVER_URL,
            json=log_data,
            timeout=5,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print(f"✅ Log sent successfully: {log_data['action']} from {log_data['source_ip']}")
        else:
            print(f"❌ Failed to send log: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error sending log to logging server: {e}")
        # Store locally if logging server is unavailable
        store_local_log(log_data)

def store_local_log(log_data):
    """Store log locally if logging server is unavailable"""
    try:
        os.makedirs('logs', exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/honeypot_log_{timestamp}_{log_data['source_ip'].replace('.', '_')}.json"
        
        with open(filename, 'w') as f:
            json.dump(log_data, f, indent=2)
        print(f"📁 Log stored locally: {filename}")
    except Exception as e:
        print(f"❌ Error storing local log: {e}")

def capture_attack_data(action, target_file=None, payload=None):
    """Capture and log attack data"""
    # Get client information
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Create log entry
    log_data = {
        'timestamp': datetime.datetime.now().isoformat() + 'Z',
        'source_ip': source_ip,
        'geo_country': 'Unknown',  # Would be enriched by logging server
        'geo_city': 'Unknown',
        'protocol': 'HTTP',
        'target_service': HONEYPOT_SERVICE_NAME,
        'action': action,
        'target_file': target_file,
        'payload': payload,
        'headers': dict(request.headers),
        'session_id': generate_session_id(),
        'user_agent': user_agent
    }
    
    # Send to logging server
    send_log(log_data)
    
    return log_data

# ============================================================================
# FAKE GIT REPOSITORY ENDPOINTS
# ============================================================================

@app.route('/repo/push', methods=['POST'])
def fake_git_push():
    """Simulate Git push operation"""
    try:
        payload = request.get_json() or {}
        
        # Capture attack data
        capture_attack_data(
            action='git_push',
            payload={
                'commit_message': payload.get('commit_message', 'No message'),
                'branch': payload.get('branch', 'main'),
                'files_changed': payload.get('files_changed', []),
                'author': payload.get('author', 'unknown@example.com')
            }
        )
        
        # Simulate processing delay
        time.sleep(random.uniform(0.5, 2.0))
        
        return jsonify({
            'status': 'success',
            'message': 'Push completed successfully',
            'commit_hash': f"{random.randint(1000000, 9999999):x}",
            'files_processed': len(payload.get('files_changed', [])),
            'branch': payload.get('branch', 'main')
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Push failed: {str(e)}'
        }), 500

@app.route('/repo/pull', methods=['POST'])
def fake_git_pull():
    """Simulate Git pull operation"""
    try:
        payload = request.get_json() or {}
        
        # Capture attack data
        capture_attack_data(
            action='git_pull',
            payload={
                'branch': payload.get('branch', 'main'),
                'remote': payload.get('remote', 'origin'),
                'force': payload.get('force', False)
            }
        )
        
        # Simulate processing delay
        time.sleep(random.uniform(0.3, 1.5))
        
        return jsonify({
            'status': 'success',
            'message': 'Pull completed successfully',
            'commits_ahead': random.randint(0, 5),
            'files_updated': random.randint(1, 10),
            'branch': payload.get('branch', 'main')
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Pull failed: {str(e)}'
        }), 500

@app.route('/.env', methods=['GET'])
def fake_env_file():
    """Serve fake environment file with sensitive data"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file='.env',
        payload={'file_type': 'environment_variables'}
    )
    
    # Return fake sensitive environment variables
    fake_env_content = """# Database Configuration
DB_HOST=prod-db.internal.company.com
DB_PORT=5432
DB_NAME=production_database
DB_USER=admin
DB_PASSWORD=SuperSecretPassword123!
DB_SSL=true

# API Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# JWT Secrets
JWT_SECRET=mySuperSecretJWTKeyThatShouldNeverBeExposed
JWT_EXPIRATION=3600

# External Services
STRIPE_SECRET_KEY=sk_test_51234567890abcdef
PAYPAL_CLIENT_ID=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890
PAYPAL_CLIENT_SECRET=1234567890abcdefghijklmnopqrstuvwxyz

# Internal Services
INTERNAL_API_KEY=internal_api_key_12345
MONITORING_TOKEN=monitoring_token_67890
"""
    
    return fake_env_content, 200, {'Content-Type': 'text/plain'}

@app.route('/secrets.yml', methods=['GET'])
def fake_secrets_yml():
    """Serve fake secrets YAML file"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file='secrets.yml',
        payload={'file_type': 'yaml_secrets'}
    )
    
    # Return fake secrets in YAML format
    fake_secrets_content = """# Production Secrets
database:
  host: "prod-db-cluster.internal"
  port: 5432
  username: "prod_user"
  password: "UltraSecurePassword456!"
  ssl_cert: "/etc/ssl/certs/db-cert.pem"

api_keys:
  stripe: "sk_live_FAKE_STRIPE_KEY_FOR_HONEYPOT_DEMO_ONLY"
  paypal: "live_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
  aws:
    access_key: "AKIAIOSFODNN7EXAMPLE"
    secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  
authentication:
  jwt_secret: "production_jwt_secret_key_very_long_and_secure"
  admin_token: "admin_token_xyz789"
  service_account_key: "service_account_key_abc123"

monitoring:
  datadog_api_key: "dd_api_key_1234567890abcdef"
  newrelic_license_key: "newrelic_license_abcdef123456"
  sentry_dsn: "https://sentry.io/project/1234567890"

internal_services:
  redis_password: "redis_secure_password_789"
  elasticsearch_password: "es_password_456"
  kafka_password: "kafka_password_123"
"""
    
    return fake_secrets_content, 200, {'Content-Type': 'text/yaml'}

@app.route('/config.json', methods=['GET'])
def fake_config_json():
    """Serve fake configuration JSON file"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file='config.json',
        payload={'file_type': 'json_config'}
    )
    
    # Return fake configuration
    fake_config = {
        "database": {
            "host": "prod-db.internal.company.com",
            "port": 5432,
            "name": "production_app",
            "credentials": {
                "username": "app_user",
                "password": "AppSecurePassword789!"
            }
        },
        "api": {
            "base_url": "https://api.company.com",
            "version": "v2",
            "timeout": 30,
            "retry_attempts": 3
        },
        "security": {
            "jwt_secret": "jwt_production_secret_key_very_long",
            "encryption_key": "encryption_key_abcdef123456",
            "admin_password": "AdminPassword123!",
            "api_keys": {
                "stripe": "sk_live_51234567890abcdef",
                "paypal": "live_AbCdEfGhIjKlMnOpQrStUvWxYz",
                "aws": "AKIAIOSFODNN7EXAMPLE"
            }
        },
        "monitoring": {
            "enabled": True,
            "log_level": "INFO",
            "metrics_endpoint": "https://metrics.company.com",
            "alert_webhook": "https://alerts.company.com/webhook"
        }
    }
    
    return jsonify(fake_config), 200

# ============================================================================
# FAKE CI/CD RUNNER ENDPOINTS
# ============================================================================

@app.route('/ci/run', methods=['POST'])
def fake_ci_run():
    """Simulate CI/CD job execution"""
    try:
        payload = request.get_json() or {}
        job_id = f"job_{random.randint(100000, 999999)}"
        
        # Capture attack data
        capture_attack_data(
            action='ci_job_run',
            payload={
                'job_id': job_id,
                'job_name': payload.get('job_name', 'default-build'),
                'environment': payload.get('environment', 'production'),
                'branch': payload.get('branch', 'main'),
                'triggered_by': payload.get('triggered_by', 'manual')
            }
        )
        
        # Simulate job processing delay
        time.sleep(random.uniform(1.0, 3.0))
        
        return jsonify({
            'status': 'success',
            'message': 'CI job started successfully',
            'job_id': job_id,
            'estimated_duration': f"{random.randint(2, 10)} minutes",
            'environment': payload.get('environment', 'production'),
            'logs_url': f"/ci/logs/{job_id}"
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'CI job failed to start: {str(e)}'
        }), 500

@app.route('/ci/status', methods=['GET'])
def fake_ci_status():
    """Check CI/CD job status"""
    job_id = request.args.get('job_id', f"job_{random.randint(100000, 999999)}")
    
    # Capture attack data
    capture_attack_data(
        action='ci_status_check',
        payload={'job_id': job_id}
    )
    
    # Simulate random job status
    statuses = ['running', 'completed', 'failed', 'pending']
    status = random.choice(statuses)
    
    response_data = {
        'job_id': job_id,
        'status': status,
        'progress': random.randint(0, 100),
        'started_at': datetime.datetime.now().isoformat(),
        'estimated_completion': datetime.datetime.now().isoformat()
    }
    
    if status == 'completed':
        response_data['exit_code'] = 0
        response_data['duration'] = f"{random.randint(1, 15)} minutes"
    elif status == 'failed':
        response_data['exit_code'] = random.randint(1, 255)
        response_data['error_message'] = 'Build failed due to test failures'
    
    return jsonify(response_data), 200

@app.route('/ci/logs/<job_id>', methods=['GET'])
def fake_ci_logs(job_id):
    """View CI/CD job logs"""
    # Capture attack data
    capture_attack_data(
        action='ci_logs_access',
        payload={'job_id': job_id}
    )
    
    # Generate fake build logs
    fake_logs = f"""=== CI/CD Job Logs for {job_id} ===
[2024-01-15 10:30:00] Starting build process...
[2024-01-15 10:30:05] Checking out code from repository
[2024-01-15 10:30:10] Installing dependencies...
[2024-01-15 10:30:45] Running unit tests...
[2024-01-15 10:31:20] Running integration tests...
[2024-01-15 10:32:00] Building Docker image...
[2024-01-15 10:32:30] Pushing image to registry...
[2024-01-15 10:33:00] Deploying to production environment...
[2024-01-15 10:33:15] Running health checks...
[2024-01-15 10:33:30] Build completed successfully!

Build Summary:
- Tests: 156 passed, 0 failed
- Coverage: 87.5%
- Build time: 3 minutes 30 seconds
- Image size: 245 MB
- Deployment: Successful
"""
    
    return fake_logs, 200, {'Content-Type': 'text/plain'}

@app.route('/ci/credentials', methods=['GET'])
def fake_ci_credentials():
    """Serve fake CI/CD credentials"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file='ci_credentials',
        payload={'file_type': 'ci_credentials'}
    )
    
    # Return fake CI/CD credentials
    fake_credentials = {
        "docker_registry": {
            "url": "registry.company.com",
            "username": "ci_user",
            "password": "CISecurePassword123!",
            "token": "docker_token_abcdef123456"
        },
        "kubernetes": {
            "cluster_url": "https://k8s.company.com",
            "namespace": "production",
            "service_account": "ci-service-account",
            "token": "k8s_token_xyz789"
        },
        "aws": {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "s3_bucket": "ci-artifacts-bucket"
        },
        "github": {
            "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "webhook_secret": "webhook_secret_12345",
            "deploy_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
        },
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/FAKE/WEBHOOK/URL_FOR_HONEYPOT_DEMO",
            "bot_token": "xoxb-FAKE-BOT-TOKEN-FOR-HONEYPOT-DEMO-ONLY"
        }
    }
    
    return jsonify(fake_credentials), 200

@app.route('/ci/config', methods=['GET'])
def fake_ci_config():
    """Serve fake CI/CD configuration"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file='ci_config',
        payload={'file_type': 'ci_config'}
    )
    
    # Return fake CI/CD configuration
    fake_config = {
        "version": "2.1",
        "jobs": {
            "build": {
                "docker": {
                    "image": "node:16"
                },
                "steps": [
                    "checkout",
                    "run: npm install",
                    "run: npm test",
                    "run: npm run build",
                    "deploy: docker build -t app:$CIRCLE_SHA1 .",
                    "deploy: docker push registry.company.com/app:$CIRCLE_SHA1"
                ]
            },
            "deploy": {
                "docker": {
                    "image": "kubectl:latest"
                },
                "steps": [
                    "deploy: kubectl apply -f k8s/",
                    "deploy: kubectl rollout status deployment/app"
                ]
            }
        },
        "workflows": {
            "build_and_deploy": {
                "jobs": ["build", "deploy"]
            }
        },
        "environment": {
            "NODE_ENV": "production",
            "API_URL": "https://api.company.com",
            "DB_URL": "postgresql://user:password@db.company.com:5432/app"
        }
    }
    
    return jsonify(fake_config), 200

# ============================================================================
# STATIC FILES SERVING
# ============================================================================

@app.route('/static/<path:filename>')
def serve_static_file(filename):
    """Serve static files from the static directory"""
    # Capture attack data
    capture_attack_data(
        action='file_access',
        target_file=f'static/{filename}',
        payload={'file_type': 'static_file'}
    )
    
    try:
        return send_from_directory('static', filename)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

# ============================================================================
# HEALTH CHECK AND INFO ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': HONEYPOT_SERVICE_NAME,
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '1.0.0'
    }), 200

@app.route('/', methods=['GET'])
def index():
    """Root endpoint - show available services"""
    return jsonify({
        'service': HONEYPOT_SERVICE_NAME,
        'version': '1.0.0',
        'endpoints': {
            'git_repository': {
                'push': 'POST /repo/push',
                'pull': 'POST /repo/pull',
                'env_file': 'GET /.env',
                'secrets': 'GET /secrets.yml',
                'config': 'GET /config.json'
            },
            'ci_cd_runner': {
                'run_job': 'POST /ci/run',
                'job_status': 'GET /ci/status',
                'job_logs': 'GET /ci/logs/<job_id>',
                'credentials': 'GET /ci/credentials',
                'config': 'GET /ci/config'
            },
            'system': {
                'health': 'GET /health',
                'static_files': 'GET /static/<filename>'
            }
        },
        'note': 'This is a honeypot service for security research'
    }), 200

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    capture_attack_data(
        action='404_error',
        payload={'requested_path': request.path}
    )
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    capture_attack_data(
        action='500_error',
        payload={'error': str(error)}
    )
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == '__main__':
    print("🍯 Starting Honeypot Services...")
    print(f"📡 Logging server: {LOGGING_SERVER_URL}")
    print("🌐 Available endpoints:")
    print("   Git Repository:")
    print("     POST /repo/push")
    print("     POST /repo/pull") 
    print("     GET /.env")
    print("     GET /secrets.yml")
    print("     GET /config.json")
    print("   CI/CD Runner:")
    print("     POST /ci/run")
    print("     GET /ci/status")
    print("     GET /ci/logs/<job_id>")
    print("     GET /ci/credentials")
    print("     GET /ci/config")
    print("   System:")
    print("     GET /health")
    print("     GET /")
    print("\n🚀 Starting Flask server on 0.0.0.0:8000...")
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Run the application
    app.run(host='0.0.0.0', port=8000, debug=False)
