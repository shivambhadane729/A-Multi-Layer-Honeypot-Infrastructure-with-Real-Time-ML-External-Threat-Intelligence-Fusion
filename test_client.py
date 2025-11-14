#!/usr/bin/env python3
"""
Test Client for Honeypot Logging System
Phase 3: Testing

This script sends dummy log events to test the honeypot services and logging server.
"""

import requests
import json
import time
import random
from datetime import datetime
import uuid

# Configuration
GIT_REPO_URL = "http://localhost:8001"
CICD_RUNNER_URL = "http://localhost:8002"
LOGGING_SERVER_URL = "http://localhost:5000"

def test_git_repo():
    """Test the fake Git repository service"""
    print("🔍 Testing Fake Git Repository...")
    
    # Test index page
    try:
        response = requests.get(f"{GIT_REPO_URL}/")
        print(f"✅ Index page: {response.status_code}")
    except Exception as e:
        print(f"❌ Index page failed: {e}")
    
    # Test git push
    try:
        push_data = {
            "commit_message": "Add new feature",
            "branch": "main",
            "files_changed": ["src/app.py", "config/settings.json"]
        }
        response = requests.post(f"{GIT_REPO_URL}/repo/push", json=push_data)
        print(f"✅ Git push: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Git push failed: {e}")
    
    # Test git pull
    try:
        pull_data = {
            "branch": "main"
        }
        response = requests.post(f"{GIT_REPO_URL}/repo/pull", json=pull_data)
        print(f"✅ Git pull: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Git pull failed: {e}")
    
    # Test file access
    try:
        response = requests.get(f"{GIT_REPO_URL}/.env")
        print(f"✅ .env file access: {response.status_code}")
    except Exception as e:
        print(f"❌ .env file access failed: {e}")
    
    try:
        response = requests.get(f"{GIT_REPO_URL}/secrets.yml")
        print(f"✅ secrets.yml file access: {response.status_code}")
    except Exception as e:
        print(f"❌ secrets.yml file access failed: {e}")

def test_cicd_runner():
    """Test the fake CI/CD runner service"""
    print("\n🔍 Testing Fake CI/CD Runner...")
    
    # Test index page
    try:
        response = requests.get(f"{CICD_RUNNER_URL}/")
        print(f"✅ Index page: {response.status_code}")
    except Exception as e:
        print(f"❌ Index page failed: {e}")
    
    # Test job execution
    try:
        job_data = {
            "job_name": "test-build",
            "branch": "main",
            "environment": "production"
        }
        response = requests.post(f"{CICD_RUNNER_URL}/ci/run", json=job_data)
        print(f"✅ CI job run: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ CI job run failed: {e}")
    
    # Test status check
    try:
        response = requests.get(f"{CICD_RUNNER_URL}/ci/status")
        print(f"✅ Status check: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Status check failed: {e}")
    
    # Test credentials access (honeypot!)
    try:
        response = requests.get(f"{CICD_RUNNER_URL}/ci/credentials")
        print(f"✅ Credentials access: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Credentials access failed: {e}")

def test_logging_server():
    """Test the logging server"""
    print("\n🔍 Testing Logging Server...")
    
    # Test health check
    try:
        response = requests.get(f"{LOGGING_SERVER_URL}/health")
        print(f"✅ Health check: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
    
    # Test stats
    try:
        response = requests.get(f"{LOGGING_SERVER_URL}/stats")
        print(f"✅ Stats: {response.status_code}")
        if response.status_code == 200:
            stats = response.json()
            print(f"   Total logs: {stats['total_logs']}")
            print(f"   Unique IPs: {stats['unique_ips']}")
    except Exception as e:
        print(f"❌ Stats failed: {e}")
    
    # Test logs retrieval
    try:
        response = requests.get(f"{LOGGING_SERVER_URL}/logs?per_page=5")
        print(f"✅ Logs retrieval: {response.status_code}")
        if response.status_code == 200:
            logs_data = response.json()
            print(f"   Retrieved {len(logs_data['logs'])} logs")
    except Exception as e:
        print(f"❌ Logs retrieval failed: {e}")

def send_dummy_logs():
    """Send dummy log entries directly to the logging server"""
    print("\n🔍 Sending Dummy Logs...")
    
    dummy_logs = [
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "protocol": "HTTP",
            "target_service": "Fake Git Repository",
            "action": "git_push",
            "target_file": None,
            "payload": {"commit_message": "Test commit", "branch": "main"},
            "headers": {"User-Agent": "Test Client"},
            "session_id": str(uuid.uuid4()),
            "user_agent": "Test Client"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "10.0.0.50",
            "protocol": "HTTP",
            "target_service": "Fake CI/CD Runner",
            "action": "ci_job_run",
            "target_file": None,
            "payload": {"job_name": "test-build", "environment": "staging"},
            "headers": {"User-Agent": "Test Client"},
            "session_id": str(uuid.uuid4()),
            "user_agent": "Test Client"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "203.0.113.42",
            "protocol": "HTTP",
            "target_service": "Fake Git Repository",
            "action": "file_access",
            "target_file": ".env",
            "payload": None,
            "headers": {"User-Agent": "curl/7.68.0"},
            "session_id": str(uuid.uuid4()),
            "user_agent": "curl/7.68.0"
        }
    ]
    
    for i, log_data in enumerate(dummy_logs):
        try:
            response = requests.post(f"{LOGGING_SERVER_URL}/log", json=log_data)
            print(f"✅ Dummy log {i+1}: {response.status_code}")
            if response.status_code == 200:
                print(f"   Log ID: {response.json().get('log_id')}")
        except Exception as e:
            print(f"❌ Dummy log {i+1} failed: {e}")

def main():
    """Main test function"""
    print("🚀 Starting Honeypot System Test")
    print("=" * 50)
    
    # Wait a moment for services to be ready
    print("⏳ Waiting for services to start...")
    time.sleep(2)
    
    # Test each service
    test_git_repo()
    test_cicd_runner()
    test_logging_server()
    send_dummy_logs()
    
    print("\n" + "=" * 50)
    print("✅ Test completed!")
    print("\n📊 Check the logging server stats:")
    print(f"   GET {LOGGING_SERVER_URL}/stats")
    print(f"   GET {LOGGING_SERVER_URL}/logs")

if __name__ == "__main__":
    main()
