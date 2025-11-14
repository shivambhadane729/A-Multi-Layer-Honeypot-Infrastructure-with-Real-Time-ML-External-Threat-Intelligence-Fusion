#!/usr/bin/env python3
"""
Test script for Honeypot Services
Tests all endpoints to ensure they're working correctly
"""

import requests
import json
import time
import sys

# Configuration
HONEYPOT_URL = "http://localhost:8000"
TEST_DELAY = 1  # Delay between tests

def test_endpoint(method, endpoint, data=None, expected_status=200):
    """Test a single endpoint"""
    url = f"{HONEYPOT_URL}{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, timeout=10)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, timeout=10)
        else:
            print(f"❌ Unsupported method: {method}")
            return False
        
        if response.status_code == expected_status:
            print(f"✅ {method} {endpoint} - Status: {response.status_code}")
            return True
        else:
            print(f"❌ {method} {endpoint} - Expected: {expected_status}, Got: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ {method} {endpoint} - Error: {e}")
        return False

def test_git_endpoints():
    """Test Git repository endpoints"""
    print("\n🔍 Testing Git Repository Endpoints...")
    
    tests = [
        ("GET", "/", 200),
        ("GET", "/health", 200),
        ("POST", "/repo/push", {"commit_message": "Test commit", "branch": "main"}, 200),
        ("POST", "/repo/pull", {"branch": "main"}, 200),
        ("GET", "/.env", 200),
        ("GET", "/secrets.yml", 200),
        ("GET", "/config.json", 200),
    ]
    
    passed = 0
    total = len(tests)
    
    for method, endpoint, *args in tests:
        data = args[0] if args and len(args) > 0 else None
        expected_status = args[1] if args and len(args) > 1 else 200
        
        if test_endpoint(method, endpoint, data, expected_status):
            passed += 1
        
        time.sleep(TEST_DELAY)
    
    print(f"📊 Git Endpoints: {passed}/{total} passed")
    return passed == total

def test_cicd_endpoints():
    """Test CI/CD runner endpoints"""
    print("\n🔍 Testing CI/CD Runner Endpoints...")
    
    tests = [
        ("POST", "/ci/run", {"job_name": "test-build", "environment": "production"}, 200),
        ("GET", "/ci/status", None, 200),
        ("GET", "/ci/logs/job_123456", None, 200),
        ("GET", "/ci/credentials", None, 200),
        ("GET", "/ci/config", None, 200),
    ]
    
    passed = 0
    total = len(tests)
    
    for method, endpoint, *args in tests:
        data = args[0] if args and len(args) > 0 else None
        expected_status = args[1] if args and len(args) > 1 else 200
        
        if test_endpoint(method, endpoint, data, expected_status):
            passed += 1
        
        time.sleep(TEST_DELAY)
    
    print(f"📊 CI/CD Endpoints: {passed}/{total} passed")
    return passed == total

def test_static_files():
    """Test static file serving"""
    print("\n🔍 Testing Static File Serving...")
    
    tests = [
        ("GET", "/static/secrets.yml", None, 200),
        ("GET", "/static/env_file", None, 200),
        ("GET", "/static/README.md", None, 200),
        ("GET", "/static/config.json", None, 200),
    ]
    
    passed = 0
    total = len(tests)
    
    for method, endpoint, *args in tests:
        data = args[0] if args and len(args) > 0 else None
        expected_status = args[1] if args and len(args) > 1 else 200
        
        if test_endpoint(method, endpoint, data, expected_status):
            passed += 1
        
        time.sleep(TEST_DELAY)
    
    print(f"📊 Static Files: {passed}/{total} passed")
    return passed == total

def test_error_handling():
    """Test error handling"""
    print("\n🔍 Testing Error Handling...")
    
    tests = [
        ("GET", "/nonexistent", None, 404),
        ("GET", "/static/nonexistent.txt", None, 404),
    ]
    
    passed = 0
    total = len(tests)
    
    for method, endpoint, *args in tests:
        data = args[0] if args and len(args) > 0 else None
        expected_status = args[1] if args and len(args) > 1 else 200
        
        if test_endpoint(method, endpoint, data, expected_status):
            passed += 1
        
        time.sleep(TEST_DELAY)
    
    print(f"📊 Error Handling: {passed}/{total} passed")
    return passed == total

def check_honeypot_running():
    """Check if honeypot is running"""
    try:
        response = requests.get(f"{HONEYPOT_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Honeypot service is running")
            return True
        else:
            print(f"❌ Honeypot service returned status: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to honeypot service: {e}")
        print("💡 Make sure to start the honeypot service first:")
        print("   python honeypot_services.py")
        return False

def main():
    """Main test function"""
    print("🍯 Honeypot Services Test Suite")
    print("=" * 50)
    
    # Check if honeypot is running
    if not check_honeypot_running():
        sys.exit(1)
    
    # Run all tests
    all_passed = True
    
    all_passed &= test_git_endpoints()
    all_passed &= test_cicd_endpoints()
    all_passed &= test_static_files()
    all_passed &= test_error_handling()
    
    # Summary
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! Honeypot services are working correctly.")
        print("\n📋 Available endpoints:")
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
        print("     GET /static/<filename>")
    else:
        print("❌ Some tests failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
