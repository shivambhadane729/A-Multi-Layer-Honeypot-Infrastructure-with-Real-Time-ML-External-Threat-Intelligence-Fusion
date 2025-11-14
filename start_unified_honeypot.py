#!/usr/bin/env python3
"""
Unified Honeypot System Startup Script
Starts all honeypot services and the logging server together
"""

import subprocess
import sys
import os
import time
import threading
import signal
import requests
from datetime import datetime

class HoneypotManager:
    def __init__(self):
        self.processes = {}
        self.running = True
        
        # Service configurations
        self.services = {
            'logging_server': {
                'script': 'logging_server.py',
                'port': 5000,
                'name': 'Logging Server',
                'description': 'Centralized logging and analytics'
            },
            'fake_git_repo': {
                'script': 'fake_git_repo.py',
                'port': 8001,
                'name': 'Fake Git Repository',
                'description': 'Git repository honeypot'
            },
            'fake_cicd_runner': {
                'script': 'fake_cicd_runner.py',
                'port': 8002,
                'name': 'Fake CI/CD Runner',
                'description': 'CI/CD runner honeypot'
            },
            'consolidated_honeypot': {
                'script': 'Honeypot/honeypot_services.py',
                'port': 8000,
                'name': 'Consolidated Honeypot',
                'description': 'Combined Git & CI/CD services'
            }
        }
    
    def check_dependencies(self):
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
    
    def start_service(self, service_name, config):
        """Start a single service"""
        script_path = config['script']
        
        if not os.path.exists(script_path):
            print(f"⚠️  {config['name']}: Script not found ({script_path})")
            return None
        
        try:
            print(f"🚀 Starting {config['name']} on port {config['port']}...")
            process = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment to check if the process started successfully
            time.sleep(2)
            
            if process.poll() is None:  # Process is still running
                print(f"✅ {config['name']} started successfully (PID: {process.pid})")
                return process
            else:
                stdout, stderr = process.communicate()
                print(f"❌ {config['name']} failed to start")
                print(f"   Error: {stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Error starting {config['name']}: {e}")
            return None
    
    def check_service_health(self, service_name, config):
        """Check if a service is responding"""
        try:
            response = requests.get(f"http://localhost:{config['port']}/health", timeout=5)
            if response.status_code == 200:
                return True
        except:
            pass
        return False
    
    def start_all_services(self):
        """Start all honeypot services"""
        print("🍯 Starting Unified Honeypot System...")
        print("=" * 60)
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Start services in order (logging server first)
        service_order = ['logging_server', 'fake_git_repo', 'fake_cicd_runner', 'consolidated_honeypot']
        
        for service_name in service_order:
            if service_name in self.services:
                config = self.services[service_name]
                process = self.start_service(service_name, config)
                
                if process:
                    self.processes[service_name] = process
                    time.sleep(1)  # Give services time to start
                else:
                    print(f"⚠️  Continuing without {config['name']}")
        
        return len(self.processes) > 0
    
    def monitor_services(self):
        """Monitor running services"""
        print("\n📊 Service Status:")
        print("-" * 40)
        
        for service_name, process in self.processes.items():
            config = self.services[service_name]
            
            if process.poll() is None:  # Process is running
                health_status = "✅ Healthy" if self.check_service_health(service_name, config) else "⚠️  Starting"
                print(f"{config['name']:<25} | Port {config['port']:<5} | {health_status}")
            else:
                print(f"{config['name']:<25} | Port {config['port']:<5} | ❌ Stopped")
    
    def show_service_info(self):
        """Show information about running services"""
        print("\n🌐 Available Services:")
        print("-" * 40)
        
        for service_name, config in self.services.items():
            if service_name in self.processes:
                print(f"🔗 {config['name']}")
                print(f"   URL: http://localhost:{config['port']}")
                print(f"   Description: {config['description']}")
                print()
    
    def show_endpoints(self):
        """Show available endpoints"""
        print("📋 Available Endpoints:")
        print("-" * 40)
        
        print("🔍 Logging Server (Port 5000):")
        print("   GET  /health - Health check")
        print("   GET  /stats - Statistics")
        print("   GET  /logs - Retrieve logs")
        print("   POST /log - Ingest logs")
        print()
        
        print("🍯 Fake Git Repository (Port 8001):")
        print("   GET  / - Repository info")
        print("   POST /repo/push - Git push")
        print("   POST /repo/pull - Git pull")
        print("   GET  /.env - Environment file")
        print("   GET  /secrets.yml - Secrets file")
        print()
        
        print("🚀 Fake CI/CD Runner (Port 8002):")
        print("   GET  / - CI/CD dashboard")
        print("   POST /ci/run - Execute job")
        print("   GET  /ci/status - Job status")
        print("   GET  /ci/logs/<job_id> - Job logs")
        print("   GET  /ci/credentials - Credentials")
        print()
        
        print("🍯 Consolidated Honeypot (Port 8000):")
        print("   GET  / - Service info")
        print("   GET  /health - Health check")
        print("   All Git & CI/CD endpoints combined")
        print()
    
    def run_tests(self):
        """Run basic connectivity tests"""
        print("🧪 Running Connectivity Tests...")
        print("-" * 40)
        
        test_results = {}
        
        for service_name, config in self.services.items():
            if service_name in self.processes:
                try:
                    response = requests.get(f"http://localhost:{config['port']}/health", timeout=5)
                    if response.status_code == 200:
                        test_results[service_name] = "✅ PASS"
                    else:
                        test_results[service_name] = f"❌ FAIL (Status: {response.status_code})"
                except Exception as e:
                    test_results[service_name] = f"❌ FAIL ({str(e)[:30]}...)"
            else:
                test_results[service_name] = "⚠️  SKIP (Not running)"
        
        for service_name, result in test_results.items():
            config = self.services[service_name]
            print(f"{config['name']:<25} | {result}")
    
    def stop_all_services(self):
        """Stop all running services"""
        print("\n🛑 Stopping all services...")
        
        for service_name, process in self.processes.items():
            config = self.services[service_name]
            try:
                process.terminate()
                process.wait(timeout=5)
                print(f"✅ {config['name']} stopped")
            except subprocess.TimeoutExpired:
                process.kill()
                print(f"🔨 {config['name']} force killed")
            except Exception as e:
                print(f"❌ Error stopping {config['name']}: {e}")
        
        self.processes.clear()
        print("🏁 All services stopped")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.running = False
        self.stop_all_services()
        sys.exit(0)
    
    def run(self):
        """Main execution loop"""
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Start all services
            if not self.start_all_services():
                print("❌ Failed to start any services")
                return
            
            # Show service information
            self.monitor_services()
            self.show_service_info()
            self.show_endpoints()
            
            # Run tests
            time.sleep(3)  # Give services time to fully start
            self.run_tests()
            
            print("\n" + "=" * 60)
            print("🎉 Unified Honeypot System is running!")
            print("💡 Press Ctrl+C to stop all services")
            print("📊 Monitor logs in real-time")
            print("🔍 Check http://localhost:5000/stats for analytics")
            print("=" * 60)
            
            # Keep running until interrupted
            while self.running:
                time.sleep(10)
                
                # Check if any services have died
                dead_services = []
                for service_name, process in self.processes.items():
                    if process.poll() is not None:
                        dead_services.append(service_name)
                
                if dead_services:
                    print(f"\n⚠️  Services stopped unexpectedly: {', '.join(dead_services)}")
                    for service_name in dead_services:
                        del self.processes[service_name]
                
                # Show periodic status
                if len(self.processes) > 0:
                    print(f"\n⏰ {datetime.now().strftime('%H:%M:%S')} - {len(self.processes)} services running")
        
        except KeyboardInterrupt:
            print("\n🛑 Shutdown requested by user")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
        finally:
            self.stop_all_services()

def main():
    """Main entry point"""
    manager = HoneypotManager()
    manager.run()

if __name__ == "__main__":
    main()
