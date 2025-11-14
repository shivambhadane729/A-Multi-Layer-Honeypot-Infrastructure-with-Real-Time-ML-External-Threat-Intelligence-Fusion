#!/usr/bin/env python3
"""
Machine Learning Integration with Honeypot System
Real-time attack detection and alerting using trained ML models
"""

import requests
import json
import time
import threading
from datetime import datetime
import logging
from ml_prediction_system import HoneypotMLPredictor

class MLHoneypotIntegration:
    def __init__(self, 
                 logging_server_url="http://localhost:5000",
                 prediction_threshold=0.6,
                 webhook_url=None):
        self.logging_server_url = logging_server_url
        self.prediction_threshold = prediction_threshold
        self.webhook_url = webhook_url
        
        # Initialize ML predictor
        self.ml_predictor = HoneypotMLPredictor()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ml_honeypot_integration.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_logs_processed': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'alerts_sent': 0,
            'start_time': datetime.now()
        }
        
        # Running flag
        self.running = False
    
    def fetch_recent_logs(self, limit=10):
        """Fetch recent logs from the logging server"""
        try:
            response = requests.get(
                f"{self.logging_server_url}/logs",
                params={'per_page': limit, 'page': 1},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('logs', [])
            else:
                self.logger.error(f"Failed to fetch logs: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error fetching logs: {e}")
            return []
    
    def process_log(self, log_data):
        """Process a single log entry with ML prediction"""
        try:
            self.stats['total_logs_processed'] += 1
            
            # Analyze with ML model
            analysis = self.ml_predictor.analyze_attack_patterns(log_data)
            
            if analysis.get('error'):
                self.logger.error(f"ML analysis error: {analysis['error']}")
                return
            
            # Check if attack is detected
            is_attack = analysis.get('is_attack', False)
            probability = analysis.get('attack_probability', 0)
            
            if is_attack and probability >= self.prediction_threshold:
                self.stats['attacks_detected'] += 1
                
                # Log attack detection
                self.logger.warning(f"🚨 ATTACK DETECTED!")
                self.logger.warning(f"   Source IP: {log_data.get('source_ip', 'Unknown')}")
                self.logger.warning(f"   Action: {log_data.get('action', 'Unknown')}")
                self.logger.warning(f"   Probability: {probability:.4f}")
                self.logger.warning(f"   Risk Level: {analysis.get('risk_level', 'Unknown')}")
                
                # Send alert
                alert = self.ml_predictor.send_alert(analysis, self.webhook_url)
                if alert:
                    self.stats['alerts_sent'] += 1
                
                # Log detailed analysis
                self.logger.info(f"Attack Indicators: {analysis.get('attack_indicators', [])}")
                self.logger.info(f"Recommended Actions: {analysis.get('recommended_actions', [])}")
            
            # Log processing info
            if self.stats['total_logs_processed'] % 100 == 0:
                self.logger.info(f"Processed {self.stats['total_logs_processed']} logs, "
                               f"detected {self.stats['attacks_detected']} attacks")
            
        except Exception as e:
            self.logger.error(f"Error processing log: {e}")
    
    def monitor_logs(self):
        """Continuously monitor logs from the honeypot system"""
        self.logger.info("🔍 Starting log monitoring...")
        processed_log_ids = set()
        
        while self.running:
            try:
                # Fetch recent logs
                logs = self.fetch_recent_logs(limit=50)
                
                # Process new logs
                for log in logs:
                    log_id = log.get('id')
                    
                    # Skip if already processed
                    if log_id in processed_log_ids:
                        continue
                    
                    # Process the log
                    self.process_log(log)
                    processed_log_ids.add(log_id)
                
                # Sleep before next check
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait longer on error
    
    def get_statistics(self):
        """Get current statistics"""
        uptime = datetime.now() - self.stats['start_time']
        
        stats = {
            'uptime_seconds': uptime.total_seconds(),
            'uptime_formatted': str(uptime).split('.')[0],
            'total_logs_processed': self.stats['total_logs_processed'],
            'attacks_detected': self.stats['attacks_detected'],
            'alerts_sent': self.stats['alerts_sent'],
            'detection_rate': (self.stats['attacks_detected'] / max(self.stats['total_logs_processed'], 1)) * 100,
            'logs_per_minute': (self.stats['total_logs_processed'] / max(uptime.total_seconds() / 60, 1)),
            'model_info': {
                'model_name': self.ml_predictor.model_info.get('name', 'Unknown'),
                'model_accuracy': self.ml_predictor.model_info.get('accuracy', 0),
                'prediction_threshold': self.prediction_threshold
            }
        }
        
        return stats
    
    def print_statistics(self):
        """Print current statistics"""
        stats = self.get_statistics()
        
        print("\n" + "=" * 60)
        print("📊 ML Honeypot Integration Statistics")
        print("=" * 60)
        print(f"⏱️  Uptime: {stats['uptime_formatted']}")
        print(f"📋 Total Logs Processed: {stats['total_logs_processed']:,}")
        print(f"🚨 Attacks Detected: {stats['attacks_detected']:,}")
        print(f"📢 Alerts Sent: {stats['alerts_sent']:,}")
        print(f"📈 Detection Rate: {stats['detection_rate']:.2f}%")
        print(f"⚡ Logs/Minute: {stats['logs_per_minute']:.1f}")
        print(f"🤖 Model: {stats['model_info']['model_name']}")
        print(f"🎯 Model Accuracy: {stats['model_info']['model_accuracy']:.4f}")
        print(f"🔍 Prediction Threshold: {stats['model_info']['prediction_threshold']}")
        print("=" * 60)
    
    def start_monitoring(self):
        """Start the monitoring process"""
        if self.running:
            self.logger.warning("Monitoring is already running")
            return
        
        self.running = True
        self.logger.info("🚀 Starting ML Honeypot Integration")
        self.logger.info(f"   Logging Server: {self.logging_server_url}")
        self.logger.info(f"   Prediction Threshold: {self.prediction_threshold}")
        self.logger.info(f"   Webhook URL: {self.webhook_url or 'None'}")
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_logs, daemon=True)
        self.monitor_thread.start()
        
        # Start statistics reporting
        self.stats_thread = threading.Thread(target=self._stats_reporter, daemon=True)
        self.stats_thread.start()
        
        self.logger.info("✅ ML Honeypot Integration started successfully")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        if not self.running:
            self.logger.warning("Monitoring is not running")
            return
        
        self.running = False
        self.logger.info("🛑 Stopping ML Honeypot Integration")
        
        # Print final statistics
        self.print_statistics()
        
        self.logger.info("✅ ML Honeypot Integration stopped")
    
    def _stats_reporter(self):
        """Report statistics periodically"""
        while self.running:
            time.sleep(300)  # Report every 5 minutes
            if self.running:
                self.print_statistics()
    
    def test_integration(self):
        """Test the integration with sample data"""
        print("🧪 Testing ML Honeypot Integration...")
        
        # Test with sample attack log
        sample_attack_log = {
            'id': 999999,
            'timestamp': datetime.now().isoformat(),
            'source_ip': '203.0.113.42',
            'protocol': 'HTTP',
            'target_service': 'Fake Git Repository',
            'action': 'file_access',
            'target_file': 'secrets.yml',
            'payload': {
                'file_type': 'yaml_secrets',
                'access_method': 'direct_request'
            },
            'headers': {
                'User-Agent': 'curl/7.68.0',
                'Accept': 'text/yaml'
            },
            'session_id': 'test-session-123',
            'user_agent': 'curl/7.68.0'
        }
        
        print("Testing with sample attack log...")
        self.process_log(sample_attack_log)
        
        # Test with sample normal log
        sample_normal_log = {
            'id': 999998,
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'protocol': 'HTTP',
            'target_service': 'Fake Git Repository',
            'action': 'index_access',
            'target_file': None,
            'payload': {},
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'session_id': 'normal-session-456',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        print("Testing with sample normal log...")
        self.process_log(sample_normal_log)
        
        print("✅ Integration test completed")

def main():
    """Main entry point"""
    print("🤖 ML Honeypot Integration System")
    print("=" * 50)
    
    # Configuration
    LOGGING_SERVER_URL = "http://localhost:5000"
    PREDICTION_THRESHOLD = 0.6
    WEBHOOK_URL = None  # Set to your webhook URL if you have one
    
    # Initialize integration
    integration = MLHoneypotIntegration(
        logging_server_url=LOGGING_SERVER_URL,
        prediction_threshold=PREDICTION_THRESHOLD,
        webhook_url=WEBHOOK_URL
    )
    
    try:
        # Test integration
        integration.test_integration()
        
        # Start monitoring
        integration.start_monitoring()
        
        print("\n💡 ML Honeypot Integration is running!")
        print("   - Monitoring logs from honeypot system")
        print("   - Analyzing with trained ML models")
        print("   - Sending alerts for detected attacks")
        print("   - Press Ctrl+C to stop")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
        integration.stop_monitoring()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        integration.stop_monitoring()

if __name__ == "__main__":
    main()

