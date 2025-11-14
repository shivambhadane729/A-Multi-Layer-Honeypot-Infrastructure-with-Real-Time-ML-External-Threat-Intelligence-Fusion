#!/usr/bin/env python3
"""
Real-time Machine Learning Prediction System for Honeypot
Integrates trained models with honeypot system for live attack detection
"""

import pandas as pd
import numpy as np
import joblib
import json
import requests
from datetime import datetime
import logging
from typing import Dict, Any, Optional, Tuple
import os

class HoneypotMLPredictor:
    def __init__(self, models_path="ml_models/"):
        self.models_path = models_path
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_selector = None
        self.best_model = None
        self.feature_columns = []
        self.model_info = {}
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ml_prediction.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Load models and preprocessing objects
        self.load_models()
    
    def load_models(self):
        """Load trained models and preprocessing objects"""
        try:
            print("🤖 Loading trained models...")
            
            # Load best model info
            with open(os.path.join(self.models_path, 'best_model_info.json'), 'r') as f:
                self.model_info = json.load(f)
            
            self.best_model_name = self.model_info['name']
            self.feature_columns = self.model_info['feature_columns']
            
            # Load best model
            best_model_path = os.path.join(self.models_path, f"{self.best_model_name.lower()}_model.pkl")
            self.best_model = joblib.load(best_model_path)
            
            # Load scalers
            for scaler_name in ['standard', 'minmax']:
                scaler_path = os.path.join(self.models_path, f"{scaler_name}_scaler.pkl")
                if os.path.exists(scaler_path):
                    self.scalers[scaler_name] = joblib.load(scaler_path)
            
            # Load encoders
            for encoder_name in ['proto', 'service', 'state']:
                encoder_path = os.path.join(self.models_path, f"{encoder_name}_encoder.pkl")
                if os.path.exists(encoder_path):
                    self.encoders[encoder_name] = joblib.load(encoder_path)
            
            # Load feature selector
            feature_selector_path = os.path.join(self.models_path, 'feature_selector.pkl')
            if os.path.exists(feature_selector_path):
                self.feature_selector = joblib.load(feature_selector_path)
            
            print(f"✅ Models loaded successfully!")
            print(f"   Best model: {self.best_model_name}")
            print(f"   Accuracy: {self.model_info['accuracy']:.4f}")
            print(f"   Features: {len(self.feature_columns)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def preprocess_honeypot_data(self, log_data: Dict[str, Any]) -> Optional[pd.DataFrame]:
        """Preprocess honeypot log data for ML prediction"""
        try:
            # Create a DataFrame from log data
            # Map honeypot data to UNSW-NB15 features
            processed_data = {}
            
            # Basic network features (simplified mapping)
            processed_data['dur'] = 0.1  # Default duration
            processed_data['proto'] = self._encode_protocol(log_data.get('protocol', 'HTTP'))
            processed_data['service'] = self._encode_service(log_data.get('target_service', 'Unknown'))
            processed_data['state'] = self._encode_state('ESTABLISHED')  # Default state
            
            # Packet and byte features (simulated based on request)
            processed_data['spkts'] = 10  # Source packets
            processed_data['dpkts'] = 5   # Destination packets
            processed_data['sbytes'] = len(str(log_data.get('payload', {}))) * 10
            processed_data['dbytes'] = len(str(log_data.get('headers', {}))) * 5
            
            # Rate and timing features
            processed_data['rate'] = 100.0  # Default rate
            processed_data['sttl'] = 64     # Source TTL
            processed_data['dttl'] = 64     # Destination TTL
            
            # Load features
            processed_data['sload'] = processed_data['sbytes'] / processed_data['dur']
            processed_data['dload'] = processed_data['dbytes'] / processed_data['dur']
            
            # Loss features
            processed_data['sloss'] = 0
            processed_data['dloss'] = 0
            
            # Packet timing
            processed_data['sinpkt'] = processed_data['dur'] / processed_data['spkts']
            processed_data['dinpkt'] = processed_data['dur'] / processed_data['dpkts']
            
            # Jitter (simulated)
            processed_data['sjit'] = 0.001
            processed_data['djit'] = 0.001
            
            # Window sizes
            processed_data['swin'] = 65535
            processed_data['dwin'] = 65535
            
            # TCP features
            processed_data['stcpb'] = 0
            processed_data['dtcpb'] = 0
            processed_data['tcprtt'] = 0.01
            processed_data['synack'] = 0.01
            processed_data['ackdat'] = 0.01
            
            # Statistical features
            processed_data['smean'] = processed_data['sbytes'] / processed_data['spkts']
            processed_data['dmean'] = processed_data['dbytes'] / processed_data['dpkts']
            
            # Connection features
            processed_data['trans_depth'] = 1
            processed_data['response_body_len'] = processed_data['dbytes']
            
            # Connection tracking features
            processed_data['ct_srv_src'] = 1
            processed_data['ct_state_ttl'] = 1
            processed_data['ct_dst_ltm'] = 1
            processed_data['ct_src_dport_ltm'] = 1
            processed_data['ct_dst_sport_ltm'] = 1
            processed_data['ct_dst_src_ltm'] = 1
            
            # Protocol-specific features
            processed_data['is_ftp_login'] = 0
            processed_data['ct_ftp_cmd'] = 0
            processed_data['ct_flw_http_mthd'] = 0
            processed_data['ct_src_ltm'] = 1
            processed_data['ct_srv_dst'] = 1
            processed_data['is_sm_ips_ports'] = 0
            
            # Create DataFrame
            df = pd.DataFrame([processed_data])
            
            # Ensure all required features are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0  # Default value for missing features
            
            # Reorder columns to match training data
            df = df[self.feature_columns]
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error preprocessing honeypot data: {e}")
            return None
    
    def _encode_protocol(self, protocol: str) -> int:
        """Encode protocol string to numeric value"""
        protocol_mapping = {
            'HTTP': 0, 'HTTPS': 0, 'TCP': 0,
            'UDP': 1,
            'ICMP': 2,
            'FTP': 3,
            'SSH': 4,
            'TELNET': 5
        }
        return protocol_mapping.get(protocol.upper(), 0)
    
    def _encode_service(self, service: str) -> int:
        """Encode service string to numeric value"""
        service_mapping = {
            'Fake Git Repository': 0,
            'Fake CI/CD Runner': 1,
            'Consolidated Honeypot Services': 2,
            'Unknown': 3
        }
        return service_mapping.get(service, 3)
    
    def _encode_state(self, state: str) -> int:
        """Encode connection state to numeric value"""
        state_mapping = {
            'ESTABLISHED': 0,
            'FIN': 1,
            'CON': 2,
            'REQ': 3,
            'RST': 4
        }
        return state_mapping.get(state.upper(), 0)
    
    def predict_attack(self, log_data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Predict if log data represents an attack"""
        try:
            # Preprocess the data
            processed_data = self.preprocess_honeypot_data(log_data)
            
            if processed_data is None:
                return False, 0.0, {'error': 'Failed to preprocess data'}
            
            # Scale the data
            if 'standard' in self.scalers:
                processed_data = self.scalers['standard'].transform(processed_data)
            
            # Make prediction
            prediction = self.best_model.predict(processed_data)[0]
            probability = self.best_model.predict_proba(processed_data)[0][1] if hasattr(self.best_model, 'predict_proba') else 0.5
            
            # Prepare result
            result = {
                'prediction': bool(prediction),
                'probability': float(probability),
                'model_used': self.best_model_name,
                'model_accuracy': self.model_info['accuracy'],
                'timestamp': datetime.now().isoformat(),
                'source_ip': log_data.get('source_ip', 'Unknown'),
                'action': log_data.get('action', 'Unknown'),
                'target_service': log_data.get('target_service', 'Unknown')
            }
            
            self.logger.info(f"Prediction: {prediction}, Probability: {probability:.4f}, IP: {log_data.get('source_ip', 'Unknown')}")
            
            return bool(prediction), float(probability), result
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return False, 0.0, {'error': str(e)}
    
    def analyze_attack_patterns(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack patterns and provide insights"""
        try:
            is_attack, probability, prediction_result = self.predict_attack(log_data)
            
            # Additional analysis based on log data
            analysis = {
                'is_attack': is_attack,
                'attack_probability': probability,
                'risk_level': self._calculate_risk_level(probability),
                'attack_indicators': self._identify_attack_indicators(log_data),
                'recommended_actions': self._get_recommended_actions(log_data, is_attack, probability),
                'prediction_details': prediction_result
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing attack patterns: {e}")
            return {'error': str(e)}
    
    def _calculate_risk_level(self, probability: float) -> str:
        """Calculate risk level based on attack probability"""
        if probability >= 0.8:
            return "HIGH"
        elif probability >= 0.6:
            return "MEDIUM"
        elif probability >= 0.4:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _identify_attack_indicators(self, log_data: Dict[str, Any]) -> list:
        """Identify potential attack indicators"""
        indicators = []
        
        # Check for suspicious actions
        suspicious_actions = ['file_access', 'ci_credentials_access', 'git_push']
        if log_data.get('action') in suspicious_actions:
            indicators.append(f"Suspicious action: {log_data.get('action')}")
        
        # Check for sensitive file access
        sensitive_files = ['.env', 'secrets.yml', 'config.json', 'credentials']
        target_file = log_data.get('target_file', '')
        if any(file in target_file for file in sensitive_files):
            indicators.append(f"Sensitive file access: {target_file}")
        
        # Check for suspicious payloads
        payload = log_data.get('payload', {})
        if isinstance(payload, dict):
            if 'commit_message' in payload and any(word in str(payload['commit_message']).lower() 
                                                 for word in ['backdoor', 'malicious', 'exploit']):
                indicators.append("Suspicious commit message")
            
            if 'job_name' in payload and any(word in str(payload['job_name']).lower() 
                                           for word in ['malicious', 'exploit', 'backdoor']):
                indicators.append("Suspicious job name")
        
        # Check user agent
        user_agent = log_data.get('user_agent', '').lower()
        if any(term in user_agent for term in ['curl', 'wget', 'python-requests']):
            indicators.append("Automated tool usage")
        
        return indicators
    
    def _get_recommended_actions(self, log_data: Dict[str, Any], is_attack: bool, probability: float) -> list:
        """Get recommended actions based on analysis"""
        actions = []
        
        if is_attack and probability >= 0.8:
            actions.extend([
                "BLOCK source IP address",
                "Alert security team immediately",
                "Review and analyze attack payload",
                "Check for data exfiltration",
                "Update firewall rules"
            ])
        elif is_attack and probability >= 0.6:
            actions.extend([
                "Monitor source IP address closely",
                "Log detailed activity",
                "Consider temporary blocking",
                "Investigate attack patterns"
            ])
        elif probability >= 0.4:
            actions.extend([
                "Increase monitoring for this IP",
                "Log additional details",
                "Review access patterns"
            ])
        else:
            actions.append("Continue normal monitoring")
        
        return actions
    
    def send_alert(self, analysis: Dict[str, Any], webhook_url: str = None):
        """Send alert based on analysis results"""
        try:
            if analysis.get('is_attack') and analysis.get('attack_probability', 0) >= 0.7:
                alert_data = {
                    'timestamp': datetime.now().isoformat(),
                    'alert_type': 'ATTACK_DETECTED',
                    'risk_level': analysis.get('risk_level', 'UNKNOWN'),
                    'attack_probability': analysis.get('attack_probability', 0),
                    'source_ip': analysis.get('prediction_details', {}).get('source_ip', 'Unknown'),
                    'target_service': analysis.get('prediction_details', {}).get('target_service', 'Unknown'),
                    'action': analysis.get('prediction_details', {}).get('action', 'Unknown'),
                    'attack_indicators': analysis.get('attack_indicators', []),
                    'recommended_actions': analysis.get('recommended_actions', []),
                    'model_info': {
                        'model_name': analysis.get('prediction_details', {}).get('model_used', 'Unknown'),
                        'model_accuracy': analysis.get('prediction_details', {}).get('model_accuracy', 0)
                    }
                }
                
                # Log alert
                self.logger.warning(f"ATTACK ALERT: {alert_data}")
                
                # Send to webhook if provided
                if webhook_url:
                    try:
                        response = requests.post(webhook_url, json=alert_data, timeout=5)
                        if response.status_code == 200:
                            self.logger.info("Alert sent to webhook successfully")
                        else:
                            self.logger.error(f"Failed to send alert to webhook: {response.status_code}")
                    except Exception as e:
                        self.logger.error(f"Error sending alert to webhook: {e}")
                
                return alert_data
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
        
        return None

def main():
    """Main entry point for testing"""
    print("🤖 Honeypot ML Prediction System")
    print("=" * 50)
    
    # Initialize predictor
    predictor = HoneypotMLPredictor()
    
    # Test with sample honeypot log data
    sample_log = {
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
    
    print("Testing with sample log data...")
    print(f"Sample log: {sample_log}")
    
    # Make prediction
    is_attack, probability, result = predictor.predict_attack(sample_log)
    print(f"\nPrediction Result:")
    print(f"  Is Attack: {is_attack}")
    print(f"  Probability: {probability:.4f}")
    print(f"  Details: {result}")
    
    # Analyze attack patterns
    analysis = predictor.analyze_attack_patterns(sample_log)
    print(f"\nAttack Analysis:")
    print(f"  Risk Level: {analysis.get('risk_level', 'Unknown')}")
    print(f"  Indicators: {analysis.get('attack_indicators', [])}")
    print(f"  Recommended Actions: {analysis.get('recommended_actions', [])}")
    
    # Send alert if needed
    alert = predictor.send_alert(analysis)
    if alert:
        print(f"\nAlert Generated: {alert}")

if __name__ == "__main__":
    main()

