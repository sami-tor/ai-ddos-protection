import numpy as np
from typing import Dict, List
import logging

class DDoSDetector:
    def __init__(self):
        self.logger = logging.getLogger('DDoSDetector')
        self.pattern_history: Dict[str, List[float]] = {}
        
    def is_attack_pattern(self, traffic_data: dict) -> bool:
        """
        Analyze traffic patterns using multiple indicators:
        1. Request frequency analysis
        2. Payload size patterns
        3. Request timing patterns
        4. Statistical anomaly detection
        """
        indicators = [
            self._analyze_request_frequency(traffic_data),
            self._analyze_payload_patterns(traffic_data),
            self._analyze_timing_patterns(traffic_data),
            self._detect_statistical_anomalies(traffic_data)
        ]
        
        # Weight and combine indicators
        weights = [0.3, 0.2, 0.25, 0.25]
        weighted_score = sum(i * w for i, w in zip(indicators, weights))
        
        return weighted_score > 0.7  # Threshold for attack classification
    
    def _analyze_request_frequency(self, data: dict) -> float:
        """Analyze the frequency of requests"""
        if not data.get('requests'):
            return 0.0
            
        # Calculate requests per second
        timestamps = data['requests']
        if len(timestamps) < 2:
            return 0.0
            
        freq = len(timestamps) / (max(timestamps) - min(timestamps))
        return min(freq / 100.0, 1.0)  # Normalize to [0,1]
    
    def _analyze_payload_patterns(self, data: dict) -> float:
        """Analyze patterns in request payloads"""
        bytes_transferred = data.get('bytes_transferred', 0)
        num_requests = len(data.get('requests', []))
        
        if num_requests == 0:
            return 0.0
            
        # Analyze average bytes per request
        avg_bytes = bytes_transferred / num_requests
        return 1.0 if avg_bytes < 100 else 0.0  # Small payloads might indicate DDoS
    
    def _analyze_timing_patterns(self, data: dict) -> float:
        """Analyze patterns in request timing"""
        timestamps = data.get('requests', [])
        if len(timestamps) < 3:
            return 0.0
            
        # Calculate intervals between requests
        intervals = np.diff(timestamps)
        
        # Check for suspiciously regular patterns
        std_dev = np.std(intervals)
        if std_dev < 0.1:  # Very regular intervals might indicate automated attack
            return 1.0
        return 0.0
    
    def _detect_statistical_anomalies(self, data: dict) -> float:
        """Detect statistical anomalies in traffic patterns"""
        timestamps = data.get('requests', [])
        if len(timestamps) < 10:
            return 0.0
            
        # Use Z-score for anomaly detection
        z_scores = np.abs(self._calculate_z_scores(timestamps))
        return float(np.mean(z_scores > 2.0))  # Proportion of anomalous points
    
    def _calculate_z_scores(self, values: List[float]) -> np.ndarray:
        """Calculate Z-scores for anomaly detection"""
        mean = np.mean(values)
        std = np.std(values)
        if std == 0:
            return np.zeros_like(values)
        return (values - mean) / std