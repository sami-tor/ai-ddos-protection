#!/usr/bin/env python3

from modules.traffic_analyzer import TrafficAnalyzer
from modules.ip_validator import IPValidator
from modules.captcha_manager import CaptchaManager
from modules.ai_detector import DDoSDetector
from modules.config import Config
from modules.logger import Logger
import time

class DDOSProtector:
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.traffic_analyzer = TrafficAnalyzer(self.config, self.logger)
        self.ip_validator = IPValidator()
        self.captcha_manager = CaptchaManager()
        self.ddos_detector = DDoSDetector()
        
    def start(self):
        self.logger.info("system", "Starting DDoS Protection System...")
        try:
            while True:
                self._protection_cycle()
                time.sleep(self.config.CYCLE_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("system", "Shutting down DDoS Protection System...")
    
    def _protection_cycle(self):
        # Analyze current traffic
        traffic_data = self.traffic_analyzer.get_traffic_data()
        
        # Check for potential threats
        for ip, data in traffic_data.items():
            if self._is_potential_threat(ip, data):
                self._handle_threat(ip, data)
    
    def _is_potential_threat(self, ip, data):
        # Multiple layers of verification
        if not self.ip_validator.is_ip_legitimate(ip):
            self.logger.warning("threats", f"Illegitimate IP detected: {ip}")
            return True
            
        if self.ddos_detector.is_attack_pattern(data):
            self.logger.warning("threats", f"Attack pattern detected from IP: {ip}")
            return True
            
        if data['requests_per_second'] > self.config.THRESHOLD_RPS:
            self.logger.warning("threats", f"High RPS detected from IP: {ip} - {data['requests_per_second']} req/s")
            return True
            
        return False
    
    def _handle_threat(self, ip, data):
        self.logger.warning("threats", f"Potential DDoS threat detected from IP: {ip}")
        
        # Progressive response
        if self.captcha_manager.should_show_captcha(ip):
            challenge = self.captcha_manager.request_captcha(ip)
            self.logger.info("captcha", f"CAPTCHA challenge issued to IP: {ip} - Challenge: {challenge['question']}")
        
        if data['threat_level'] > self.config.BLOCK_THRESHOLD:
            self.traffic_analyzer.block_ip(ip)
            self.logger.warning("blocks", f"Blocked malicious IP: {ip} - Threat Level: {data['threat_level']}")

if __name__ == "__main__":
    protector = DDOSProtector()
    protector.start()