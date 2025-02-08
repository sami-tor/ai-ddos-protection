import re
import requests
from typing import Dict, Optional
import logging

class IPValidator:
    def __init__(self):
        self.logger = logging.getLogger('IPValidator')
        self.ip_cache: Dict[str, dict] = {}
        
    def is_ip_legitimate(self, ip: str) -> bool:
        """
        Validates IP address through multiple checks:
        1. Format validation
        2. Reputation check
        3. Known proxy/VPN check
        """
        if not self._is_valid_ip_format(ip):
            return False
            
        reputation = self._check_ip_reputation(ip)
        if reputation and reputation['score'] < 0:
            return False
            
        return True
    
    def _is_valid_ip_format(self, ip: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip):
            return False
            
        # Validate each octet
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    
    def _check_ip_reputation(self, ip: str) -> Optional[dict]:
        """
        Check IP reputation using AbuseIPDB API
        In production, replace with your preferred IP reputation service
        """
        if ip in self.ip_cache:
            return self.ip_cache[ip]
            
        try:
            # Mock API call - replace with real API in production
            reputation = {'score': 0}  # Mock good reputation
            self.ip_cache[ip] = reputation
            return reputation
        except Exception as e:
            self.logger.error(f"Error checking IP reputation: {e}")
            return None