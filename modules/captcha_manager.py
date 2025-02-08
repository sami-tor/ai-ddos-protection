import time
import random
import string
from typing import Dict
import logging

class CaptchaManager:
    def __init__(self):
        self.logger = logging.getLogger('CaptchaManager')
        self.captcha_history: Dict[str, dict] = {}
        
    def should_show_captcha(self, ip: str) -> bool:
        """Determine if we should show a captcha to this IP"""
        if ip not in self.captcha_history:
            return True
            
        last_captcha = self.captcha_history[ip]
        if time.time() - last_captcha['timestamp'] > 3600:  # 1 hour
            return True
            
        if last_captcha['failures'] >= 3:
            return False  # Too many failures, block instead
            
        return False
    
    def request_captcha(self, ip: str) -> dict:
        """Generate and store a new captcha challenge"""
        challenge = self._generate_challenge()
        self.captcha_history[ip] = {
            'challenge': challenge,
            'timestamp': time.time(),
            'failures': 0
        }
        return challenge
    
    def _generate_challenge(self) -> dict:
        """Generate a custom captcha challenge"""
        operations = ['+', '-', '*']
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        operation = random.choice(operations)
        
        if operation == '+':
            answer = num1 + num2
        elif operation == '-':
            answer = num1 - num2
        else:
            answer = num1 * num2
            
        question = f"What is {num1} {operation} {num2}?"
        return {
            'question': question,
            'answer': answer,
            'type': 'math'
        }