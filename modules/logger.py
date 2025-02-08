import os
import time
from datetime import datetime

class Logger:
    def __init__(self):
        self.log_dir = "logs"
        self._ensure_log_directory()
        
    def _ensure_log_directory(self):
        """Create log directory and subdirectories if they don't exist"""
        subdirs = ["traffic", "threats", "blocks", "captcha", "system", "access"]
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        for subdir in subdirs:
            subdir_path = os.path.join(self.log_dir, subdir)
            if not os.path.exists(subdir_path):
                os.makedirs(subdir_path)
    
    def _get_log_file(self, category):
        """Get the appropriate log file path for the current day"""
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, category, f"{today}.log")
    
    def _write_log(self, category, level, message):
        """Write a log entry to the appropriate file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        with open(self._get_log_file(category), 'a') as f:
            f.write(log_entry)
    
    def info(self, category, message):
        """Log an info message"""
        self._write_log(category, "INFO", message)
    
    def warning(self, category, message):
        """Log a warning message"""
        self._write_log(category, "WARNING", message)
    
    def error(self, category, message):
        """Log an error message"""
        self._write_log(category, "ERROR", message)
    
    def log_access(self, ip, endpoint, method, status_code, user_agent):
        """Log an access attempt"""
        message = f"IP: {ip} | {method} {endpoint} | Status: {status_code} | UA: {user_agent}"
        self._write_log("access", "INFO", message)