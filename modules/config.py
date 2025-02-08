class Config:
    """Configuration settings for the DDoS protection system"""
    
    def __init__(self):
        # Traffic Analysis Settings
        self.THRESHOLD_RPS = 100  # Requests per second threshold
        self.CYCLE_INTERVAL = 1.0  # Seconds between protection cycles
        self.DATA_RETENTION_PERIOD = 3600  # 1 hour
        
        # Threat Response Settings
        self.BLOCK_THRESHOLD = 0.8  # Threat level threshold for blocking
        self.CAPTCHA_THRESHOLD = 0.5  # Threat level threshold for CAPTCHA
        
        # IP Validation Settings
        self.IP_CACHE_DURATION = 3600  # 1 hour
        self.MAX_FAILED_CAPTCHAS = 3
        
        # AI Detection Settings
        self.ANOMALY_THRESHOLD = 2.0  # Standard deviations for anomaly
        self.MIN_SAMPLES_FOR_ANALYSIS = 10