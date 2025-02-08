import time
from collections import defaultdict
import socket
import psutil
import os
import requests
from win32com.shell import shell
from scapy.all import *
import threading
import queue

class TrafficAnalyzer:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.traffic_history = defaultdict(lambda: {
            'requests': [],
            'bytes_transferred': 0,
            'last_seen': 0,
            'blocked': False,
            'endpoints': [],
            'user_agents': set(),
            'methods': defaultdict(int),
            'status_codes': defaultdict(int),
            'threat_level': 0.0,
            'requests_per_second': 0,
            'protocols': defaultdict(int),
            'ports': set(),
            'packet_sizes': [],
            'tcp_flags': defaultdict(int)
        })
        self.packet_queue = queue.Queue()
        self.public_ip = self._get_public_ip()
        self._print_system_info()
        self._start_packet_capture()
        
    def _get_public_ip(self):
        """Get the public IP address of the system"""
        try:
            response = requests.get('https://api.ipify.org?format=json')
            if response.status_code == 200:
                public_ip = response.json()['ip']
                return public_ip
        except Exception as e:
            self.logger.error("system", f"Failed to get public IP: {str(e)}")
            return None
    
    def _print_system_info(self):
        """Display system network information"""
        print("\n=== System Information ===")
        if self.public_ip:
            print(f"Public IP: {self.public_ip}")
        else:
            print("Could not determine public IP")
            
        print("\nMonitoring ALL network traffic...\n")
    
    def _packet_callback(self, packet):
        """Callback function for packet capture"""
        try:
            self.packet_queue.put(packet)
        except Exception as e:
            self.logger.error("system", f"Error in packet callback: {str(e)}")
    
    def _start_packet_capture(self):
        """Start capturing all network packets"""
        def capture_thread():
            try:
                sniff(prn=self._packet_callback, store=0)
            except Exception as e:
                self.logger.error("system", f"Error starting packet capture: {str(e)}")
        
        # Start capture in a separate thread
        threading.Thread(target=capture_thread, daemon=True).start()
        self.logger.info("system", "Started packet capture")
    
    def _analyze_packet(self, packet):
        """Analyze a single packet"""
        try:
            # Extract IP information
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                
                # Update traffic data for both source and destination
                for ip in [ip_src, ip_dst]:
                    data = self.traffic_history[ip]
                    data['protocols'][protocol] += 1
                    data['packet_sizes'].append(len(packet))
                    data['last_seen'] = time.time()
                    
                    # TCP specific analysis
                    if TCP in packet:
                        data['ports'].add(packet[TCP].sport)
                        data['ports'].add(packet[TCP].dport)
                        data['tcp_flags'][packet[TCP].flags] += 1
                        
                        # HTTP detection
                        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            if Raw in packet:
                                payload = packet[Raw].load.decode('utf-8', 'ignore')
                                if any(method in payload for method in ['GET', 'POST', 'PUT', 'DELETE']):
                                    self._process_http_request(ip, payload)
                    
                    # Update bytes transferred
                    data['bytes_transferred'] += len(packet)
                    
                    # Log packet
                    self.logger.info("traffic", 
                        f"Packet: {ip_src} -> {ip_dst} | "
                        f"Protocol: {protocol} | "
                        f"Size: {len(packet)} bytes")
                    
        except Exception as e:
            self.logger.error("system", f"Error analyzing packet: {str(e)}")
    
    def _process_http_request(self, ip, payload):
        """Process HTTP request data"""
        try:
            # Extract HTTP method and endpoint
            lines = payload.split('\n')
            if lines:
                request_line = lines[0].strip()
                parts = request_line.split()
                if len(parts) >= 2:
                    method = parts[0]
                    endpoint = parts[1]
                    
                    # Extract User-Agent
                    user_agent = "Unknown"
                    for line in lines:
                        if line.startswith("User-Agent:"):
                            user_agent = line.split(":", 1)[1].strip()
                            break
                    
                    self.log_request(ip, endpoint, method, len(payload), 200, user_agent)
                    
        except Exception as e:
            self.logger.error("system", f"Error processing HTTP request: {str(e)}")
    
    def get_traffic_data(self):
        """Process queued packets and return traffic data"""
        current_time = time.time()
        
        # Process all queued packets
        while not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                self._analyze_packet(packet)
            except queue.Empty:
                break
            except Exception as e:
                self.logger.error("system", f"Error processing packet: {str(e)}")
        
        self._clean_old_data(current_time)
        return self.traffic_history
    
    def log_request(self, ip, endpoint, method, bytes_transferred, status_code, user_agent):
        """Log a new request from an IP"""
        current_time = time.time()
        data = self.traffic_history[ip]
        
        # Update traffic data
        data['requests'].append(current_time)
        data['bytes_transferred'] += bytes_transferred
        data['last_seen'] = current_time
        data['endpoints'].append(endpoint)
        data['user_agents'].add(user_agent)
        data['methods'][method] += 1
        data['status_codes'][status_code] += 1
        
        # Calculate requests per second
        recent_requests = [r for r in data['requests'] if r > current_time - 1]
        data['requests_per_second'] = len(recent_requests)
        
        # Log the access
        self.logger.log_access(ip, endpoint, method, status_code, user_agent)
        
        # Log suspicious activity
        if data['requests_per_second'] > self.config.THRESHOLD_RPS:
            self.logger.warning("traffic", 
                f"High traffic from {ip}: {data['requests_per_second']} req/s | "
                f"Endpoint: {endpoint} | Method: {method} | "
                f"Bytes: {bytes_transferred}")
    
    def _clean_old_data(self, current_time):
        """Remove old traffic data beyond retention period"""
        cleanup_threshold = current_time - self.config.DATA_RETENTION_PERIOD
        for ip in list(self.traffic_history.keys()):
            data = self.traffic_history[ip]
            data['requests'] = [
                req for req in data['requests']
                if req > cleanup_threshold
            ]
            
            # Log cleanup
            if len(data['requests']) == 0:
                self.logger.info("traffic", f"Cleaned up traffic data for IP: {ip}")
                del self.traffic_history[ip]
    
    def block_ip(self, ip):
        """Block an IP address using Windows Firewall"""
        try:
            # Check for admin privileges
            if not shell.IsUserAnAdmin():
                self.logger.error("system", "Administrator privileges required to block IPs")
                return
            
            # Add Windows Firewall rule to block the IP
            rule_name = f"DDoS_Protection_Block_{ip}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            
            result = os.system(command)
            if result == 0:
                self.traffic_history[ip]['blocked'] = True
                self.logger.warning("blocks", 
                    f"IP {ip} has been blocked | "
                    f"Total Requests: {len(self.traffic_history[ip]['requests'])} | "
                    f"Unique Endpoints: {len(set(self.traffic_history[ip]['endpoints']))} | "
                    f"User Agents: {len(self.traffic_history[ip]['user_agents'])}")
            else:
                self.logger.error("system", f"Failed to add firewall rule for IP {ip}")
                
        except Exception as e:
            self.logger.error("system", f"Failed to block IP {ip}: {str(e)}")