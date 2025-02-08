# AI-Based DDoS Protection System
![DDoS Protection System](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=2070)
An intelligent DDoS (Distributed Denial of Service) protection system that uses AI/ML techniques to detect and mitigate potential attacks. The system employs multiple layers of protection including traffic analysis, IP reputation checking, custom CAPTCHA challenges, and machine learning-based pattern detection.

## Features

- **Real-time Traffic Monitoring**: Continuously monitors network traffic patterns
- **AI-Powered Detection**: Uses statistical analysis and machine learning to identify attack patterns
- **Custom CAPTCHA System**: Implements a dynamic math-based CAPTCHA challenge
- **IP Reputation Checking**: Validates IPs against known threat databases
- **Progressive Response**: Escalates protection measures based on threat level
- **Detailed Logging**: Separate log files for different types of events
- **Modular Architecture**: Easy to extend and customize for specific needs

## Log Categories

The system maintains separate log files for different types of events:

- `logs/traffic/`: Daily traffic patterns and statistics
- `logs/threats/`: Detected potential threats and attacks
- `logs/blocks/`: IP blocking events and reasons
- `logs/captcha/`: CAPTCHA challenges and responses
- `logs/system/`: System startup, shutdown, and errors
- `logs/access/`: Detailed access logs for each request

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-ddos-protection.git

# Navigate to the project directory
cd ai-ddos-protection

# Install required dependencies
pip install -r requirements.txt
pip install numpy requests
```

## Usage

```python
# Run the protection system
python main.py
```

## Configuration

Edit `modules/config.py` to customize the protection parameters:

- `THRESHOLD_RPS`: Maximum allowed requests per second
- `BLOCK_THRESHOLD`: Threat level threshold for IP blocking
- `CAPTCHA_THRESHOLD`: Threshold for CAPTCHA challenges
- `DATA_RETENTION_PERIOD`: How long to keep traffic history

## Log Format

Each log entry follows this format:
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message
```

Access logs include additional details:
```
[YYYY-MM-DD HH:MM:SS] [INFO] IP: x.x.x.x | METHOD /endpoint | Status: 200 | UA: User-Agent
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is a proof-of-concept implementation. For production use, additional security measures and testing are recommended. The system requires appropriate permissions and access to network interfaces to function properly.
