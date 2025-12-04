# 🛡️ Network Port Anomaly Detector

A comprehensive network traffic anomaly detection system through port analysis.

**Cybersecurity Module 3 Project**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📋 Project Overview

Network Port Anomaly Detector is a comprehensive system for detecting anomalies and potential threats in network traffic. It utilizes advanced analysis methods including statistical algorithms, machine learning, heuristic rules, and temporal analysis.

### Key Features

- ✅ **Multi-source Data Analysis**
  - PCAP file analysis
  - Real-time traffic capture (live capture)
  - Network traffic simulator for testing

- ✅ **Advanced Detection Methods**
  - **Statistical Detection** - anomaly detection based on standard deviations and frequency
  - **Machine Learning** - Isolation Forest and One-Class SVM
  - **Heuristic Rules** - port scanning, DDoS, SYN flood detection
  - **Temporal Analysis** - rate limiting, burst detection, beaconing detection

- ✅ **Real-time Web Dashboard**
  - Interactive data visualization
  - Protocol, port, and traffic source distribution charts
  - Anomaly timeline
  - Real-time updates via WebSocket

- ✅ **Reporting System**
  - JSON export
  - CSV export
  - HTML reports with charts

## 🚀 Installation

### Requirements

- Python 3.8+
- pip
- Optional: root/admin privileges for live capture

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd netport-anomaly-detector

# Activate virtual environment
source .venv/bin/activate  # macOS/Linux
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Dependencies

```
scapy>=2.5.0            # Packet capture and analysis
numpy>=1.24.0           # Numerical operations
pandas>=2.0.0           # Data analysis
scikit-learn>=1.3.0     # Machine Learning
flask>=3.0.0            # Web framework
flask-socketio>=5.3.0   # WebSocket support
plotly>=5.18.0          # Interactive charts
matplotlib>=3.8.0       # Visualization
seaborn>=0.13.0         # Statistical visualization
pyyaml>=6.0             # Configuration
colorama>=0.4.6         # Colored logs
```

## 📖 Usage

### Basic Usage (Simulator Mode)

```bash
python main.py
```

Launches the application with traffic simulator and dashboard at http://127.0.0.1:5000

### PCAP File Analysis

```bash
python main.py --mode pcap --pcap-file data/capture.pcap
```

### Live Capture (requires admin privileges)

```bash
sudo python main.py --mode live --interface en0
```

### CLI Only (no dashboard)

```bash
python main.py --no-dashboard
```

### Report Generation Only

```bash
python main.py --report-only --output-dir reports
```

### Custom Configuration

```bash
python main.py --config config/custom_config.yaml
```

### Command Line Arguments

```
--mode              Data source mode: simulator, pcap, live
--pcap-file         Path to PCAP file (pcap mode)
--interface         Network interface (live mode)
--config            Configuration file path
--no-dashboard      Run without web dashboard
--report-only       Generate reports and exit
--output-dir        Output directory for reports
```

## ⚙️ Configuration

Edit `config/config.yaml` to customize parameters:

```yaml
# Data Source Settings
data_source:
  mode: "simulator"  # pcap, live, simulator
  pcap_file: "data/sample_traffic.pcap"
  network_interface: "en0"
  packet_count: 1000
  anomaly_rate: 0.1

# Detection Settings
detection:
  statistical:
    enabled: true
    z_score_threshold: 3.0
    window_size: 100

  ml:
    enabled: true
    isolation_forest:
      contamination: 0.1
      n_estimators: 100
    one_class_svm:
      nu: 0.1

  heuristic:
    enabled: true
    port_scan:
      threshold: 10
      time_window: 5
    ddos:
      threshold: 100

  temporal:
    enabled: true
    rate_limit: 50
    burst_threshold: 200

# Dashboard Settings
dashboard:
  host: "127.0.0.1"
  port: 5000
  auto_refresh: 2
```

## 🏗️ Architecture

### Project Structure

```
netport-anomaly-detector/
├── main.py                    # Main entry point
├── config/
│   └── config.yaml           # Configuration file
├── src/
│   ├── analyzer.py           # Main analysis module
│   ├── data_sources/         # Data sources
│   │   ├── base.py          # Base classes
│   │   ├── pcap_reader.py   # PCAP file reader
│   │   ├── live_capture.py  # Live traffic capture
│   │   └── simulator.py     # Traffic simulator
│   ├── detectors/            # Anomaly detectors
│   │   ├── base.py          # Base detector classes
│   │   ├── statistical_detector.py
│   │   ├── ml_detector.py
│   │   ├── heuristic_detector.py
│   │   └── temporal_detector.py
│   ├── dashboard/            # Web dashboard
│   │   ├── app.py           # Flask application
│   │   └── templates/
│   │       └── dashboard.html
│   └── utils/                # Utilities
│       ├── config_loader.py
│       ├── logger.py
│       └── report_generator.py
├── data/                     # Test data
├── logs/                     # Application logs
└── reports/                  # Generated reports
```

### Data Flow

```
Data Source → Analyzer → Detectors → Anomalies
     ↓                                    ↓
  Packets                           Dashboard
                                         ↓
                                     Reports
```

## 🔍 Detection Methods

### 1. Statistical Detection

- Port frequency anomalies (z-score analysis)
- Packet size anomalies
- IP address frequency anomalies
- Uses sliding window approach

**Example anomalies detected:**
- Unusual traffic volume from specific IP
- Abnormal port access patterns
- Packet size outliers

### 2. Machine Learning

**Isolation Forest:**
- Detects outliers in network traffic feature space
- Unsupervised learning approach
- Features: src_port, dst_port, packet_size, protocol, hour

**One-Class SVM:**
- Binary classification (normal/anomaly)
- Learns patterns of normal traffic
- Robust to noise and outliers

### 3. Heuristic Rules

**Port Scanning Detection:**
- Multiple unique ports accessed from same source IP
- Time-based analysis
- Severity levels based on scan intensity

**DDoS Detection:**
- Excessive connections to same destination
- Connection rate analysis
- Volumetric attack detection

**SYN Flood Detection:**
- High ratio of SYN packets
- TCP flag analysis
- Connection state tracking

**Unusual Ports:**
- Connections to uncommon port ranges
- Non-standard service detection

### 4. Temporal Analysis

**Rate Limiting:**
- Packets per second threshold violations
- Source-based rate tracking

**Burst Detection:**
- Sudden traffic spikes
- Statistical deviation from baseline

**Beaconing Detection:**
- Regular periodic patterns
- Potential C2 (Command & Control) detection
- Low variance interval analysis

**Off-hours Activity:**
- Traffic during unusual hours (2-5 AM)
- Behavioral anomaly detection

## 📊 Dashboard

Access the web dashboard at http://127.0.0.1:5000

**Features:**
- **Real-time Monitoring:** WebSocket-based live updates
- **Statistics:** Total packets, anomalies, detection rate
- **Interactive Charts:**
  - Protocol distribution (pie chart)
  - Top destination ports (bar chart)
  - Top source IPs (bar chart)
  - Anomaly timeline (scatter plot)
- **Anomaly List:** Recent anomalies with details
  - Timestamp
  - Severity level (Low, Medium, High, Critical)
  - Type and description
  - Source/destination IPs and ports
  - Confidence score

## 📄 Reports

The system generates reports in three formats:

### JSON Report
```json
{
  "generated_at": "2024-12-04T20:00:00",
  "statistics": {
    "total_packets": 1000,
    "total_anomalies": 95,
    "detection_rate": 9.5,
    "anomaly_types": {...},
    "severity_distribution": {...}
  },
  "anomalies": [...]
}
```

### CSV Report
Anomaly table with columns:
- timestamp
- type
- severity
- description
- source_ip
- destination_ip
- port
- confidence

### HTML Report
Interactive HTML report with:
- Executive summary
- Statistics dashboard
- Interactive charts
- Detailed anomaly table
- Severity color coding

## 🧪 Testing

### Built-in Traffic Simulator

The application includes a traffic simulator that generates:

**Normal Traffic:**
- Connections to common ports (80, 443, 22, etc.)
- Realistic packet sizes
- Various protocols (TCP, UDP)

**Anomalous Traffic:**
- Port scanning patterns
- Unusual port connections
- DDoS simulation
- Traffic bursts

### Example Test Scenarios

```bash
# High anomaly rate test
# Edit config.yaml: anomaly_rate: 0.3
python main.py

# Run example test script
python example_test.py

# Generate reports without dashboard
python main.py --report-only
```

## 🔒 Security & Ethics

### Security Considerations

- Live capture requires root/administrator privileges
- Use only on authorized networks
- Port scanning detection may trigger IDS/IPS alerts
- Store logs securely for audit purposes
- Dashboard has no authentication - bind to localhost only

### Ethical Use

This project is intended for:
- **Educational purposes** in cybersecurity courses
- **Research** in network security
- **Authorized security testing** only

**DO NOT use for:**
- Unauthorized network scanning
- Malicious traffic generation
- Privacy violations
- Production networks without authorization

## 📚 Technologies

- **Python 3.14** - Primary programming language
- **Scapy** - Packet manipulation and analysis
- **scikit-learn** - Machine learning algorithms
- **Flask** - Web framework
- **Plotly** - Interactive visualizations
- **Socket.IO** - Real-time communication
- **NumPy/Pandas** - Data processing

## 👨‍💻 Author

Sebastian Pytka
Cybersecurity Module 3 Project
Semester 5

## 📝 License

Educational project - Academic use only

## 🎯 Future Enhancements

See [TODO.md](TODO.md) for detailed roadmap.

- [ ] Deep Learning (LSTM) for complex pattern detection
- [ ] Threat intelligence feed integration
- [ ] Geolocation-based analysis
- [ ] Multi-sensor correlation
- [ ] Automated incident response
- [ ] Suricata/Snort integration
- [ ] API for external integrations
- [ ] User authentication for dashboard
- [ ] Historical data analysis
- [ ] Custom alerting system

## 📖 Documentation

- **README.md** - This file (overview and usage)
- **CLAUDE.md** - Technical documentation for developers
- **PROJECT_GUIDE.md** - Detailed project guide
- **TODO.md** - Future enhancements and roadmap
- **PRESENTATION.md** - Presentation guide

## 🔗 References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [scikit-learn Anomaly Detection](https://scikit-learn.org/stable/modules/outlier_detection.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🤝 Contributing

This is an educational project. For improvements or suggestions, please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## 📞 Support

For questions or issues:
- Check [PROJECT_GUIDE.md](PROJECT_GUIDE.md) for detailed instructions
- Review [CLAUDE.md](CLAUDE.md) for technical details
- Consult configuration examples in `config/`

---

**⚡ Quick Commands Reference:**

```bash
# Basic run
python main.py

# With PCAP
python main.py --mode pcap --pcap-file data/traffic.pcap

# CLI only
python main.py --no-dashboard

# Generate reports
python main.py --report-only

# Custom config
python main.py --config my_config.yaml
```
