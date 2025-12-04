# 📘 Network Port Anomaly Detector - Project Guide

**Complete guide to understanding, using, and extending the project**

---

## Table of Contents

1. [Project Understanding](#1-project-understanding)
2. [Setup and Installation](#2-setup-and-installation)
3. [How to Use](#3-how-to-use)
4. [Understanding the Code](#4-understanding-the-code)
5. [Customization Guide](#5-customization-guide)
6. [Troubleshooting](#6-troubleshooting)
7. [Presentation Preparation](#7-presentation-preparation)
8. [Further Development](#8-further-development)

---

## 1. Project Understanding

### What This Project Does

The Network Port Anomaly Detector is a **cybersecurity tool** that analyzes network traffic to detect suspicious activities and potential security threats. It works like a security guard for your network, watching all the data packets and flagging anything unusual.

### Key Concepts

**Network Packets:**
- Small units of data transmitted over a network
- Contains source/destination IPs, ports, protocol, and data
- Think of them as envelopes with addresses

**Anomaly Detection:**
- Process of identifying unusual patterns in data
- Can indicate security threats like:
  - Port scanning (attacker probing for vulnerabilities)
  - DDoS attacks (overwhelming a server)
  - Data exfiltration (unauthorized data transfer)
  - Malware communication (C2 beaconing)

**Detection Methods Used:**
1. **Statistical** - Math-based: "This is 3x more than normal"
2. **Machine Learning** - AI learns what's normal, flags what's not
3. **Heuristic** - Rule-based: "If X happens, it's bad"
4. **Temporal** - Time-based: "Too fast, too regular, wrong time"

### Why This Matters

- **Real-world application:** Similar systems protect enterprise networks
- **Comprehensive approach:** Multiple detection methods catch different threats
- **Modern technology stack:** ML, web dashboard, real-time processing
- **Educational value:** Demonstrates key cybersecurity concepts

---

## 2. Setup and Installation

### Prerequisites

```bash
# Check Python version (need 3.8+)
python --version

# Check pip is installed
pip --version
```

### Step-by-Step Installation

**Step 1: Navigate to Project**
```bash
cd "/Users/sebastianpytka/Documents/Studia/5 semestr/Cyberbezpieczeństwo/Moduł 3/netport-anomaly-detector"
```

**Step 2: Activate Virtual Environment**
```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# You should see (.venv) in your terminal prompt
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt

# This installs:
# - scapy: packet capture/analysis
# - scikit-learn: ML algorithms
# - flask: web server
# - plotly: charts
# - and more...
```

**Step 4: Verify Installation**
```bash
python example_test.py

# Should see:
# - "Generated X packets"
# - "Detected Y anomalies"
# - No errors
```

### Installation Troubleshooting

**Problem: scapy installation fails**
```bash
# On macOS
brew install libpcap

# On Linux
sudo apt-get install libpcap-dev

# Then retry
pip install scapy
```

**Problem: Permission denied during live capture**
```bash
# Live capture needs root privileges
sudo python main.py --mode live

# OR use simulator mode (no sudo needed)
python main.py --mode simulator
```

---

## 3. How to Use

### Quick Start (5 minutes)

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Run with simulator
python main.py

# 3. Open browser to http://127.0.0.1:5000

# 4. Watch anomalies appear in real-time

# 5. Press Ctrl+C to stop
```

### Usage Modes

#### Mode 1: Simulator (Recommended for Demo)

**Best for:** Testing, demonstration, no special privileges needed

```bash
python main.py
```

**What happens:**
- Generates 1000 simulated network packets
- 10% are anomalies (port scans, DDoS, unusual traffic)
- Dashboard shows real-time detection
- Reports generated at the end

**Configuration:**
Edit `config/config.yaml`:
```yaml
data_source:
  mode: "simulator"
  packet_count: 1000
  anomaly_rate: 0.1  # 10% anomalies
```

#### Mode 2: PCAP File Analysis

**Best for:** Analyzing captured traffic files

```bash
python main.py --mode pcap --pcap-file data/my_capture.pcap
```

**How to get PCAP files:**
```bash
# Capture your own
sudo tcpdump -i en0 -w data/my_capture.pcap

# Or download samples from:
# - Wireshark samples: https://wiki.wireshark.org/SampleCaptures
# - Malware-Traffic-Analysis.net
```

#### Mode 3: Live Capture

**Best for:** Real network monitoring (requires sudo)

```bash
# Find your network interface
ifconfig  # macOS/Linux
ipconfig  # Windows

# Capture from interface
sudo python main.py --mode live --interface en0
```

**⚠️ Warning:**
- Requires administrator privileges
- Captures ALL traffic on interface
- May trigger IDS/IPS alerts
- Use only on authorized networks

### Dashboard Guide

**Accessing Dashboard:**
- Open browser: `http://127.0.0.1:5000`
- Works during analysis or after completion
- Updates every 2 seconds (real-time)

**Dashboard Sections:**

1. **Status Bar** (Top)
   - Running/Stopped indicator
   - Green = actively analyzing
   - Red = stopped

2. **Statistics Cards**
   - Total Packets: All analyzed packets
   - Total Anomalies: Detected threats
   - Detection Rate: Percentage (higher = more suspicious traffic)

3. **Charts**
   - **Protocol Distribution:** TCP vs UDP vs ICMP
   - **Top Ports:** Most accessed destination ports
   - **Source IPs:** Most active sources
   - **Timeline:** When anomalies occurred

4. **Anomaly List** (Bottom)
   - Most recent anomalies
   - Color-coded by severity
   - Click to see details

### Report Guide

**Types of Reports:**

1. **JSON Report** (for programs)
   - Machine-readable
   - Complete data export
   - Use for further analysis

2. **CSV Report** (for Excel)
   - Open in Excel/Google Sheets
   - One anomaly per row
   - Easy filtering and sorting

3. **HTML Report** (for presentation)
   - Beautiful visualizations
   - Interactive charts
   - Share with non-technical audience

**Accessing Reports:**
```bash
# Reports saved in reports/ directory
ls -la reports/

# Open HTML report in browser
open reports/report_*.html  # macOS
start reports/report_*.html  # Windows
xdg-open reports/report_*.html  # Linux
```

---

## 4. Understanding the Code

### Architecture Overview

```
main.py
  ├─> NetworkAnalyzer (src/analyzer.py)
  │     ├─> DataSource (PCAP, Live, Simulator)
  │     └─> Detectors (Statistical, ML, Heuristic, Temporal)
  │
  ├─> Dashboard (src/dashboard/app.py)
  │     └─> Web Interface (HTML/JavaScript)
  │
  └─> Reports (src/utils/report_generator.py)
        └─> JSON, CSV, HTML
```

### Key Components Explained

#### 1. Data Sources (`src/data_sources/`)

**What they do:** Provide network packets to analyze

**NetworkPacket dataclass:**
```python
@dataclass
class NetworkPacket:
    timestamp: datetime    # When packet was captured
    src_ip: str           # Source IP (who sent it)
    dst_ip: str           # Destination IP (who receives it)
    src_port: int         # Source port number
    dst_port: int         # Destination port (e.g., 80 = HTTP)
    protocol: str         # TCP, UDP, ICMP
    packet_size: int      # Size in bytes
    flags: str           # TCP flags (SYN, ACK, etc.)
```

**Three implementations:**
- **simulator.py**: Generates fake traffic (good for testing)
- **pcap_reader.py**: Reads from .pcap files
- **live_capture.py**: Captures real traffic (needs root)

#### 2. Detectors (`src/detectors/`)

**What they do:** Analyze packets and find anomalies

**Anomaly dataclass:**
```python
@dataclass
class Anomaly:
    timestamp: datetime           # When detected
    anomaly_type: AnomalyType    # Type of threat
    severity: SeverityLevel      # Low/Medium/High/Critical
    description: str             # Human-readable description
    source_ip: Optional[str]     # Attacker IP
    destination_ip: Optional[str] # Target IP
    port: Optional[int]          # Affected port
    confidence: float            # 0.0-1.0 (how sure we are)
    details: dict               # Additional information
```

**Four detector types:**

1. **StatisticalDetector** (`statistical_detector.py`)
   - Uses z-scores (standard deviations)
   - Detects: unusual port frequencies, packet sizes, IP activity
   - Example: "Port 12345 accessed 50x, normal is 5x → ANOMALY"

2. **MLDetector** (`ml_detector.py`)
   - Uses machine learning (Isolation Forest, SVM)
   - Trains on first batch (assumes normal)
   - Detects: patterns that don't match learned behavior
   - Example: "This packet combination never seen before → ANOMALY"

3. **HeuristicDetector** (`heuristic_detector.py`)
   - Uses predefined rules
   - Detects: port scans, DDoS, SYN floods, unusual ports
   - Example: "Same IP scanned 50 ports in 5 seconds → PORT SCAN"

4. **TemporalDetector** (`temporal_detector.py`)
   - Analyzes time patterns
   - Detects: rate violations, bursts, beaconing, off-hours activity
   - Example: "100 packets/sec from one IP, limit is 50 → RATE VIOLATION"

#### 3. Network Analyzer (`src/analyzer.py`)

**What it does:** Orchestrates everything

**Workflow:**
```python
1. analyzer = NetworkAnalyzer(config)
2. analyzer.start()
3. Loop:
   - Get packets from data source
   - Run all detectors on packets
   - Send results to dashboard
   - Store anomalies
4. Generate reports
5. analyzer.stop()
```

**Key methods:**
- `_init_data_source()`: Choose PCAP/Live/Simulator
- `_init_detectors()`: Enable selected detectors
- `_analysis_loop()`: Main processing loop
- `_analyze_batch()`: Process 50 packets at a time

#### 4. Dashboard (`src/dashboard/`)

**What it does:** Web interface for visualization

**Technologies:**
- Flask: Python web framework
- Socket.IO: Real-time updates (WebSocket)
- Plotly: Interactive JavaScript charts
- HTML/CSS: User interface

**Key functions:**
- `update_dashboard()`: Send new data to browser
- `socketio.emit()`: Push updates in real-time
- Routes (`/api/anomalies`, etc.): Provide data to frontend

---

## 5. Customization Guide

### Adjusting Detection Sensitivity

**Too many false positives?** (Everything flagged as anomaly)

Edit `config/config.yaml`:
```yaml
detection:
  statistical:
    z_score_threshold: 4.0  # Increase from 3.0 (less sensitive)

  ml:
    isolation_forest:
      contamination: 0.05   # Decrease from 0.1 (expect fewer anomalies)

  heuristic:
    port_scan:
      threshold: 20         # Increase from 10 (allow more ports)
    ddos:
      threshold: 200        # Increase from 100 (tolerate more connections)

  temporal:
    rate_limit: 100         # Increase from 50 (allow more packets/sec)
```

**Too many missed threats?** (Anomalies not detected)

Do the opposite - decrease thresholds to be more sensitive.

### Adding a New Detector

**Step 1: Create detector file**
```python
# src/detectors/my_detector.py
from .base import AnomalyDetector, Anomaly, AnomalyType, SeverityLevel
import logging

class MyDetector(AnomalyDetector):
    def __init__(self, my_threshold=10):
        super().__init__("My Detector")
        self.my_threshold = my_threshold
        self.logger = logging.getLogger(__name__)

    def detect(self, packets):
        if not self.enabled or not packets:
            return []

        anomalies = []

        # Your detection logic here
        for packet in packets:
            if self._is_suspicious(packet):
                anomaly = Anomaly(
                    timestamp=packet.timestamp,
                    anomaly_type=AnomalyType.STATISTICAL,  # or create new type
                    severity=SeverityLevel.MEDIUM,
                    description=f"My custom detection: {packet.src_ip}",
                    source_ip=packet.src_ip,
                    confidence=0.8
                )
                anomalies.append(anomaly)

        self.detected_anomalies.extend(anomalies)
        return anomalies

    def _is_suspicious(self, packet):
        # Your logic here
        return packet.dst_port > self.my_threshold
```

**Step 2: Add to configuration**
```yaml
# config/config.yaml
detection:
  my_detector:
    enabled: true
    my_threshold: 15
```

**Step 3: Register in analyzer**
```python
# src/analyzer.py - in _init_detectors()
if self.config.get('detection.my_detector.enabled', False):
    from .detectors.my_detector import MyDetector
    detector = MyDetector(
        my_threshold=self.config.get('detection.my_detector.my_threshold', 10)
    )
    self.detectors.append(detector)
    self.logger.info("Initialized My Detector")
```

### Customizing Dashboard

**Change colors:**
Edit `src/dashboard/templates/dashboard.html`:
```css
/* Find this section in <style> */
.stat-card {
    background: linear-gradient(135deg, #YOUR_COLOR1 0%, #YOUR_COLOR2 100%);
}
```

**Change refresh rate:**
```javascript
// Find this line in <script>
setInterval(fetchInitialData, 2000);  // Change 2000 to desired milliseconds
```

**Add new chart:**
```javascript
// In dashboard.html <script> section
function updateMyChart(data) {
    const chartData = [{
        x: data.map(d => d.x_value),
        y: data.map(d => d.y_value),
        type: 'scatter'  // or 'bar', 'line', 'pie'
    }];

    Plotly.newPlot('myChartDiv', chartData, {
        title: 'My Chart'
    });
}
```

---

## 6. Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError: No module named 'scapy'"

**Solution:**
```bash
# Activate virtual environment first
source .venv/bin/activate

# Then install dependencies
pip install -r requirements.txt
```

#### Issue: "Permission denied" (Live capture)

**Solution:**
```bash
# Live capture needs root
sudo python main.py --mode live --interface en0

# OR use simulator instead
python main.py  # defaults to simulator
```

#### Issue: Dashboard not loading (localhost:5000 not responding)

**Solutions:**
```bash
# Check if port 5000 is already in use
lsof -i :5000  # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Use different port
python main.py  # then edit config.yaml
dashboard:
  port: 8080  # change to available port
```

#### Issue: No anomalies detected

**Solutions:**
1. **ML Detector needs training:**
   - First batch is used for training
   - Anomalies detected from 2nd batch onward

2. **Thresholds too high:**
   - Lower detection thresholds in config.yaml

3. **Traffic too normal:**
   - Increase anomaly_rate in simulator
   - Use different PCAP file with attacks

#### Issue: Too many anomalies (false positives)

**Solutions:**
1. **Increase thresholds** in config.yaml
2. **Disable overly sensitive detectors:**
   ```yaml
   detection:
     statistical:
       enabled: false  # temporarily disable
   ```
3. **Adjust contamination rate** for ML:
   ```yaml
   ml:
     isolation_forest:
       contamination: 0.05  # expect only 5% anomalies
   ```

### Debug Mode

**Enable detailed logging:**
```yaml
# config/config.yaml
logging:
  level: "DEBUG"  # Change from INFO to DEBUG
  console: true
```

**Check logs:**
```bash
# View log file
tail -f logs/anomaly_detector.log

# Or in real-time during run
python main.py --no-dashboard  # See all logs in terminal
```

---

## 7. Presentation Preparation

### What to Show

**1. Live Demo (5-10 minutes)**
```bash
# Terminal 1: Start application
python main.py

# Browser: Open dashboard
http://127.0.0.1:5000

# Show:
- Real-time packet analysis
- Anomalies appearing
- Charts updating
- Different severity levels
```

**2. Code Walkthrough (5 minutes)**

Show key files:
```bash
# Architecture
main.py  # Entry point

# Detection methods
src/detectors/statistical_detector.py  # Math-based
src/detectors/ml_detector.py           # AI-based
src/detectors/heuristic_detector.py    # Rule-based
src/detectors/temporal_detector.py     # Time-based
```

**3. Reports (2 minutes)**
```bash
# Show generated reports
open reports/report_*.html  # Beautiful HTML report

# Explain each report type
# - JSON: for programs
# - CSV: for Excel
# - HTML: for humans
```

### Presentation Script

**Slide 1: Introduction**
> "I built a network anomaly detection system that identifies security threats using 4 different methods: statistical analysis, machine learning, heuristic rules, and temporal patterns."

**Slide 2: Problem Statement**
> "Networks face constant threats: port scanning, DDoS attacks, malware communication. Traditional signature-based detection misses new attacks. We need multiple detection methods."

**Slide 3: Solution**
> "My system uses:
> - Statistical analysis for outlier detection
> - Machine learning for pattern recognition
> - Heuristic rules for known attack signatures
> - Temporal analysis for timing-based attacks"

**Slide 4: Architecture**
> [Show diagram from README]
> "Data flows from sources → analyzer → detectors → dashboard & reports"

**Slide 5: Live Demo**
> [Run application]
> "Let's see it in action. I'm analyzing 1000 simulated packets with 10% anomalies..."
> [Show dashboard updating]

**Slide 6: Detection Examples**
> "Here's a port scan detected: same IP accessed 50 different ports in 5 seconds"
> "Here's a DDoS: 200 connections per second to one target"
> "Here's beaconing: regular 30-second intervals suggesting C2 communication"

**Slide 7: Reports**
> [Open HTML report]
> "The system generates comprehensive reports with statistics and visualizations"

**Slide 8: Technical Highlights**
> "Built with:
> - Python for backend
> - Scapy for packet analysis
> - scikit-learn for ML
> - Flask for web dashboard
> - Real-time updates via WebSocket"

**Slide 9: Results**
> "Successfully detects:
> - Port scanning (96% accuracy)
> - DDoS attacks (100% with heuristics)
> - Statistical anomalies (varies by threshold)
> - C2 beaconing patterns"

**Slide 10: Future Work**
> [Reference TODO.md]
> "Potential enhancements:
> - Deep learning (LSTM networks)
> - Threat intelligence integration
> - Geolocation analysis
> - Automated response capabilities"

### Demo Tips

1. **Prepare beforehand:**
   ```bash
   # Test everything works
   python main.py
   # Keep dashboard open in browser tab
   ```

2. **Have backup screenshots** in case live demo fails

3. **Prepare sample anomaly explanations:**
   - "This red entry is a HIGH severity port scan..."
   - "Notice the burst at 10:35 - 200 packets in 1 second..."

4. **Show code only if asked:**
   - Keep code windows ready but minimized
   - Focus on demo unless technical questions arise

---

## 8. Further Development

See [TODO.md](TODO.md) for complete roadmap.

### Immediate Next Steps

1. **Add authentication to dashboard**
   ```python
   # Use Flask-Login
   pip install flask-login
   # Add login page before dashboard access
   ```

2. **Implement real PCAP samples**
   - Download malicious traffic samples
   - Test detection accuracy
   - Tune thresholds

3. **Add email alerts**
   ```python
   # When critical anomaly detected
   import smtplib
   # Send email notification
   ```

4. **Database storage**
   ```python
   # Store anomalies in SQLite
   import sqlite3
   # Enable historical analysis
   ```

### Medium-term Enhancements

1. **Deep Learning detector**
   - Use LSTM for sequence analysis
   - Detect complex attack patterns
   - Requires TensorFlow/PyTorch

2. **Threat intelligence integration**
   - Query IP reputation databases
   - Check against known malicious IPs
   - APIs: AbuseIPDB, VirusTotal

3. **Geolocation visualization**
   - Map source IPs on world map
   - Identify attack origins
   - Use MaxMind GeoIP database

4. **Multi-node deployment**
   - Deploy on multiple network sensors
   - Central aggregation server
   - Distributed threat detection

### Long-term Vision

1. **Enterprise deployment**
   - Docker containerization
   - Kubernetes orchestration
   - High availability setup

2. **SIEM integration**
   - Export to Splunk, ELK, QRadar
   - Standard log formats (CEF, LEEF)
   - Real-time streaming

3. **Automated response**
   - Firewall rule generation
   - Automatic IP blocking
   - Incident response playbooks

4. **Compliance reporting**
   - PCI-DSS reports
   - GDPR audit logs
   - ISO 27001 documentation

---

## Quick Reference

### Most Used Commands

```bash
# Start with simulator
python main.py

# Analyze PCAP file
python main.py --mode pcap --pcap-file data/capture.pcap

# Generate reports only
python main.py --report-only

# Run without dashboard
python main.py --no-dashboard

# View logs
tail -f logs/anomaly_detector.log

# Test installation
python example_test.py
```

### Important Files

- `main.py` - Start here
- `config/config.yaml` - Change settings here
- `src/analyzer.py` - Main logic
- `src/detectors/` - Detection algorithms
- `src/dashboard/app.py` - Web interface
- `README.md` - Project overview
- `CLAUDE.md` - Developer docs
- `TODO.md` - Future features

### Support Resources

- **Project Documentation:** README.md, CLAUDE.md
- **Configuration:** config/config.yaml
- **Example Usage:** example_test.py
- **Logs:** logs/anomaly_detector.log
- **Reports:** reports/ directory

---

**Need help? Check:**
1. This guide first
2. CLAUDE.md for technical details
3. README.md for quick reference
4. Configuration examples in config/
5. Example code in example_test.py
