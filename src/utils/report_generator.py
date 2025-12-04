"""Report generation utility"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List
import logging

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


class ReportGenerator:
    """Generates reports from analysis results"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def generate_json_report(self, packets, anomalies, statistics) -> str:
        """
        Generate JSON report

        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"report_{timestamp}.json"

        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': statistics,
            'anomalies': [a.to_dict() for a in anomalies],
            'total_packets': len(packets),
            'total_anomalies': len(anomalies)
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"JSON report generated: {filename}")
        return str(filename)

    def generate_csv_report(self, anomalies) -> str:
        """
        Generate CSV report of anomalies

        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"anomalies_{timestamp}.csv"

        if not anomalies:
            self.logger.warning("No anomalies to export")
            return None

        # Get all unique keys from anomaly details
        fieldnames = [
            'timestamp', 'type', 'severity', 'description',
            'source_ip', 'destination_ip', 'port', 'confidence'
        ]

        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for anomaly in anomalies:
                row = {
                    'timestamp': anomaly.timestamp.isoformat(),
                    'type': anomaly.anomaly_type.value,
                    'severity': anomaly.severity.value,
                    'description': anomaly.description,
                    'source_ip': anomaly.source_ip or '',
                    'destination_ip': anomaly.destination_ip or '',
                    'port': anomaly.port or '',
                    'confidence': f"{anomaly.confidence:.2f}"
                }
                writer.writerow(row)

        self.logger.info(f"CSV report generated: {filename}")
        return str(filename)

    def generate_html_report(self, packets, anomalies, statistics) -> str:
        """
        Generate HTML report with charts

        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"report_{timestamp}.html"

        # Create charts if plotly is available
        charts_html = ""
        if PLOTLY_AVAILABLE:
            charts_html = self._generate_charts(anomalies, statistics)

        # Generate anomalies table
        anomalies_html = self._generate_anomalies_table(anomalies[-50:])  # Last 50

        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Network Anomaly Detection Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity-critical {{ color: #b71c1c; font-weight: bold; }}
        .severity-high {{ color: #f44336; font-weight: bold; }}
        .severity-medium {{ color: #ff6b35; font-weight: bold; }}
        .severity-low {{ color: #ffa500; }}
        .charts {{ margin: 30px 0; }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
    </style>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>🛡️ Network Anomaly Detection Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{statistics.get('total_packets', 0)}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{statistics.get('total_anomalies', 0)}</div>
                <div class="stat-label">Anomalies Detected</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{statistics.get('detection_rate', 0):.2f}%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
        </div>

        <div class="charts">
            {charts_html}
        </div>

        <h2>Recent Anomalies</h2>
        {anomalies_html}

        <div class="footer">
            <p>Network Port Anomaly Detector v1.0</p>
            <p>Cybersecurity Module 3 Project</p>
        </div>
    </div>
</body>
</html>
"""

        with open(filename, 'w') as f:
            f.write(html_content)

        self.logger.info(f"HTML report generated: {filename}")
        return str(filename)

    def _generate_charts(self, anomalies, statistics) -> str:
        """Generate charts for HTML report"""
        if not PLOTLY_AVAILABLE or not anomalies:
            return "<p>Charts not available (install plotly)</p>"

        # Severity distribution
        severity_dist = statistics.get('severity_distribution', {})
        severity_fig = go.Figure(data=[
            go.Pie(labels=list(severity_dist.keys()),
                   values=list(severity_dist.values()))
        ])
        severity_fig.update_layout(title="Severity Distribution", height=400)

        # Anomaly types
        anomaly_types = statistics.get('anomaly_types', {})
        types_fig = go.Figure(data=[
            go.Bar(x=list(anomaly_types.keys()),
                   y=list(anomaly_types.values()),
                   marker_color='#667eea')
        ])
        types_fig.update_layout(title="Anomaly Types", height=400)

        # Combine charts
        charts_html = f"""
        <div id="severityChart"></div>
        <div id="typesChart"></div>
        <script>
            Plotly.newPlot('severityChart', {severity_fig.to_json()});
            Plotly.newPlot('typesChart', {types_fig.to_json()});
        </script>
        """

        return charts_html

    def _generate_anomalies_table(self, anomalies) -> str:
        """Generate HTML table of anomalies"""
        if not anomalies:
            return "<p>No anomalies detected.</p>"

        rows = ""
        for anomaly in reversed(anomalies):  # Most recent first
            severity_class = f"severity-{anomaly.severity.value}"
            rows += f"""
            <tr>
                <td>{anomaly.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>
                <td class="{severity_class}">{anomaly.severity.value.upper()}</td>
                <td>{anomaly.anomaly_type.value}</td>
                <td>{anomaly.description}</td>
                <td>{anomaly.source_ip or '-'}</td>
                <td>{anomaly.destination_ip or '-'}</td>
                <td>{anomaly.port or '-'}</td>
                <td>{anomaly.confidence:.2f}</td>
            </tr>
            """

        table = f"""
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Source IP</th>
                    <th>Dest IP</th>
                    <th>Port</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

        return table

    def generate_all_reports(self, packets, anomalies, statistics) -> dict:
        """
        Generate all report formats

        Returns:
            Dictionary with paths to generated reports
        """
        reports = {}

        try:
            reports['json'] = self.generate_json_report(packets, anomalies, statistics)
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")

        try:
            reports['csv'] = self.generate_csv_report(anomalies)
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {e}")

        try:
            reports['html'] = self.generate_html_report(packets, anomalies, statistics)
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")

        return reports
