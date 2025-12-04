"""Main network traffic analyzer"""

import logging
import threading
import time
from pathlib import Path
from typing import List, Optional

from .data_sources.base import DataSource, NetworkPacket
from .data_sources.pcap_reader import PCAPReader
from .data_sources.live_capture import LiveCapture
from .data_sources.simulator import TrafficSimulator
from .detectors.statistical_detector import StatisticalDetector
from .detectors.ml_detector import MLDetector
from .detectors.heuristic_detector import HeuristicDetector
from .detectors.temporal_detector import TemporalDetector
from .detectors.base import Anomaly
from .utils.config_loader import ConfigLoader
from .utils.logger import setup_logger


class NetworkAnalyzer:
    """Main network traffic analyzer"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the network analyzer

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = ConfigLoader(config_path)

        # Setup logger
        self.logger = setup_logger(
            "NetworkAnalyzer",
            log_file=self.config.get('logging.file', 'logs/anomaly_detector.log'),
            level=self.config.get('logging.level', 'INFO'),
            console=self.config.get('logging.console', True)
        )

        # Initialize data source
        self.data_source: Optional[DataSource] = None
        self._init_data_source()

        # Initialize detectors
        self.detectors = []
        self._init_detectors()

        # Storage
        self.packets: List[NetworkPacket] = []
        self.anomalies: List[Anomaly] = []

        # State
        self.is_running = False
        self.analysis_thread: Optional[threading.Thread] = None

        # Dashboard callback
        self.dashboard_callback = None

        self.logger.info("Network Analyzer initialized")

    def _init_data_source(self):
        """Initialize data source based on configuration"""
        mode = self.config.data_source_mode

        if mode == 'pcap':
            pcap_file = self.config.pcap_file
            self.data_source = PCAPReader(pcap_file)
            self.logger.info(f"Initialized PCAP reader: {pcap_file}")

        elif mode == 'live':
            interface = self.config.network_interface
            self.data_source = LiveCapture(interface=interface, packet_count=1000)
            self.logger.info(f"Initialized live capture: {interface}")

        elif mode == 'simulator':
            packet_count = self.config.get('data_source.packet_count', 1000)
            anomaly_rate = self.config.get('data_source.anomaly_rate', 0.1)
            self.data_source = TrafficSimulator(
                packet_count=packet_count,
                anomaly_rate=anomaly_rate
            )
            self.logger.info(f"Initialized traffic simulator")

        else:
            raise ValueError(f"Unknown data source mode: {mode}")

    def _init_detectors(self):
        """Initialize anomaly detectors based on configuration"""

        # Statistical detector
        if self.config.get('detection.statistical.enabled', True):
            detector = StatisticalDetector(
                z_score_threshold=self.config.get('detection.statistical.z_score_threshold', 3.0),
                window_size=self.config.get('detection.statistical.window_size', 100)
            )
            self.detectors.append(detector)
            self.logger.info("Initialized Statistical Detector")

        # ML detector
        if self.config.get('detection.ml.enabled', True):
            detector = MLDetector(
                use_isolation_forest=True,
                use_one_class_svm=True,
                contamination=self.config.get('detection.ml.isolation_forest.contamination', 0.1),
                nu=self.config.get('detection.ml.one_class_svm.nu', 0.1)
            )
            self.detectors.append(detector)
            self.logger.info("Initialized ML Detector")

        # Heuristic detector
        if self.config.get('detection.heuristic.enabled', True):
            detector = HeuristicDetector(
                port_scan_threshold=self.config.get('detection.heuristic.port_scan.threshold', 10),
                port_scan_window=self.config.get('detection.heuristic.port_scan.time_window', 5),
                ddos_threshold=self.config.get('detection.heuristic.ddos.threshold', 100),
                ddos_window=self.config.get('detection.heuristic.ddos.time_window', 1)
            )
            self.detectors.append(detector)
            self.logger.info("Initialized Heuristic Detector")

        # Temporal detector
        if self.config.get('detection.temporal.enabled', True):
            detector = TemporalDetector(
                rate_limit=self.config.get('detection.temporal.rate_limit', 50),
                burst_threshold=self.config.get('detection.temporal.burst_threshold', 200)
            )
            self.detectors.append(detector)
            self.logger.info("Initialized Temporal Detector")

    def set_dashboard_callback(self, callback):
        """Set callback function for dashboard updates"""
        self.dashboard_callback = callback

    def start(self):
        """Start the network analyzer"""
        if self.is_running:
            self.logger.warning("Analyzer is already running")
            return

        self.is_running = True
        self.logger.info("Starting network analyzer...")

        # Start data source
        self.data_source.start()

        # Start analysis in separate thread
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()

        self.logger.info("Network analyzer started")

    def stop(self):
        """Stop the network analyzer"""
        if not self.is_running:
            return

        self.logger.info("Stopping network analyzer...")
        self.is_running = False

        # Stop data source
        if self.data_source:
            self.data_source.stop()

        # Wait for analysis thread to finish
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)

        self.logger.info("Network analyzer stopped")

    def _analysis_loop(self):
        """Main analysis loop"""
        batch_size = 50

        try:
            # Collect packets in batches
            packet_batch = []

            for packet in self.data_source.get_packets():
                if not self.is_running:
                    break

                packet_batch.append(packet)
                self.packets.append(packet)

                # Process in batches
                if len(packet_batch) >= batch_size:
                    self._analyze_batch(packet_batch)
                    packet_batch = []

            # Process remaining packets
            if packet_batch:
                self._analyze_batch(packet_batch)

        except Exception as e:
            self.logger.error(f"Error in analysis loop: {e}", exc_info=True)
        finally:
            self.is_running = False

    def _analyze_batch(self, packets: List[NetworkPacket]):
        """
        Analyze a batch of packets

        Args:
            packets: List of packets to analyze
        """
        batch_anomalies = []

        # Run all detectors
        for detector in self.detectors:
            if detector.enabled:
                try:
                    anomalies = detector.detect(self.packets)
                    batch_anomalies.extend(anomalies)
                except Exception as e:
                    self.logger.error(f"Error in {detector.name}: {e}", exc_info=True)

        # Store anomalies
        self.anomalies.extend(batch_anomalies)

        # Update dashboard if callback is set
        if self.dashboard_callback:
            try:
                self.dashboard_callback(packets, batch_anomalies)
            except Exception as e:
                self.logger.error(f"Error updating dashboard: {e}")

        # Log summary
        if batch_anomalies:
            self.logger.info(
                f"Analyzed {len(packets)} packets, detected {len(batch_anomalies)} anomalies"
            )

    def get_statistics(self) -> dict:
        """Get analysis statistics"""
        from collections import Counter

        total_packets = len(self.packets)
        total_anomalies = len(self.anomalies)

        # Anomaly types distribution
        anomaly_types = Counter(a.anomaly_type.value for a in self.anomalies)

        # Severity distribution
        severity_dist = Counter(a.severity.value for a in self.anomalies)

        # Top source IPs in anomalies
        source_ips = Counter(a.source_ip for a in self.anomalies if a.source_ip)

        return {
            'total_packets': total_packets,
            'total_anomalies': total_anomalies,
            'detection_rate': (total_anomalies / total_packets * 100) if total_packets > 0 else 0,
            'anomaly_types': dict(anomaly_types),
            'severity_distribution': dict(severity_dist),
            'top_anomaly_sources': dict(source_ips.most_common(10))
        }

    def get_anomalies(self, limit: int = None) -> List[Anomaly]:
        """Get detected anomalies"""
        if limit:
            return self.anomalies[-limit:]
        return self.anomalies

    def clear_data(self):
        """Clear all collected data"""
        self.packets = []
        self.anomalies = []
        for detector in self.detectors:
            detector.clear_anomalies()
        self.logger.info("Cleared all data")
