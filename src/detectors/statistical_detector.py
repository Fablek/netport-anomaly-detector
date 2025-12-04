"""Statistical anomaly detection"""

import numpy as np
import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import List

from .base import AnomalyDetector, Anomaly, AnomalyType, SeverityLevel
from ..data_sources.base import NetworkPacket


class StatisticalDetector(AnomalyDetector):
    """Detects anomalies using statistical methods"""

    def __init__(self, z_score_threshold: float = 3.0, window_size: int = 100):
        super().__init__("Statistical Detector")
        self.z_score_threshold = z_score_threshold
        self.window_size = window_size
        self.logger = logging.getLogger(__name__)

    def _calculate_z_score(self, values: List[float]) -> List[float]:
        """Calculate z-scores for values"""
        if len(values) < 2:
            return [0.0] * len(values)

        values_array = np.array(values)
        mean = np.mean(values_array)
        std = np.std(values_array)

        if std == 0:
            return [0.0] * len(values)

        z_scores = (values_array - mean) / std
        return z_scores.tolist()

    def _detect_port_frequency_anomalies(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """Detect anomalies in port access frequency"""
        anomalies = []

        # Count destination port frequencies
        port_counts = Counter(pkt.dst_port for pkt in packets if pkt.dst_port > 0)

        if not port_counts:
            return anomalies

        # Calculate z-scores for port frequencies
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        z_scores = self._calculate_z_score(counts)

        for port, count, z_score in zip(ports, counts, z_scores):
            if abs(z_score) > self.z_score_threshold:
                severity = SeverityLevel.HIGH if abs(z_score) > 4 else SeverityLevel.MEDIUM

                anomaly = Anomaly(
                    timestamp=datetime.now(),
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=severity,
                    description=f"Unusual port frequency detected for port {port}",
                    port=port,
                    confidence=min(abs(z_score) / 5.0, 1.0),
                    details={
                        'port': port,
                        'count': count,
                        'z_score': z_score,
                        'mean_count': np.mean(counts),
                        'std_count': np.std(counts)
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_packet_size_anomalies(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """Detect anomalies in packet sizes"""
        anomalies = []

        packet_sizes = [pkt.packet_size for pkt in packets]
        z_scores = self._calculate_z_score(packet_sizes)

        for pkt, z_score in zip(packets, z_scores):
            if abs(z_score) > self.z_score_threshold:
                severity = SeverityLevel.MEDIUM if abs(z_score) > 4 else SeverityLevel.LOW

                anomaly = Anomaly(
                    timestamp=pkt.timestamp,
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=severity,
                    description=f"Unusual packet size detected: {pkt.packet_size} bytes",
                    source_ip=pkt.src_ip,
                    destination_ip=pkt.dst_ip,
                    confidence=min(abs(z_score) / 5.0, 1.0),
                    details={
                        'packet_size': pkt.packet_size,
                        'z_score': z_score,
                        'mean_size': np.mean(packet_sizes),
                        'std_size': np.std(packet_sizes)
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_ip_frequency_anomalies(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """Detect anomalies in IP address frequency"""
        anomalies = []

        # Count source IP frequencies
        ip_counts = Counter(pkt.src_ip for pkt in packets)

        if len(ip_counts) < 2:
            return anomalies

        ips = list(ip_counts.keys())
        counts = list(ip_counts.values())
        z_scores = self._calculate_z_score(counts)

        for ip, count, z_score in zip(ips, counts, z_scores):
            if abs(z_score) > self.z_score_threshold:
                severity = SeverityLevel.HIGH if abs(z_score) > 4 else SeverityLevel.MEDIUM

                anomaly = Anomaly(
                    timestamp=datetime.now(),
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=severity,
                    description=f"Unusual traffic volume from IP {ip}",
                    source_ip=ip,
                    confidence=min(abs(z_score) / 5.0, 1.0),
                    details={
                        'ip': ip,
                        'packet_count': count,
                        'z_score': z_score,
                        'mean_count': np.mean(counts),
                        'std_count': np.std(counts)
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def detect(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect statistical anomalies in packets

        Args:
            packets: List of network packets

        Returns:
            List of detected anomalies
        """
        if not self.enabled or not packets:
            return []

        self.logger.info(f"Running statistical detection on {len(packets)} packets")

        anomalies = []

        # Use sliding window
        window_packets = packets[-self.window_size:] if len(packets) > self.window_size else packets

        # Detect various types of statistical anomalies
        anomalies.extend(self._detect_port_frequency_anomalies(window_packets))
        anomalies.extend(self._detect_ip_frequency_anomalies(window_packets))

        # Only check packet size anomalies if we have enough data
        if len(window_packets) > 10:
            anomalies.extend(self._detect_packet_size_anomalies(window_packets))

        self.detected_anomalies.extend(anomalies)
        self.logger.info(f"Detected {len(anomalies)} statistical anomalies")

        return anomalies
