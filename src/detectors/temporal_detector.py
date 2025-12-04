"""Temporal anomaly detection (rate limiting, bursts, timing patterns)"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict

from .base import AnomalyDetector, Anomaly, AnomalyType, SeverityLevel
from ..data_sources.base import NetworkPacket


class TemporalDetector(AnomalyDetector):
    """Detects anomalies in temporal patterns of network traffic"""

    def __init__(self, rate_limit: int = 50, burst_threshold: int = 200):
        super().__init__("Temporal Detector")
        self.rate_limit = rate_limit  # packets per second
        self.burst_threshold = burst_threshold  # sudden spike
        self.logger = logging.getLogger(__name__)

    def _detect_rate_violations(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect rate limit violations
        Criteria: Too many packets per second from same source
        """
        anomalies = []

        # Group packets by source IP and second
        ip_packets_per_second: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for pkt in packets:
            second_bucket = pkt.timestamp.replace(microsecond=0)
            ip_packets_per_second[pkt.src_ip][str(second_bucket)] += 1

        # Check for rate violations
        for src_ip, time_buckets in ip_packets_per_second.items():
            for time_bucket, count in time_buckets.items():
                if count > self.rate_limit:
                    # Severity based on how much over the limit
                    excess_ratio = count / self.rate_limit

                    if excess_ratio > 4:
                        severity = SeverityLevel.HIGH
                    elif excess_ratio > 2:
                        severity = SeverityLevel.MEDIUM
                    else:
                        severity = SeverityLevel.LOW

                    anomaly = Anomaly(
                        timestamp=datetime.fromisoformat(time_bucket),
                        anomaly_type=AnomalyType.RATE_LIMIT,
                        severity=severity,
                        description=f"Rate limit exceeded by {src_ip}",
                        source_ip=src_ip,
                        confidence=min(excess_ratio / 5.0, 1.0),
                        details={
                            'packets_per_second': count,
                            'rate_limit': self.rate_limit,
                            'excess_ratio': excess_ratio
                        }
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_traffic_bursts(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect sudden bursts in traffic
        Criteria: Sudden spike in traffic volume
        """
        anomalies = []

        if len(packets) < 10:
            return anomalies

        # Group packets by time windows (5-second windows)
        time_windows: Dict[str, int] = defaultdict(int)

        for pkt in packets:
            # Round to 5-second windows
            window = pkt.timestamp.replace(second=(pkt.timestamp.second // 5) * 5, microsecond=0)
            time_windows[str(window)] += 1

        # Calculate average and detect bursts
        if len(time_windows) < 3:
            return anomalies

        counts = list(time_windows.values())
        avg_count = sum(counts) / len(counts)

        for window, count in time_windows.items():
            if count > avg_count * 3 and count > self.burst_threshold:
                # Severity based on burst magnitude
                burst_ratio = count / avg_count

                if burst_ratio > 10:
                    severity = SeverityLevel.CRITICAL
                elif burst_ratio > 5:
                    severity = SeverityLevel.HIGH
                else:
                    severity = SeverityLevel.MEDIUM

                anomaly = Anomaly(
                    timestamp=datetime.fromisoformat(window),
                    anomaly_type=AnomalyType.BURST,
                    severity=severity,
                    description=f"Traffic burst detected: {count} packets in 5 seconds",
                    confidence=min(burst_ratio / 10.0, 1.0),
                    details={
                        'packets_in_window': count,
                        'average_packets': avg_count,
                        'burst_ratio': burst_ratio,
                        'window_size': '5 seconds'
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_periodic_patterns(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect suspiciously regular periodic patterns (potential beaconing)
        """
        anomalies = []

        # Group by source IP
        ip_timestamps: Dict[str, List[datetime]] = defaultdict(list)

        for pkt in packets:
            ip_timestamps[pkt.src_ip].append(pkt.timestamp)

        # Analyze time intervals for each IP
        for src_ip, timestamps in ip_timestamps.items():
            if len(timestamps) < 5:
                continue

            # Sort timestamps
            sorted_times = sorted(timestamps)

            # Calculate intervals between consecutive packets
            intervals = []
            for i in range(1, len(sorted_times)):
                interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                intervals.append(interval)

            if not intervals:
                continue

            # Check for regular intervals (potential beaconing)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5

            # Low variance with regular intervals suggests beaconing
            if avg_interval > 0 and std_dev / avg_interval < 0.1 and len(intervals) >= 5:
                anomaly = Anomaly(
                    timestamp=sorted_times[0],
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=SeverityLevel.MEDIUM,
                    description=f"Periodic beaconing pattern detected from {src_ip}",
                    source_ip=src_ip,
                    confidence=0.7,
                    details={
                        'average_interval_seconds': avg_interval,
                        'interval_variance': variance,
                        'pattern_count': len(intervals),
                        'pattern_type': 'beaconing'
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_time_based_anomalies(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect anomalies based on time of day
        Traffic during unusual hours (e.g., 2-5 AM) might be suspicious
        """
        anomalies = []

        # Count packets during unusual hours (2 AM - 5 AM)
        unusual_hour_packets = defaultdict(list)

        for pkt in packets:
            hour = pkt.timestamp.hour
            if 2 <= hour < 5:
                unusual_hour_packets[pkt.src_ip].append(pkt)

        # Report if significant traffic during unusual hours
        for src_ip, pkts in unusual_hour_packets.items():
            if len(pkts) > 20:
                severity = SeverityLevel.MEDIUM if len(pkts) > 100 else SeverityLevel.LOW

                anomaly = Anomaly(
                    timestamp=pkts[0].timestamp,
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=severity,
                    description=f"Unusual activity during off-hours from {src_ip}",
                    source_ip=src_ip,
                    confidence=0.6,
                    details={
                        'packet_count': len(pkts),
                        'time_period': '2 AM - 5 AM',
                        'pattern_type': 'off-hours activity'
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def detect(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect temporal anomalies in packets

        Args:
            packets: List of network packets

        Returns:
            List of detected anomalies
        """
        if not self.enabled or not packets:
            return []

        self.logger.info(f"Running temporal detection on {len(packets)} packets")

        anomalies = []

        # Run all temporal checks
        anomalies.extend(self._detect_rate_violations(packets))
        anomalies.extend(self._detect_traffic_bursts(packets))
        anomalies.extend(self._detect_periodic_patterns(packets))
        anomalies.extend(self._detect_time_based_anomalies(packets))

        self.detected_anomalies.extend(anomalies)
        self.logger.info(f"Detected {len(anomalies)} temporal anomalies")

        return anomalies
