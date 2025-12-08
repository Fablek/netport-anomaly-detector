"""Heuristic-based anomaly detection (port scanning, DDoS, etc.)"""

import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict

from .base import AnomalyDetector, Anomaly, AnomalyType, SeverityLevel
from ..data_sources.base import NetworkPacket


class HeuristicDetector(AnomalyDetector):
    """Detects anomalies using predefined heuristic rules"""

    def __init__(self,
                 port_scan_threshold: int = 10,
                 port_scan_window: int = 5,
                 ddos_threshold: int = 100,
                 ddos_window: int = 1):
        super().__init__("Heuristic Detector")
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.ddos_threshold = ddos_threshold
        self.ddos_window = ddos_window
        self.logger = logging.getLogger(__name__)

    def _detect_port_scanning(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect port scanning activity
        Criteria: Same source IP accessing many different ports in short time
        """
        anomalies = []

        # Group packets by source IP and time window
        ip_port_access: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

        for pkt in packets:
            time_bucket = pkt.timestamp.replace(second=0, microsecond=0)
            ip_port_access[pkt.src_ip][str(time_bucket)].add(pkt.dst_port)

        # Check for port scanning
        for src_ip, time_buckets in ip_port_access.items():
            for time_bucket, ports in time_buckets.items():
                unique_ports = len(ports)

                if unique_ports >= self.port_scan_threshold:
                    # Severity based on number of ports scanned
                    if unique_ports > 50:
                        severity = SeverityLevel.CRITICAL
                    elif unique_ports > 25:
                        severity = SeverityLevel.HIGH
                    else:
                        severity = SeverityLevel.MEDIUM

                    anomaly = Anomaly(
                        timestamp=datetime.fromisoformat(time_bucket),
                        anomaly_type=AnomalyType.PORT_SCAN,
                        severity=severity,
                        description=f"Port scanning detected from {src_ip}",
                        source_ip=src_ip,
                        confidence=min(unique_ports / self.port_scan_threshold, 1.0),
                        details={
                            'unique_ports_accessed': unique_ports,
                            'ports': sorted(list(ports))[:20],  # First 20 ports
                            'scan_type': 'horizontal' if unique_ports > 30 else 'targeted'
                        }
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_ddos(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect DDoS attacks
        Criteria: Excessive connections to same destination in short time
        """
        anomalies = []

        # Group by destination IP and count connections per time window
        dst_connections: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for pkt in packets:
            # Use 1-second buckets for DDoS detection
            time_bucket = pkt.timestamp.replace(microsecond=0)
            dst_connections[pkt.dst_ip][str(time_bucket)] += 1

        # Check for DDoS
        for dst_ip, time_buckets in dst_connections.items():
            for time_bucket, count in time_buckets.items():
                if count >= self.ddos_threshold:
                    # Severity based on connection count
                    if count > 500:
                        severity = SeverityLevel.CRITICAL
                    elif count > 250:
                        severity = SeverityLevel.HIGH
                    else:
                        severity = SeverityLevel.MEDIUM

                    anomaly = Anomaly(
                        timestamp=datetime.fromisoformat(time_bucket),
                        anomaly_type=AnomalyType.DDOS,
                        severity=severity,
                        description=f"Potential DDoS attack targeting {dst_ip}",
                        destination_ip=dst_ip,
                        confidence=min(count / (self.ddos_threshold * 2), 1.0),
                        details={
                            'connections_per_second': count,
                            'threshold': self.ddos_threshold,
                            'attack_type': 'volumetric'
                        }
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_syn_flood(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect SYN flood attacks
        Criteria: Excessive SYN packets without corresponding ACKs
        """
        anomalies = []

        # Count SYN flags per destination IP
        syn_counts: Dict[str, int] = defaultdict(int)
        total_counts: Dict[str, int] = defaultdict(int)

        for pkt in packets:
            if pkt.protocol == 'TCP' and pkt.flags:
                total_counts[pkt.dst_ip] += 1
                if 'S' in pkt.flags and 'A' not in pkt.flags:
                    syn_counts[pkt.dst_ip] += 1

        # Detect SYN flood
        for dst_ip, syn_count in syn_counts.items():
            total = total_counts.get(dst_ip, 0)
            if total > 0:
                syn_ratio = syn_count / total

                # If more than 70% are SYN packets, potential SYN flood
                if syn_ratio > 0.7 and syn_count > 20:
                    severity = SeverityLevel.HIGH if syn_count > 100 else SeverityLevel.MEDIUM

                    anomaly = Anomaly(
                        timestamp=datetime.now(),
                        anomaly_type=AnomalyType.DDOS,
                        severity=severity,
                        description=f"SYN flood attack detected targeting {dst_ip}",
                        destination_ip=dst_ip,
                        confidence=min(syn_ratio, 1.0),
                        details={
                            'syn_packets': syn_count,
                            'total_packets': total,
                            'syn_ratio': syn_ratio,
                            'attack_type': 'SYN flood'
                        }
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_unusual_ports(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect connections to unusual/suspicious ports
        """
        anomalies = []

        # Define suspicious port ranges
        # High ports (> 49152) or uncommon service ports
        suspicious_high_ports = range(49152, 65536)
        common_ports = {
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 443,  # Standard
            3306, 5432, 6379, 8080, 8443, 8000, 8008, 8009,  # Dev/DB
            5353, 1900, 5000, 5001,  # mDNS, UPnP, Flask
            993, 465, 587  # Secure Email
        }

        suspicious_connections: Dict[int, List[NetworkPacket]] = defaultdict(list)

        for pkt in packets:
            if pkt.dst_port >= 49152:
                continue

            if pkt.dst_port not in common_ports and pkt.dst_port > 1024:
                suspicious_connections[pkt.dst_port].append(pkt)

        # Report if multiple connections to same unusual port
        for port, pkts in suspicious_connections.items():
            if len(pkts) >= 5:  # At least 5 connections to unusual port
                severity = SeverityLevel.MEDIUM if len(pkts) > 20 else SeverityLevel.LOW

                anomaly = Anomaly(
                    timestamp=pkts[0].timestamp,
                    anomaly_type=AnomalyType.UNUSUAL_PORT,
                    severity=severity,
                    description=f"Multiple connections to unusual port {port}",
                    port=port,
                    confidence=0.6,
                    details={
                        'port': port,
                        'connection_count': len(pkts),
                        'unique_sources': len(set(p.src_ip for p in pkts))
                    }
                )
                anomalies.append(anomaly)

        return anomalies

    def detect(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect anomalies using heuristic rules

        Args:
            packets: List of network packets

        Returns:
            List of detected anomalies
        """
        if not self.enabled or not packets:
            return []

        self.logger.info(f"Running heuristic detection on {len(packets)} packets")

        anomalies = []

        # Run all heuristic checks
        anomalies.extend(self._detect_port_scanning(packets))
        anomalies.extend(self._detect_ddos(packets))
        anomalies.extend(self._detect_syn_flood(packets))
        anomalies.extend(self._detect_unusual_ports(packets))

        self.detected_anomalies.extend(anomalies)
        self.logger.info(f"Detected {len(anomalies)} heuristic anomalies")

        return anomalies
