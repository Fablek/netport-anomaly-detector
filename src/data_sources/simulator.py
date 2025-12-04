"""Traffic simulator for testing"""

import random
import logging
from datetime import datetime, timedelta
from typing import Iterator

from .base import DataSource, NetworkPacket


class TrafficSimulator(DataSource):
    """Simulates network traffic for testing"""

    # Common ports
    COMMON_PORTS = {
        'TCP': [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 6379, 8080],
        'UDP': [53, 67, 68, 123, 161, 514]
    }

    # Private IP ranges
    PRIVATE_IPS = [
        '192.168.1.{}',
        '192.168.0.{}',
        '10.0.0.{}',
        '172.16.0.{}'
    ]

    def __init__(self, packet_count: int = 1000, anomaly_rate: float = 0.1):
        super().__init__()
        self.packet_count = packet_count
        self.anomaly_rate = anomaly_rate
        self.logger = logging.getLogger(__name__)
        self.current_time = datetime.now()

    def start(self):
        """Start traffic simulation"""
        self.is_running = True
        self.current_time = datetime.now()
        self.logger.info(f"Started traffic simulator (packets: {self.packet_count}, anomaly rate: {self.anomaly_rate})")

    def stop(self):
        """Stop traffic simulation"""
        self.is_running = False
        self.logger.info("Stopped traffic simulator")

    def _generate_ip(self) -> str:
        """Generate a random IP address"""
        template = random.choice(self.PRIVATE_IPS)
        return template.format(random.randint(1, 254))

    def _generate_normal_packet(self) -> NetworkPacket:
        """Generate a normal network packet"""
        protocol = random.choice(['TCP', 'UDP'])
        src_ip = self._generate_ip()
        dst_ip = self._generate_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.COMMON_PORTS[protocol])
        packet_size = random.randint(64, 1500)

        # Increment time slightly
        self.current_time += timedelta(milliseconds=random.randint(1, 100))

        flags = None
        if protocol == 'TCP':
            flags = random.choice(['S', 'SA', 'A', 'FA', 'PA'])

        return NetworkPacket(
            timestamp=self.current_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            flags=flags
        )

    def _generate_anomaly_packet(self) -> NetworkPacket:
        """Generate an anomalous packet (port scan, unusual port, etc.)"""
        anomaly_type = random.choice(['port_scan', 'unusual_port', 'burst', 'ddos'])

        if anomaly_type == 'port_scan':
            # Sequential port scanning
            src_ip = self._generate_ip()
            dst_ip = self._generate_ip()
            dst_port = random.randint(1, 1024)  # Scanning low ports
            return NetworkPacket(
                timestamp=self.current_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(1024, 65535),
                dst_port=dst_port,
                protocol='TCP',
                packet_size=64,
                flags='S'  # SYN scan
            )

        elif anomaly_type == 'unusual_port':
            # Connection to unusual port
            return NetworkPacket(
                timestamp=self.current_time,
                src_ip=self._generate_ip(),
                dst_ip=self._generate_ip(),
                src_port=random.randint(1024, 65535),
                dst_port=random.randint(30000, 60000),  # Unusual port range
                protocol=random.choice(['TCP', 'UDP']),
                packet_size=random.randint(64, 1500),
                flags='S'
            )

        elif anomaly_type == 'ddos':
            # DDoS simulation - multiple connections from same IP
            src_ip = self._generate_ip()
            dst_ip = self._generate_ip()
            return NetworkPacket(
                timestamp=self.current_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443]),
                protocol='TCP',
                packet_size=random.randint(64, 128),
                flags='S'
            )

        else:  # burst
            # Traffic burst
            return NetworkPacket(
                timestamp=self.current_time,
                src_ip=self._generate_ip(),
                dst_ip=self._generate_ip(),
                src_port=random.randint(1024, 65535),
                dst_port=random.choice(self.COMMON_PORTS['TCP']),
                protocol='TCP',
                packet_size=random.randint(1200, 1500),  # Large packets
                flags='PA'
            )

    def get_packets(self) -> Iterator[NetworkPacket]:
        """
        Generate simulated network packets

        Yields:
            NetworkPacket: Simulated network packets
        """
        for i in range(self.packet_count):
            if not self.is_running:
                break

            # Randomly inject anomalies
            if random.random() < self.anomaly_rate:
                packet = self._generate_anomaly_packet()
            else:
                packet = self._generate_normal_packet()

            yield packet

        self.logger.info(f"Generated {self.packet_count} simulated packets")
