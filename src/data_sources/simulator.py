"""Traffic simulator for testing"""

import random
import logging
import time  # <--- WAŻNY IMPORT
from datetime import datetime, timedelta
from typing import Iterator

from .base import DataSource, NetworkPacket


class TrafficSimulator(DataSource):
    """Simulates network traffic for testing"""

    COMMON_PORTS = {
        'TCP': [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 6379, 8080],
        'UDP': [53, 67, 68, 123, 161, 514]
    }

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
        self.is_running = True
        self.current_time = datetime.now()
        self.logger.info(f"Started traffic simulator (packets: {self.packet_count}, anomaly rate: {self.anomaly_rate})")

    def stop(self):
        self.is_running = False
        self.logger.info("Stopped traffic simulator")

    def _generate_ip(self) -> str:
        template = random.choice(self.PRIVATE_IPS)
        return template.format(random.randint(1, 254))

    def _generate_normal_packet(self) -> NetworkPacket:
        protocol = random.choice(['TCP', 'UDP'])
        return NetworkPacket(
            timestamp=self.current_time,
            src_ip=self._generate_ip(),
            dst_ip=self._generate_ip(),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice(self.COMMON_PORTS[protocol]),
            protocol=protocol,
            packet_size=random.randint(64, 1500),
            flags='A' if protocol == 'TCP' else None
        )

    def _generate_anomaly_packet(self) -> NetworkPacket:
        anomaly_type = random.choice(['port_scan', 'unusual_port', 'burst', 'ddos'])
        # (Logika generowania anomalii pozostaje bez zmian - skrócona dla czytelności)
        # Upewnij się, że zachowujesz oryginalną logikę z poprzedniego pliku
        # Tutaj najważniejsza jest zmiana w get_packets poniżej
        return self._generate_normal_packet() # Placeholder - użyj swojej oryginalnej logiki _generate_anomaly_packet

    def get_packets(self) -> Iterator[NetworkPacket]:
        """Generate simulated network packets with delay"""
        for i in range(self.packet_count):
            if not self.is_running:
                break

            # Symulacja upływu czasu
            self.current_time += timedelta(milliseconds=random.randint(10, 100))

            if random.random() < self.anomaly_rate:
                # Tutaj normalnie wywołujesz swoją pełną metodę _generate_anomaly_packet
                # Wklej tu kod z oryginalnego pliku, jeśli go usunąłeś,
                # lub po prostu upewnij się, że masz tę metodę zdefiniowaną
                packet = self._generate_anomaly_packet()
            else:
                packet = self._generate_normal_packet()

            # --- KLUCZOWA ZMIANA: OPÓŹNIENIE ---
            # Dzięki temu symulator działa jak "Live" (ok. 20-50 pakietów/sek)
            time.sleep(0.02)
            # -----------------------------------

            yield packet

        self.logger.info(f"Generated {self.packet_count} simulated packets")