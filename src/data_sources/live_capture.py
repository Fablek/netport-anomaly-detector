"""Live network capture data source"""

import logging
from datetime import datetime
from typing import Iterator
import time

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .base import DataSource, NetworkPacket


class LiveCapture(DataSource):
    """Captures live network traffic"""

    def __init__(self, interface: str = None, packet_count: int = 100):
        # packet_count w trybie live ignorujemy jako limit całkowity,
        # użyjemy go jako rozmiaru buffora (batch size)
        super().__init__()
        self.interface = interface
        self.batch_size = 50  # Pobieraj po 50 pakietów na raz
        self.logger = logging.getLogger(__name__)

        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for live capture. Install with: pip install scapy")

    def start(self):
        """Start live capture"""
        self.is_running = True
        self.logger.info(f"Started live capture on interface: {self.interface or 'default'}")
        self.logger.warning("Live capture requires root/administrator privileges")

    def stop(self):
        """Stop live capture"""
        self.is_running = False
        self.logger.info("Stopped live capture")

    def _process_packet(self, pkt) -> NetworkPacket:
        """Convert Scapy packet to NetworkPacket"""
        if IP not in pkt:
            return None

        ip_layer = pkt[IP]
        protocol = None
        src_port = 0
        dst_port = 0
        flags = None

        # Extract TCP/UDP information
        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            protocol = str(ip_layer.proto)

        return NetworkPacket(
            timestamp=datetime.now(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=len(pkt),
            flags=flags
        )

    def get_packets(self) -> Iterator[NetworkPacket]:
        """
        Capture and yield live packets continuously

        Yields:
            NetworkPacket: Live network packets
        """
        try:
            self.logger.info("Starting continuous packet capture...")

            # Pętla nieskończona - działa dopóki nie zatrzymamy programu
            while self.is_running:
                # Pobieramy małą partię pakietów (np. 50) z timeoutem
                # Timeout jest ważny, żeby pętla nie wisiała w nieskończoność przy braku ruchu
                packets = sniff(
                    iface=self.interface,
                    count=self.batch_size,
                    timeout=1.0,  # Czekaj max 1 sekundę na pakiety
                    store=True    # Musimy zapisać, żeby je przetworzyć
                )

                if not packets:
                    continue

                for pkt in packets:
                    processed_pkt = self._process_packet(pkt)
                    if processed_pkt:
                        yield processed_pkt

                if len(packets) == 0:
                    time.sleep(0.1)

        except PermissionError:
            self.logger.error("Permission denied. Live capture requires root/administrator privileges")
            raise
        except Exception as e:
            self.logger.error(f"Error during live capture: {e}")
            raise