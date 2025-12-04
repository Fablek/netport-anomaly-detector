"""Live network capture data source"""

import logging
from datetime import datetime
from typing import Iterator

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .base import DataSource, NetworkPacket


class LiveCapture(DataSource):
    """Captures live network traffic"""

    def __init__(self, interface: str = None, packet_count: int = 100):
        super().__init__()
        self.interface = interface
        self.packet_count = packet_count
        self.logger = logging.getLogger(__name__)
        self.captured_packets = []

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

    def _packet_handler(self, pkt):
        """Handle captured packet"""
        if IP not in pkt:
            return

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

        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=len(pkt),
            flags=flags
        )

        self.captured_packets.append(packet)

    def get_packets(self) -> Iterator[NetworkPacket]:
        """
        Capture and yield live packets

        Yields:
            NetworkPacket: Live network packets
        """
        try:
            self.logger.info(f"Starting packet capture (count: {self.packet_count})")

            # Capture packets
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=self.packet_count,
                store=False
            )

            # Yield captured packets
            for packet in self.captured_packets:
                if not self.is_running:
                    break
                yield packet

            self.captured_packets = []

        except PermissionError:
            self.logger.error("Permission denied. Live capture requires root/administrator privileges")
            raise
        except Exception as e:
            self.logger.error(f"Error during live capture: {e}")
            raise
