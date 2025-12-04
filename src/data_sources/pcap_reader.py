"""PCAP file reader data source"""

from pathlib import Path
from datetime import datetime
from typing import Iterator
import logging

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .base import DataSource, NetworkPacket


class PCAPReader(DataSource):
    """Reads network packets from PCAP files"""

    def __init__(self, pcap_file: str):
        super().__init__()
        self.pcap_file = Path(pcap_file)
        self.logger = logging.getLogger(__name__)

        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP reading. Install with: pip install scapy")

        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    def start(self):
        """Start reading PCAP file"""
        self.is_running = True
        self.logger.info(f"Started reading PCAP file: {self.pcap_file}")

    def stop(self):
        """Stop reading PCAP file"""
        self.is_running = False
        self.logger.info("Stopped PCAP reader")

    def get_packets(self) -> Iterator[NetworkPacket]:
        """
        Read and yield packets from PCAP file

        Yields:
            NetworkPacket: Parsed network packets
        """
        try:
            self.logger.info(f"Loading packets from {self.pcap_file}")
            packets = rdpcap(str(self.pcap_file))
            self.logger.info(f"Loaded {len(packets)} packets")

            for pkt in packets:
                if not self.is_running:
                    break

                # Only process IP packets
                if IP not in pkt:
                    continue

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
                    protocol = ip_layer.proto
                    src_port = 0
                    dst_port = 0

                # Create NetworkPacket
                packet = NetworkPacket(
                    timestamp=datetime.fromtimestamp(float(pkt.time)),
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packet_size=len(pkt),
                    flags=flags
                )

                yield packet

        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}")
            raise
