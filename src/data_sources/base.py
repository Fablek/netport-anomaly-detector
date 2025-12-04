"""Base class for data sources"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


@dataclass
class NetworkPacket:
    """Represents a network packet"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert packet to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'flags': self.flags
        }


class DataSource(ABC):
    """Abstract base class for data sources"""

    def __init__(self):
        self.is_running = False

    @abstractmethod
    def start(self):
        """Start the data source"""
        pass

    @abstractmethod
    def stop(self):
        """Stop the data source"""
        pass

    @abstractmethod
    def get_packets(self) -> Iterator[NetworkPacket]:
        """
        Get packets from the data source

        Yields:
            NetworkPacket: Individual network packets
        """
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
