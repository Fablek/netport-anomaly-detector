"""Base class for anomaly detectors"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from enum import Enum


class AnomalyType(Enum):
    """Types of anomalies"""
    STATISTICAL = "statistical"
    PORT_SCAN = "port_scan"
    DDOS = "ddos"
    UNUSUAL_PORT = "unusual_port"
    RATE_LIMIT = "rate_limit"
    BURST = "burst"
    ML_ISOLATION = "ml_isolation"
    ML_SVM = "ml_svm"


class SeverityLevel(Enum):
    """Severity levels for anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    timestamp: datetime
    anomaly_type: AnomalyType
    severity: SeverityLevel
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    confidence: float = 1.0
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert anomaly to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'type': self.anomaly_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'confidence': self.confidence,
            'details': self.details or {}
        }


class AnomalyDetector(ABC):
    """Abstract base class for anomaly detectors"""

    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.detected_anomalies: List[Anomaly] = []

    @abstractmethod
    def detect(self, packets: List) -> List[Anomaly]:
        """
        Detect anomalies in network packets

        Args:
            packets: List of NetworkPacket objects

        Returns:
            List of detected anomalies
        """
        pass

    def clear_anomalies(self):
        """Clear detected anomalies"""
        self.detected_anomalies = []

    def get_anomalies(self) -> List[Anomaly]:
        """Get all detected anomalies"""
        return self.detected_anomalies

    def enable(self):
        """Enable the detector"""
        self.enabled = True

    def disable(self):
        """Disable the detector"""
        self.enabled = False
