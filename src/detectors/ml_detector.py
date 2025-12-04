"""Machine Learning-based anomaly detection"""

import numpy as np
import logging
from datetime import datetime
from typing import List
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

from .base import AnomalyDetector, Anomaly, AnomalyType, SeverityLevel
from ..data_sources.base import NetworkPacket


class MLDetector(AnomalyDetector):
    """Detects anomalies using Machine Learning algorithms"""

    def __init__(self,
                 use_isolation_forest: bool = True,
                 use_one_class_svm: bool = True,
                 contamination: float = 0.1,
                 nu: float = 0.1):
        super().__init__("ML Detector")
        self.use_isolation_forest = use_isolation_forest
        self.use_one_class_svm = use_one_class_svm
        self.contamination = contamination
        self.nu = nu
        self.logger = logging.getLogger(__name__)

        # Initialize models
        self.isolation_forest = None
        self.one_class_svm = None
        self.scaler = StandardScaler()
        self.is_trained = False

    def _extract_features(self, packets: List[NetworkPacket]) -> np.ndarray:
        """
        Extract numerical features from packets for ML

        Features:
        - Source port
        - Destination port
        - Packet size
        - Protocol (encoded as number)
        - Hour of day
        """
        features = []

        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}

        for pkt in packets:
            # Convert protocol to number
            proto_num = protocol_map.get(pkt.protocol, 0)

            # Extract hour from timestamp
            hour = pkt.timestamp.hour

            feature_vector = [
                pkt.src_port,
                pkt.dst_port,
                pkt.packet_size,
                proto_num,
                hour
            ]

            features.append(feature_vector)

        return np.array(features)

    def train(self, packets: List[NetworkPacket]):
        """
        Train ML models on normal traffic

        Args:
            packets: List of normal network packets for training
        """
        if not packets or len(packets) < 10:
            self.logger.warning("Not enough packets for ML training")
            return

        self.logger.info(f"Training ML models on {len(packets)} packets")

        # Extract and scale features
        features = self._extract_features(packets)
        scaled_features = self.scaler.fit_transform(features)

        # Train Isolation Forest
        if self.use_isolation_forest:
            self.isolation_forest = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                random_state=42
            )
            self.isolation_forest.fit(scaled_features)
            self.logger.info("Isolation Forest model trained")

        # Train One-Class SVM
        if self.use_one_class_svm:
            self.one_class_svm = OneClassSVM(
                nu=self.nu,
                gamma='auto',
                kernel='rbf'
            )
            self.one_class_svm.fit(scaled_features)
            self.logger.info("One-Class SVM model trained")

        self.is_trained = True

    def detect(self, packets: List[NetworkPacket]) -> List[Anomaly]:
        """
        Detect anomalies using ML models

        Args:
            packets: List of network packets to analyze

        Returns:
            List of detected anomalies
        """
        if not self.enabled or not packets:
            return []

        anomalies = []

        # Auto-train if not trained yet (using first batch as normal traffic)
        if not self.is_trained:
            self.logger.info("Auto-training on first batch of packets")
            self.train(packets)
            return []  # Don't detect on training data

        self.logger.info(f"Running ML detection on {len(packets)} packets")

        # Extract and scale features
        features = self._extract_features(packets)
        scaled_features = self.scaler.transform(features)

        # Isolation Forest detection
        if self.use_isolation_forest and self.isolation_forest:
            predictions = self.isolation_forest.predict(scaled_features)
            scores = self.isolation_forest.score_samples(scaled_features)

            for i, (pred, score, pkt) in enumerate(zip(predictions, scores, packets)):
                if pred == -1:  # Anomaly detected
                    # Convert score to confidence (more negative = more anomalous)
                    confidence = min(abs(score) / 2.0, 1.0)

                    severity = SeverityLevel.HIGH if confidence > 0.7 else SeverityLevel.MEDIUM

                    anomaly = Anomaly(
                        timestamp=pkt.timestamp,
                        anomaly_type=AnomalyType.ML_ISOLATION,
                        severity=severity,
                        description="Anomaly detected by Isolation Forest",
                        source_ip=pkt.src_ip,
                        destination_ip=pkt.dst_ip,
                        port=pkt.dst_port,
                        confidence=confidence,
                        details={
                            'anomaly_score': float(score),
                            'model': 'Isolation Forest',
                            'packet_size': pkt.packet_size,
                            'protocol': pkt.protocol
                        }
                    )
                    anomalies.append(anomaly)

        # One-Class SVM detection
        if self.use_one_class_svm and self.one_class_svm:
            predictions = self.one_class_svm.predict(scaled_features)
            scores = self.one_class_svm.decision_function(scaled_features)

            for i, (pred, score, pkt) in enumerate(zip(predictions, scores, packets)):
                if pred == -1:  # Anomaly detected
                    confidence = min(abs(score) / 2.0, 1.0)

                    severity = SeverityLevel.HIGH if confidence > 0.7 else SeverityLevel.MEDIUM

                    # Avoid duplicate anomalies (same packet detected by both models)
                    if not any(a.timestamp == pkt.timestamp and a.source_ip == pkt.src_ip for a in anomalies):
                        anomaly = Anomaly(
                            timestamp=pkt.timestamp,
                            anomaly_type=AnomalyType.ML_SVM,
                            severity=severity,
                            description="Anomaly detected by One-Class SVM",
                            source_ip=pkt.src_ip,
                            destination_ip=pkt.dst_ip,
                            port=pkt.dst_port,
                            confidence=confidence,
                            details={
                                'decision_score': float(score),
                                'model': 'One-Class SVM',
                                'packet_size': pkt.packet_size,
                                'protocol': pkt.protocol
                            }
                        )
                        anomalies.append(anomaly)

        self.detected_anomalies.extend(anomalies)
        self.logger.info(f"Detected {len(anomalies)} ML-based anomalies")

        return anomalies
