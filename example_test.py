"""
Example script demonstrating the Network Anomaly Detector API
This shows how to use the detector programmatically without running the full application
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.data_sources.simulator import TrafficSimulator
from src.detectors.statistical_detector import StatisticalDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.detectors.temporal_detector import TemporalDetector


def main():
    print("="*70)
    print("Network Anomaly Detector - Example Test")
    print("="*70)

    # Create traffic simulator
    print("\n1. Generating simulated network traffic...")
    simulator = TrafficSimulator(packet_count=500, anomaly_rate=0.15)
    simulator.start()

    # Collect packets
    packets = list(simulator.get_packets())
    print(f"   Generated {len(packets)} packets (15% anomalies)")

    # Initialize detectors
    print("\n2. Initializing detectors...")
    statistical = StatisticalDetector(z_score_threshold=2.5)
    heuristic = HeuristicDetector(port_scan_threshold=8)
    temporal = TemporalDetector(rate_limit=40)

    print("   - Statistical Detector (z-score threshold: 2.5)")
    print("   - Heuristic Detector (port scan threshold: 8)")
    print("   - Temporal Detector (rate limit: 40 pps)")

    # Run detection
    print("\n3. Running anomaly detection...")

    stat_anomalies = statistical.detect(packets)
    print(f"   - Statistical: {len(stat_anomalies)} anomalies")

    heur_anomalies = heuristic.detect(packets)
    print(f"   - Heuristic: {len(heur_anomalies)} anomalies")

    temp_anomalies = temporal.detect(packets)
    print(f"   - Temporal: {len(temp_anomalies)} anomalies")

    # Combine all anomalies
    all_anomalies = stat_anomalies + heur_anomalies + temp_anomalies
    print(f"\n   Total anomalies detected: {len(all_anomalies)}")

    # Display sample anomalies
    if all_anomalies:
        print("\n4. Sample Anomalies:")
        print("-" * 70)

        for i, anomaly in enumerate(all_anomalies[:10], 1):
            print(f"\n   [{i}] {anomaly.anomaly_type.value.upper()}")
            print(f"       Severity: {anomaly.severity.value}")
            print(f"       Description: {anomaly.description}")
            if anomaly.source_ip:
                print(f"       Source IP: {anomaly.source_ip}")
            if anomaly.destination_ip:
                print(f"       Destination IP: {anomaly.destination_ip}")
            if anomaly.port:
                print(f"       Port: {anomaly.port}")
            print(f"       Confidence: {anomaly.confidence:.2%}")

        if len(all_anomalies) > 10:
            print(f"\n   ... and {len(all_anomalies) - 10} more anomalies")

    # Statistics
    print("\n5. Statistics:")
    print("-" * 70)

    from collections import Counter

    anomaly_types = Counter(a.anomaly_type.value for a in all_anomalies)
    print("   Anomalies by type:")
    for atype, count in anomaly_types.most_common():
        print(f"     - {atype}: {count}")

    severity_dist = Counter(a.severity.value for a in all_anomalies)
    print("\n   Severity distribution:")
    for severity, count in severity_dist.most_common():
        print(f"     - {severity.upper()}: {count}")

    print("\n" + "="*70)
    print("Test completed successfully!")
    print("="*70)


if __name__ == '__main__':
    main()
