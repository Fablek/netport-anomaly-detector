"""
Network Port Anomaly Detector - Main Application
Cybersecurity Module 3 Project
"""

import sys
import argparse
import threading
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.analyzer import NetworkAnalyzer
from src.dashboard.app import run_dashboard, update_dashboard, set_running_state, clear_dashboard
from src.utils.config_loader import ConfigLoader
from src.utils.report_generator import ReportGenerator
from src.utils.logger import setup_logger


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='Network Port Anomaly Detector'
    )

    parser.add_argument('--mode', choices=['simulator', 'pcap', 'live'],
                       help='Data source mode')
    parser.add_argument('--pcap-file', type=str,
                       help='PCAP file path (for pcap mode)')
    parser.add_argument('--interface', type=str,
                       help='Network interface (for live mode)')
    parser.add_argument('--config', type=str,
                       help='Configuration file path')
    parser.add_argument('--no-dashboard', action='store_true',
                       help='Run without web dashboard')
    parser.add_argument('--report-only', action='store_true',
                       help='Generate reports and exit')
    parser.add_argument('--output-dir', type=str, default='reports',
                       help='Output directory for reports')

    args = parser.parse_args()
    logger = setup_logger("Main", level="INFO")

    print("""
╔═══════════════════════════════════════════════════════════════╗
║     🛡️  Network Port Anomaly Detector v1.0                   ║
║     Cybersecurity Module 3 Project                            ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    try:
        # Load or update configuration
        config = ConfigLoader(args.config)

        # Override config with command line arguments
        if args.mode:
            config.config['data_source']['mode'] = args.mode
        if args.pcap_file:
            config.config['data_source']['pcap_file'] = args.pcap_file
        if args.interface:
            config.config['data_source']['network_interface'] = args.interface

        # Initialize analyzer WITH CONFIG OBJECT
        logger.info("Initializing Network Analyzer...")
        analyzer = NetworkAnalyzer(config)

        report_gen = ReportGenerator(args.output_dir)

        if args.report_only:
            logger.info("Running analysis in report-only mode...")
            analyzer.start()
            while analyzer.is_running:
                time.sleep(1)

            # Generate reports logic for report-only mode
            logger.info("Generating reports...")
            statistics = analyzer.get_statistics()
            reports = report_gen.generate_all_reports(
                analyzer.packets,
                analyzer.anomalies,
                statistics
            )
            print("\n📊 Reports generated:")
            for format_type, path in reports.items():
                if path:
                    print(f"  - {format_type.upper()}: {path}")
            return

        # Setup dashboard integration
        if not args.no_dashboard:
            analyzer.set_dashboard_callback(update_dashboard)

            # Handle port conflict or custom port
            dash_port = int(config.dashboard_port)

            # Start dashboard thread
            dashboard_thread = threading.Thread(
                target=run_dashboard,
                args=(config.dashboard_host, dash_port, False),
                daemon=True
            )
            dashboard_thread.start()

            logger.info(f"Dashboard started at http://{config.dashboard_host}:{dash_port}")
            print(f"\n🌐 Dashboard: http://{config.dashboard_host}:{dash_port}")

            time.sleep(2)

        # Start analyzer
        logger.info("Starting network traffic analysis...")
        print(f"📡 Data Source: {config.data_source_mode}")
        print("🔍 Detection Methods: Statistical, ML (Isolation Forest, SVM), Heuristic, Temporal")
        print("\n⏳ Analysis in progress...\n")

        set_running_state(True)
        analyzer.start()

        # Wait loop - keep running analysis
        try:
            while True:
                if not analyzer.is_running and config.data_source_mode != 'live':
                     # Jeśli analiza się skończyła (symulator/pcap), wychodzimy z pętli czekania na analizę
                     break
                time.sleep(1)
        except KeyboardInterrupt:
            # Przerwanie analizy przez użytkownika
            pass

        set_running_state(False)
        analyzer.stop()

        # Display summary
        statistics = analyzer.get_statistics()
        print("\n" + "="*70)
        print("📊 ANALYSIS SUMMARY")
        print("="*70)
        print(f"Total Packets Analyzed: {statistics['total_packets']}")
        print(f"Total Anomalies Detected: {statistics['total_anomalies']}")
        print(f"Detection Rate: {statistics['detection_rate']:.2f}%")

        if statistics.get('anomaly_types'):
            print("\nAnomalies by Type:")
            for atype, count in statistics['anomaly_types'].items():
                print(f"  - {atype}: {count}")

        if statistics.get('severity_distribution'):
            print("\nSeverity Distribution:")
            for severity, count in statistics['severity_distribution'].items():
                print(f"  - {severity.upper()}: {count}")

        # Generate reports
        print("\n📄 Generating reports...")
        reports = report_gen.generate_all_reports(
            analyzer.packets,
            analyzer.anomalies,
            statistics
        )

        print("\n✅ Reports generated:")
        for format_type, path in reports.items():
            if path:
                print(f"  - {format_type.upper()}: {path}")

        print("\n" + "="*70)
        print("✅ Analysis completed successfully!")
        print("="*70)

        if not args.no_dashboard:
            print("\n💡 Dashboard is still running. Press Ctrl+C to exit.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n\n👋 Shutting down...")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()