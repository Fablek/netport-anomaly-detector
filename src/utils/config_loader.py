"""Configuration loader utility"""

import yaml
import os
from pathlib import Path


class ConfigLoader:
    """Loads and manages application configuration"""

    def __init__(self, config_path: str = None):
        if config_path is None:
            # Default to config/config.yaml relative to project root
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "config" / "config.yaml"

        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing configuration file: {e}")

    def get(self, key_path: str, default=None):
        """
        Get configuration value using dot notation
        Example: config.get('detection.ml.enabled')
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()

    @property
    def data_source_mode(self) -> str:
        return self.get('data_source.mode', 'simulator')

    @property
    def pcap_file(self) -> str:
        return self.get('data_source.pcap_file', 'data/sample_traffic.pcap')

    @property
    def network_interface(self) -> str:
        return self.get('data_source.network_interface', 'en0')

    @property
    def dashboard_host(self) -> str:
        return self.get('dashboard.host', '127.0.0.1')

    @property
    def dashboard_port(self) -> int:
        return self.get('dashboard.port', 5000)
