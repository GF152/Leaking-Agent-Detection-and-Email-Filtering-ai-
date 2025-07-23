"""
Configuration Management Module
Handles loading and managing system configuration
"""
import json
import os
import logging
from pathlib import Path

class ConfigManager:
    """Configuration management class"""

    def __init__(self, config_path="config/config.json"):
        self.config_path = config_path
        self.config = {}
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                # Create default configuration
                self.config = self.get_default_config()
                self.save_config()
        except Exception as e:
            print(f"Error loading config: {e}")
            self.config = self.get_default_config()

    def get_default_config(self):
        """Get default configuration"""
        return {
            "system": {
                "name": "Leaking Agent Detection System",
                "version": "1.0.0",
                "debug": False
            },
            "email_filtering": {
                "spam_threshold": 0.6,
                "phishing_threshold": 0.7,
                "malware_threshold": 0.8,
                "use_bert_model": True,
                "model_path": "models/",
                "max_email_size": "10MB"
            },
            "behavioral_analysis": {
                "anomaly_threshold": 0.7,
                "learning_rate": 0.01,
                "baseline_update_frequency": "daily",
                "risk_score_weights": {
                    "time_anomaly": 0.2,
                    "volume_anomaly": 0.25,
                    "access_pattern_anomaly": 0.2,
                    "data_movement_anomaly": 0.35
                }
            },
            "database": {
                "type": "sqlite",
                "path": "data/system.db",
                "backup_frequency": "daily"
            },
            "logging": {
                "level": "INFO",
                "file": "logs/system.log",
                "max_size": "100MB",
                "backup_count": 5
            }
        }

    def save_config(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")

    def get(self, key, default=None):
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key, value):
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config_ref = self.config

        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]

        config_ref[keys[-1]] = value
        self.save_config()
