import os
import json
import re
import threading
from datetime import datetime

DEFAULT_CONFIG = {
  "network": {
    "default_ip_range": "192.168.1.0/24",
    "gateway_ip": "192.168.1.1",
    "scan_interval": "60",
    "device_discovery_settings": {
      "scapy_enabled": True,
      "ping_sweep_enabled": True,
      "arp_table_enabled": True
    }
  },
  "thresholds": {
    "cpu_alert_threshold": 90,
    "memory_alert_threshold": 85,
    "disk_usage_threshold": 90,
    "network_utilization_threshold": 80
  },
  "alerts": {
    "discord_webhook_url": "",
    "slack_webhook_url": "",
    "teams_webhook_url": "",
    "email_sender": "priyanshupri25@gmail.com",
    "email_password": "kygfclwiebnaxpqn",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email_recipients": {
      "level_1_email": "priyanshupri25@gmail.com",
      "level_2_email": "priyanshupri25@gmail.com",
      "level_3_email": "priyanshupri25@gmail.com"
    },
    "alert_severity_levels": {
      "level_1_seconds": 1800,
      "level_2_seconds": 7200,
      "level_3_seconds": 21600
    }
  },
  "monitoring": {
    "auto_scan_enabled": True,
    "scan_frequency": "60",
    "asset_discovery_settings": {
      "active_subnet_only": True
    },
    "risk_scoring_parameters": {
      "high_threat_ports": [23, 21],
      "medium_threat_ports": [22, 3389]
    }
  },
  "dashboard": {
    "refresh_interval": 30,
    "chart_settings": {
      "theme": "cyberpunk"
    },
    "widget_visibility": {
      "network_assets": True,
      "all_devices": True,
      "level_escalations": True
    }
  },
  "security": {
    "session_timeout": 3600,
    "failed_login_limits": 5,
    "password_policy_settings": {
      "min_length": 8,
      "require_special": True
    }
  },
  "cooldowns": {
    "low": 60,
    "medium": 45,
    "high": 30,
    "critical": 15
  }
}

class ConfigurationManager:
    def __init__(self, filepath="config.json"):
        self.filepath = filepath
        self.lock = threading.Lock()
        self.config = {}
        self.load()

    def load(self):
        with self.lock:
            # If the file does not exist, initialize with defaults
            if not os.path.exists(self.filepath):
                self.config = self._deep_copy(DEFAULT_CONFIG)
                self._save_unlocked()
                print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] config.json not found. Created with default values.")
                return

            try:
                with open(self.filepath, 'r') as f:
                    file_data = json.load(f)
            except Exception as e:
                print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] [ERROR] Failed to load config.json: {e}. Falling back to default settings.")
                self.config = self._deep_copy(DEFAULT_CONFIG)
                return

            # Merge defaults for any missing properties
            self.config = self._deep_merge(self._deep_copy(DEFAULT_CONFIG), file_data)
            
            # Validate configurations on startup
            errors = self.validate(self.config)
            if errors:
                print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] [WARNING] Configuration validation errors found:")
                for err in errors:
                    print(f"  - {err}")
                print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] Resolving invalid settings with defaults.")
                self._resolve_validation_errors(errors)
                self._save_unlocked()
            else:
                print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] Startup validation complete. Configuration is valid.")

    def _deep_copy(self, obj):
        return json.loads(json.dumps(obj))

    def _deep_merge(self, base, update):
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def validate(self, config_dict):
        errors = []
        
        # Check Network
        ip_range = config_dict.get("network", {}).get("default_ip_range", "")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", str(ip_range)):
            errors.append("network.default_ip_range: Invalid CIDR format.")
            
        gateway = config_dict.get("network", {}).get("gateway_ip", "")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(gateway)):
            errors.append("network.gateway_ip: Invalid IP address format.")
            
        # Check Thresholds
        threshold_keys = [
            "cpu_alert_threshold", "memory_alert_threshold", 
            "disk_usage_threshold", "network_utilization_threshold"
        ]
        for tk in threshold_keys:
            val = config_dict.get("thresholds", {}).get(tk)
            try:
                val_f = float(val)
                if not (0 <= val_f <= 100):
                    errors.append(f"thresholds.{tk}: Must be between 0 and 100.")
            except (ValueError, TypeError):
                errors.append(f"thresholds.{tk}: Must be a valid numeric value.")
                
        # Check Emails
        def is_valid_email(email):
            if not email:
                return True
            return "@" in str(email) and "." in str(email)

        sender = config_dict.get("alerts", {}).get("email_sender", "")
        if not is_valid_email(sender):
            errors.append("alerts.email_sender: Invalid email address format.")
            
        recipients = config_dict.get("alerts", {}).get("email_recipients", {})
        for r_lvl, email in recipients.items():
            if not is_valid_email(email):
                errors.append(f"alerts.email_recipients.{r_lvl}: Invalid email address format.")
                
        # Check SMTP server / port
        smtp_port = config_dict.get("alerts", {}).get("smtp_port")
        try:
            port_i = int(smtp_port)
            if not (1 <= port_i <= 65535):
                errors.append("alerts.smtp_port: Must be between 1 and 65535.")
        except (ValueError, TypeError):
            errors.append("alerts.smtp_port: Must be a valid integer.")
            
        # Check Security Limits
        timeout = config_dict.get("security", {}).get("session_timeout")
        try:
            if int(timeout) <= 0:
                errors.append("security.session_timeout: Must be a positive integer.")
        except (ValueError, TypeError):
            errors.append("security.session_timeout: Must be a valid integer.")
            
        failed_limit = config_dict.get("security", {}).get("failed_login_limits")
        try:
            if int(failed_limit) <= 0:
                errors.append("security.failed_login_limits: Must be a positive integer.")
        except (ValueError, TypeError):
            errors.append("security.failed_login_limits: Must be a valid integer.")

        # Check Cooldowns
        cooldowns = config_dict.get("cooldowns", {})
        for severity in ["low", "medium", "high", "critical"]:
            val = cooldowns.get(severity)
            try:
                val_i = int(val)
                if val_i <= 0:
                    errors.append(f"cooldowns.{severity}: Must be a positive integer.")
            except (ValueError, TypeError):
                errors.append(f"cooldowns.{severity}: Must be a valid integer.")
            
        return errors

    def _resolve_validation_errors(self, errors):
        for err in errors:
            key_path = err.split(":")[0].strip()
            # Restore the default value for this key path
            self.set(key_path, self._get_default_val(key_path))

    def _get_default_val(self, key_path):
        keys = key_path.split(".")
        current = DEFAULT_CONFIG
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return None
        return current

    def get(self, key_path, default=None):
        with self.lock:
            keys = key_path.split(".")
            current = self.config
            for k in keys:
                if isinstance(current, dict) and k in current:
                    current = current[k]
                else:
                    return default
            return current

    def set(self, key_path, value):
        keys = key_path.split(".")
        current = self.config
        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]
        
        # Validate value type if default exists
        default_val = self._get_default_val(key_path)
        if default_val is not None:
            try:
                if isinstance(default_val, bool):
                    if str(value).lower() in ["true", "1", "yes"]:
                        value = True
                    elif str(value).lower() in ["false", "0", "no"]:
                        value = False
                    else:
                        value = bool(value)
                elif isinstance(default_val, int):
                    value = int(value)
                elif isinstance(default_val, float):
                    value = float(value)
                elif isinstance(default_val, list):
                    if isinstance(value, str):
                        value = [v.strip() for v in value.split(",") if v.strip()]
                    else:
                        value = list(value)
            except:
                pass  # Use as-is if conversion fails
                
        current[keys[-1]] = value

    def save(self):
        with self.lock:
            self._save_unlocked()

    def _save_unlocked(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] [ERROR] Failed to save config.json: {e}")

    def restore_defaults(self):
        with self.lock:
            self.config = self._deep_copy(DEFAULT_CONFIG)
            self._save_unlocked()
            print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] Restored configurations to factory defaults.")

    def export_config(self):
        with self.lock:
            return json.dumps(self.config, indent=2)

    def import_config(self, json_str):
        try:
            parsed = json.loads(json_str)
        except Exception as e:
            return f"Invalid JSON string: {e}"

        errors = self.validate(parsed)
        if errors:
            return f"Validation failed:\n" + "\n".join([f"- {err}" for err in errors])

        with self.lock:
            self.config = self._deep_merge(self._deep_copy(DEFAULT_CONFIG), parsed)
            self._save_unlocked()
            print(f"[{datetime.now().isoformat()}] [CONFIG_MGR] Imported configuration from external JSON.")
        return None

# Singleton instance for the application
config_mgr = ConfigurationManager()
