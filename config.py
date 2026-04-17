import json
import os
import argparse
from types import SimpleNamespace


class ConfigError(Exception):
    pass


def _to_namespace(d):
    """Recursively convert dict to SimpleNamespace."""
    if isinstance(d, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in d.items()})
    elif isinstance(d, list):
        return [_to_namespace(x) for x in d]
    else:
        return d


def load_config(path: str):
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")

    with open(path, "r") as f:
        data = json.load(f)

    # Validate required sections
    required_sections = ["network", "transfer", "timers"]
    for section in required_sections:
        if section not in data:
            raise ConfigError(f"Missing required section: {section}")

    # Validate required network fields
    required_network = ["client_ip", "server_ip", "client_port", "server_port"]
    for field in required_network:
        if field not in data["network"]:
            raise ConfigError(f"Missing network field: {field}")

    # Default values
    data.setdefault("security", {"enabled": False})
    data.setdefault("debug", {})
    data["transfer"].setdefault("chunk_size", 1200)
    data["transfer"].setdefault("send_window_packets", 64)
    data["timers"].setdefault("rto_ms", 300)
    data["timers"].setdefault("ack_interval_ms", 50)
    data["timers"].setdefault("handshake_timeout_ms", 3000)
    
    # validate PSK
    if data["security"].get("enabled", False):
        psk = data["security"].get("psk", "")
        if len(psk) < 32:
            raise ConfigError("PSK must be at least 32 chars")

    return _to_namespace(data)

# extract psk from config as bytes
def get_psk(cfg) -> bytes:
    if not cfg.security.enabled:
        return b""
    return cfg.security.psk.encode()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--file", help="Filename (client only)")
    parser.add_argument("--override-server-ip", help="Override server IP")
    parser.add_argument("--override-client-ip", help="Override client IP")
    return parser.parse_args()


def apply_overrides(cfg, args):
    if args.override_server_ip:
        cfg.network.server_ip = args.override_server_ip
    if args.override_client_ip:
        cfg.network.client_ip = args.override_client_ip
    return cfg