"""Sozo config loader (E1). Single source of truth for all tunables."""
import copy
import os
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CONFIG_PATH = os.path.join(ROOT, "config", "sozo.yaml")

DEFAULTS = {
    "system": {"name": "Project Sozo", "demo_mode": True, "dry_run": True},
    "database": {"path": "sozo.db"},
    "collector": {"container": "sozo_victim",
                  "log_path": "/var/log/apache2/access.log",
                  "flush_interval_seconds": 2, "flush_batch_size": 50},
    "detection": {
        "sqli": {"enabled": True},
        "brute_force": {"enabled": True, "count": 5, "window_seconds": 300,
                        "high_count": 10, "high_window_seconds": 600},
        "scanner": {"enabled": True, "count": 20, "window_seconds": 60},
    },
    "soar": {"allowlist": ["127.0.0.1"], "ttl_first_minutes": 30,
             "ttl_repeat_minutes": 120, "ttl_max_auto_minutes": 1440,
             "max_concurrent_blocks": 100},
    "narrator": {"model": "phi4-mini", "max_evidence_chars": 80},
}


def _deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path=DEFAULT_CONFIG_PATH):
    cfg = copy.deepcopy(DEFAULTS)
    if os.path.exists(path):
        with open(path, "r") as f:
            cfg = _deep_merge(cfg, yaml.safe_load(f) or {})
    return cfg


def db_path(cfg):
    p = cfg["database"]["path"]
    return p if os.path.isabs(p) else os.path.join(ROOT, p)


if __name__ == "__main__":
    c = load_config()
    print(f"[CONFIG] loaded: {DEFAULT_CONFIG_PATH}")
    print(f"[CONFIG] demo_mode={c['system']['demo_mode']} dry_run={c['system']['dry_run']}")
    print(f"[CONFIG] brute={c['detection']['brute_force']['count']}/{c['detection']['brute_force']['window_seconds']}s "
          f"scan={c['detection']['scanner']['count']}/{c['detection']['scanner']['window_seconds']}s")
    print(f"[CONFIG] allowlist={c['soar']['allowlist']} ttl_first={c['soar']['ttl_first_minutes']}m")
