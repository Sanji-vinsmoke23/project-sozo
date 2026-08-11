import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.core.config import load_config


def test_config_sane():
    cfg = load_config()
    assert cfg["detection"]["brute_force"]["count"] > 0
    assert cfg["detection"]["scanner"]["count"] >= 10
    assert cfg["detection"]["brute_force"]["window_seconds"] > 0
    assert "127.0.0.1" in cfg["soar"]["allowlist"]
    assert cfg["system"]["dry_run"] is True
