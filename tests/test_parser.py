import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.parser.parser import parse_line, parse_file

VALID = ('10.10.10.1 - - [09/Aug/2026:15:19:47 +0000] '
         '"GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1" 200 1792 '
         '"http://localhost:8080/" "Mozilla/5.0"')


def test_parse_valid_line():
    ev = parse_line(VALID)
    assert ev["parse_status"] == "ok"
    assert ev["source_ip"] == "10.10.10.1"
    assert ev["method"] == "GET"
    assert ev["uri_path"] == "/vulnerabilities/sqli/"
    assert ev["query_params"]["id"] == "1"
    assert ev["status_code"] == 200


def test_parse_decodes_once():
    line = VALID.replace("id=1&", "id=O%27Brien&")
    ev = parse_line(line)
    assert ev["query_params"]["id"] == "O'Brien"


def test_parse_malformed():
    ev = parse_line('10.10.10.1 - - [ts] "-" 408 0 "-" "-"')
    assert ev["parse_status"] == "malformed"


def test_parse_empty_returns_none():
    assert parse_line("") is None


def test_benign_files_parse_without_crash():
    for i in (1, 2, 3):
        events, malformed = parse_file(f"data/benign_samples/benign_sample_0{i}.log")
        assert len(events) > 0
