"""Sozo Structured Log Parser (R-011 / R-020)."""
import re
import sys
import uuid
import urllib.parse
from datetime import datetime, timezone

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
)


def normalize_ts(ts):
    dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_line(line):
    line = line.strip()
    if not line:
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return {"parse_status": "malformed", "raw": line}
    uri = m.group("uri")
    parts = uri.split("?", 1)
    path = parts[0]
    query = parts[1] if len(parts) > 1 else ""
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    return {
        "event_id": uuid.uuid4().hex,
        "event_ts": normalize_ts(m.group("ts")),
        "source_ip": m.group("ip"),
        "method": m.group("method"),
        "uri_path": path,
        "uri_query": query,
        "query_params": params,
        "status_code": int(m.group("status")),
        "response_bytes": 0 if m.group("bytes") == "-" else int(m.group("bytes")),
        "user_agent": m.group("ua"),
        "referer": m.group("referer"),
        "parse_status": "ok",
    }


def parse_file(path):
    events, malformed = [], 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            ev = parse_line(line)
            if ev is None:
                continue
            if ev["parse_status"] == "malformed":
                malformed += 1
            else:
                events.append(ev)
    return events, malformed


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/benign_samples/benign_sample_01.log"
    events, malformed = parse_file(target)
    print(f"[PARSER] file={target}")
    print(f"[PARSER] parsed_ok={len(events)} malformed={malformed}")
    if events:
        e = events[0]
        print(f"[PARSER] sample: ip={e['source_ip']} ts={e['event_ts']} "
              f"{e['method']} {e['uri_path']} params={e['query_params']} status={e['status_code']}")
