# Event Schema Specification v1

| Field Name | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `id` | String | Unique Event UUID | `"a1b2c3d4-e5f6-7890-1234-56789abcdef0"` |
| `timestamp` | String | ISO 8601 UTC Timestamp | `"2026-08-05T22:00:00Z"` |
| `source_ip` | String | IPv4/IPv6 Address | `"172.28.0.20"` |
| `attack_type` | String | Threat Classification | `"SQL_Injection"` |
| `owasp_ref` | String | OWASP Top 10 Category | `"A03:2021-Injection"` |
| `mitre_ref` | String | MITRE ATT&CK Technique ID | `"T1190"` |
| `confidence` | Float | Confidence Level (0.0 - 1.0) | `0.95` |
| `severity` | String | Alert Level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | `"HIGH"` |
| `evidence` | Dict | Raw request details/payload | `{"uri": "/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1"}` |
| `action` | String | Response Action | `"DRY_RUN"` |
