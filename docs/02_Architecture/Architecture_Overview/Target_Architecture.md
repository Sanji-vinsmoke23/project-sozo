[200~[Victim Logs] -> [Collector] -> [Parser] -> [Detection Engine]
|
[Risk Scoring]
|
[Memory & Storage]
|
[200~[SOAR Response / API / Dashboard]~
## 2. Core Components

1. **Collector & Parser:** Reads container logs (DVWA) and parses them into standardized `SozoEvent` JSON format.
2. **Detection Engine:** Evaluates logs against signature rules and statistical anomalies.
3. **Risk Scoring:** Assigns threat scores based on severity, frequency, and target context.
4. **Memory:** Stores historical events in SQLite database for contextual lookup.
5. **SOAR Response:** Triggers automatic actions (e.g., IP blocks, alert flags) based on risk thresholds.
6. **API & Dashboard:** Exposes endpoints for the UI to display live alerts and metrics.
