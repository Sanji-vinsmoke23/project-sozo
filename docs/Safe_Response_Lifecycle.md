# 🛡️ Safe Response Lifecycle (SOAR)

One of the biggest risks in autonomous security is automated mitigation causing business disruption (e.g., permanently blocking a legitimate user or a health-check IP). Project Sozo solves this with a strict, biologically-inspired response lifecycle.

## Core Safety Rails
1. **Dry-Run by Default:** The system defaults to `L1: Dry-Run`, logging exactly what it *would* do without executing it. Automation only engages after human approval or high-confidence thresholds.
2. **Temporary by Design:** There are no permanent automated bans. Blocks use Time-To-Live (TTL) expiration (e.g., 30 minutes for first offense, 2 hours for repeat).
3. **Strict Validation:** IP addresses and log parameters are strictly validated before entering the memory or enforcement pipelines, preventing injection attacks against the SOC itself.
4. **Allowlists:** Critical infrastructure (Docker gateways, health-checkers, admin IPs) are hardcoded into an allowlist and bypass all automated mitigation.

## Enforcement Levels
| Level | Name | Description |
| :--- | :--- | :--- |
| **L0** | Observe | Log the event only. |
| **L1** | Dry-Run | Plan recorded, visible on dashboard, zero enforcement. |
| **L2** | Soft | Rate-limit or throttle at the application layer. |
| **L3** | Temp Block | Network drop with strict TTL. |
| **L4** | Quarantine | Container isolation (Requires Analyst Approval). |

This lifecycle ensures Project Sozo acts like a real biological immune system: it responds proportionally to the threat and recovers automatically, preventing self-inflicted denial-of-service.
