# 🧬 Project Sozo: The Autonomous Immune SOC

**Project Sozo** is an autonomous Security Operations Center (SOC) designed to protect containerized web applications. Inspired by the **human biological immune system**, Sozo moves beyond static rule-matching to provide adaptive, evidence-driven, and self-healing security responses.

> 🏆 **Smart India Hackathon (SIH) Submission**  
> *Track: Cybersecurity / Autonomous Systems*

---

## 🧠 The Core Philosophy: Biological Cyber-Defense
Traditional SOCs rely on rigid, easily-bypassed signatures. Project Sozo mimics human immunity:

| Biological System | Sozo Cyber Equivalent | Function |
| :--- | :--- | :--- |
| **Innate Immunity** | Rule & Threshold Engine | Immediate, signature-based response to known threats (OWASP Top 10). |
| **Adaptive Immunity** | ML Anomaly Engine | Isolation Forest models detecting zero-day behavioral deviations. |
| **Memory Cells** | Threat Intel Lifecycle | Stateful tracking of attacker IPs with TTL, confidence scoring, and decay. |
| **White Blood Cells** | SOAR Orchestrator | Automated, reversible mitigation (Dry-run, Rate-limit, Network Isolation). |
| **Nervous System** | Streamlit API Dashboard | Real-time telemetry, alert triage, and human-in-the-loop analyst workflows. |
| **Speech Center** | Local LLM Narrator | Phi-4/Ollama integration generating plain-language incident summaries. |

---

## 🏗️ Architecture & Engineering Maturity
Unlike standard hackathon prototypes, Project Sozo is engineered with enterprise-grade discipline:
- **Safety First:** Default "Dry-Run" mode. All automated mitigations are temporary, reversible, and strictly audited.
- **Evidence-Driven:** Every alert maps directly to **OWASP Top 10** and **MITRE ATT&CK** frameworks.
- **Zero Trust Parsing:** Structured log parsing prevents the regex injection and false-positive flaws common in legacy WAFs.
- **Measurable Efficacy:** Built-in simulation matrix to calculate Precision, Recall, and False Positive Rates against benign baselines.

---

## 📂 Repository Structure
- `/docs`: Comprehensive architecture, threat models, and detection requirement matrices.
- `/legacy_v0`: The initial proof-of-concept scripts (Phase 1-3).
- `/src`: The modular v1.0 microservices architecture (Collector, Parser, Detection, SOAR, ML).
- `/data`: Ground-truth benign and malicious traffic captures for ML training.
- `/docker`: Isolated lab environment (Kali Attacker + DVWA Victim).

---

## 🗺️ Development Roadmap (v1.0)
We are currently executing an 8-week agile sprint to transition from prototype to legacy-grade software:
- [x] **M0:** Project Charter, Risk Register, and Lab Baseline Capture.
- [x] **M1:** Safe Core Architecture & Event Schema Design.
- [ ] **M2:** OWASP Detection Quality & False-Positive Catalog.
- [ ] **M3:** SOAR Lifecycle & Threat Memory Implementation.
- [ ] **M4:** Adaptive ML Integration & LLM Guardrails.
- [ ] **M5:** Dashboard API & Analyst Workflows.
- [ ] **M6:** Attack Simulation & Metrics Evaluation.
- [ ] **M7:** Security Hardening & Final Release.

---

## 🛠️ Tech Stack
- **Core:** Python 3.11, Docker SDK
- **Data/ML:** Scikit-Learn (Isolation Forest), SQLite, Pandas
- **AI Narrator:** Ollama (Local LLM - Phi-4-mini)
- **Visualization:** Streamlit
- **Target Environment:** DVWA (Damn Vulnerable Web App), Kali Linux

## 🤝 Team
- **Rithish** - Project Lead, Detection, ML & SOAR Architecture
- **Mugundhan R** - Platform Engineering, Evaluation & Infrastructure
- **Aravindha** - Review and Evaluation
---
*Project Sozo: Because your infrastructure deserves an immune system.*
