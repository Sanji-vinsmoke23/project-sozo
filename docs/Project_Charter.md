# 📜 Project Sozo: Project Charter

## 1. Vision
Every containerized web application deserves an autonomous, evidence-driven security operations capability that detects, correlates, explains, and safely responds to attacks — and proves its own performance with measurable results.

## 2. Problem Statement
Traditional SOCs and WAFs rely on rigid, easily-bypassed signatures and cause massive false-positive business disruptions. The v0 prototype of Sozo demonstrated a strong biological immune-system concept but suffered from unsafe auto-blocking, lack of audit trails, and weak thresholding. This project rebuilds Sozo into a safe, modular, and measurable legacy-grade platform.

## 3. Core Engineering Principles
1. **Safety First:** "Dry-run" is the default. Every automated response is temporary, reversible, and strictly audited.
2. **Evidence Over Claims:** No task is complete without telemetry proof.
3. **Framework Alignment:** All detections map directly to **OWASP Top 10** and **MITRE ATT&CK**.
4. **Least Privilege:** The SOC platform itself operates with minimal Docker and system privileges.

## 4. Target Architecture (The Immune System)
- **Innate Engine:** Rule-based, signature, and threshold detection.
- **Adaptive Engine:** Machine Learning (Isolation Forest) anomaly scoring.
- **Threat Memory:** Stateful indicator tracking with TTL and decay.
- **SOAR Orchestrator:** Automated, audited response with enforcement levels (L0-L5).
- **Narrator:** Local LLM (Phi-4) for plain-language incident summaries.

## 5. Success Criteria (v1.0)
- **Precision:** ≥ 90% across simulated attack scenarios.
- **Recall:** ≥ 80% for signature-based detections.
- **False Positive Rate:** < 5% over benign traffic baselines.
- **Safety:** 100% of SOAR actions audited; zero unvalidated inputs in enforcement paths.

## 6. Team
- **Rithish:** Project Lead, Detection, ML & SOAR Architecture
- **Mugundhan R:** Platform Engineering, Evaluation & Infrastructure
