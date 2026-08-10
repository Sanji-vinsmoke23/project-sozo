from dataclasses import dataclass, asdict
from typing import Dict, Any

@dataclass
class SozoEvent:
    id: str
    timestamp: str
    source_ip: str
    attack_type: str
    owasp_ref: str
    mitre_ref: str
    confidence: float
    severity: str
    evidence: Dict[str, Any]
    action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
