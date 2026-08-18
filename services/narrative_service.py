from typing import Any, Dict, Optional


def build_narrative(
    incident_id: str,
    title: str,
    severity: str,
    risk_score: Optional[float] = None,
    mitre_techniques: Optional[list] = None
) -> Dict[str, Any]:
    """Generates the AI narrative data payload for an incident."""
    return {
        "incident_id": incident_id,
        "analysis_id": f"ANALYZE-{incident_id[:8]}",
        "model_used": "SentriX Analytical Core",
        "analysis_summary": f"Incident '{title}' analyzed with severity {severity}.",
        "key_findings": {
            "risk_score": risk_score,
            "mitre_techniques": mitre_techniques or []
        },
        "prompt_version": "v1.1",
        "narrative_source": "skipped"
    }