from typing import Any, Dict


# ============================================================
# SentriX Threat Profiles
# Deterministic mapping - NOT LLM-generated
# ============================================================

THREAT_PROFILES: Dict[str, Dict[str, Any]] = {

    "Brute-force": {
        "matched_profile": "brute_force",
        "mitre_tactics": [
            {
                "id": "TA0006",
                "name": "Credential Access"
            }
        ],
        "mitre_techniques": [
            {
                "id": "T1110",
                "name": "Brute Force"
            }
        ],

        # Current prototype CIA classification
        "confidentiality_impact": "medium",
        "integrity_impact": "medium",
        "availability_impact": "low",
    },

    "Heartbleed": {
        "matched_profile": "heartbleed",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "high",
        "integrity_impact": "low",
        "availability_impact": "low",
    },

    "Botnet": {
        "matched_profile": "botnet",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "medium",
        "integrity_impact": "medium",
        "availability_impact": "medium",
    },

    "DoS": {
        "matched_profile": "dos",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "low",
        "integrity_impact": "low",
        "availability_impact": "high",
    },

    "DDoS": {
        "matched_profile": "ddos",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "low",
        "integrity_impact": "low",
        "availability_impact": "high",
    },

    "Web Attacks": {
        "matched_profile": "web_attack",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "medium",
    },

    "Infiltration": {
        "matched_profile": "infiltration",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "confidentiality_impact": "high",
        "integrity_impact": "high",
        "availability_impact": "medium",
    },
}


def analyze_threat(incident_type: str) -> Dict[str, Any]:
    """
    Deterministically map an incident type
    to its threat profile.
    """

    profile = THREAT_PROFILES.get(incident_type)

    if profile is None:
        return {
            "threat_type": incident_type,
            "matched_profile": None,
            "is_unmapped": True,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "confidentiality_impact": None,
            "integrity_impact": None,
            "availability_impact": None,
            "intel_version": "1.0",
        }

    return {
        "threat_type": incident_type,
        "matched_profile": profile["matched_profile"],
        "is_unmapped": False,
        "mitre_tactics": profile["mitre_tactics"],
        "mitre_techniques": profile["mitre_techniques"],
        "confidentiality_impact": profile["confidentiality_impact"],
        "integrity_impact": profile["integrity_impact"],
        "availability_impact": profile["availability_impact"],
        "intel_version": "1.0",
    }