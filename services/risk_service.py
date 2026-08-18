from typing import Any, Dict, Optional


# ============================================================
# SentriX Risk Score Configuration
# ============================================================

ANOMALY_WEIGHT = 0.45
CRITICALITY_WEIGHT = 0.20
EXPOSURE_WEIGHT = 0.15
VULNERABILITY_WEIGHT = 0.10
BUSINESS_IMPACT_WEIGHT = 0.10

ANOMALY_THRESHOLD = 0.1167
ANOMALY_AMPLIFIER = 1.15


# ============================================================
# Categorical values -> 0..1
# ============================================================

CRITICALITY_VALUES = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}

EXPOSURE_VALUES = {
    "internal": 0.3,
    "dmz": 0.7,
    "internet_facing": 1.0,
}

VULNERABILITY_VALUES = {
    "none": 0.0,
    "low": 0.3,
    "medium": 0.6,
    "high": 0.9,
    "critical": 1.0,
}

IMPACT_VALUES = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}


# ============================================================
# Risk Classification
# ============================================================

def classify_risk(risk_score: float) -> Dict[str, Any]:
    """
    Convert Risk Score (0-100) into:
    Severity + Priority + SLA
    """

    if risk_score >= 75:
        return {
            "severity": "CRITICAL",
            "priority": "P1",
            "sla_hours": 1,
        }

    if risk_score >= 50:
        return {
            "severity": "HIGH",
            "priority": "P2",
            "sla_hours": 4,
        }

    if risk_score >= 25:
        return {
            "severity": "MEDIUM",
            "priority": "P3",
            "sla_hours": 24,
        }

    return {
        "severity": "LOW",
        "priority": "P4",
        "sla_hours": 72,
    }


# ============================================================
# Risk Calculation
# ============================================================

def calculate_risk(
    anomaly_score: Optional[float],
    asset_criticality: Optional[str],
    exposure: Optional[str],
    vulnerability_level: Optional[str],
    business_impact: Optional[str],
) -> Dict[str, Any]:
    """
    SentriX Risk Score:

    Full path:
        Anomaly
        + Asset Criticality
        + Exposure
        + Vulnerability
        + Business Impact

    Context-only path:
        No anomaly/model result.
        Anomaly weight is redistributed proportionally
        across the four contextual factors.
    """

    # --------------------------------------------------------
    # Convert categorical values
    # --------------------------------------------------------

    criticality_key = (asset_criticality or "").lower()
    exposure_key = (exposure or "").lower()
    vulnerability_key = (vulnerability_level or "").lower()
    impact_key = (business_impact or "").lower()

    criticality_value = CRITICALITY_VALUES.get(criticality_key)
    exposure_value = EXPOSURE_VALUES.get(exposure_key)
    vulnerability_value = VULNERABILITY_VALUES.get(vulnerability_key)
    impact_value = IMPACT_VALUES.get(impact_key)

    if criticality_value is None:
        raise ValueError(
            f"Invalid asset_criticality: {asset_criticality}"
        )

    if exposure_value is None:
        raise ValueError(
            f"Invalid exposure: {exposure}"
        )

    if vulnerability_value is None:
        raise ValueError(
            f"Invalid vulnerability_level: {vulnerability_level}"
        )

    if impact_value is None:
        raise ValueError(
            f"Invalid business_impact: {business_impact}"
        )

    # ========================================================
    # FULL PATH
    # Model result available
    # ========================================================

    if anomaly_score is not None:

        if not 0.0 <= anomaly_score <= 1.0:
            raise ValueError(
                f"Invalid anomaly_score: {anomaly_score}"
            )

        weights = {
            "anomaly_score": ANOMALY_WEIGHT,
            "asset_criticality": CRITICALITY_WEIGHT,
            "exposure": EXPOSURE_WEIGHT,
            "vulnerability": VULNERABILITY_WEIGHT,
            "business_impact": BUSINESS_IMPACT_WEIGHT,
        }

        contributions = {
            "anomaly_score": (
                ANOMALY_WEIGHT * anomaly_score
            ),
            "asset_criticality": (
                CRITICALITY_WEIGHT * criticality_value
            ),
            "exposure": (
                EXPOSURE_WEIGHT * exposure_value
            ),
            "vulnerability": (
                VULNERABILITY_WEIGHT * vulnerability_value
            ),
            "business_impact": (
                BUSINESS_IMPACT_WEIGHT * impact_value
            ),
        }

        risk_base = sum(contributions.values())

        anomaly_exceeds_threshold = (
            anomaly_score > ANOMALY_THRESHOLD
        )

        # Default: no amplification
        risk_final = risk_base

        # Amplification when anomaly exceeds threshold
        if anomaly_exceeds_threshold:
            risk_final = min(
                risk_base * ANOMALY_AMPLIFIER,
                1.0,
            )

        scoring_mode = "ml_assisted"
        flow = "full_path"

    # ========================================================
    # CONTEXT-ONLY PATH
    # Model result unavailable
    # ========================================================

    else:

        redistributed_weights = {
            "asset_criticality": (
                CRITICALITY_WEIGHT / 0.55
            ),
            "exposure": (
                EXPOSURE_WEIGHT / 0.55
            ),
            "vulnerability": (
                VULNERABILITY_WEIGHT / 0.55
            ),
            "business_impact": (
                BUSINESS_IMPACT_WEIGHT / 0.55
            ),
        }

        weights = {
            "anomaly_score": 0.0,
            **redistributed_weights,
        }

        contributions = {
            "anomaly_score": 0.0,

            "asset_criticality": (
                redistributed_weights["asset_criticality"]
                * criticality_value
            ),

            "exposure": (
                redistributed_weights["exposure"]
                * exposure_value
            ),

            "vulnerability": (
                redistributed_weights["vulnerability"]
                * vulnerability_value
            ),

            "business_impact": (
                redistributed_weights["business_impact"]
                * impact_value
            ),
        }

        risk_base = sum(contributions.values())

        risk_final = min(
            risk_base,
            1.0,
        )

        scoring_mode = "context_only"
        flow = "short_path"

        anomaly_exceeds_threshold = False

    # ========================================================
    # Final Score
    # ========================================================

    risk_score = round(
        risk_final * 100,
        2
    )

    classification = classify_risk(
        risk_score
    )

    return {
        "risk_score": risk_score,

        "severity": classification["severity"],

        "priority": classification["priority"],

        "sla_hours": classification["sla_hours"],

        "scoring_mode": scoring_mode,

        "flow": flow,

        "dynamic_threshold": ANOMALY_THRESHOLD,

        "weights_used": weights,

        "risk_factors": {
            "values": {
                "anomaly_score": anomaly_score,
                "asset_criticality": criticality_value,
                "exposure": exposure_value,
                "vulnerability": vulnerability_value,
                "business_impact": impact_value,
            },

            "contributions": contributions,

            "base_risk": round(
                risk_base,
                6
            ),

            "anomaly_exceeded_threshold":
                anomaly_exceeds_threshold,

            "amplifier":
                ANOMALY_AMPLIFIER
                if anomaly_exceeds_threshold
                else 1.0,
        },
    }


# ============================================================
# Local test
# ============================================================

if __name__ == "__main__":

    result = calculate_risk(
        anomaly_score=0.93,
        asset_criticality="critical",
        exposure="internet_facing",
        vulnerability_level="high",
        business_impact="critical",
    )

    print("\n=== SentriX Risk Test ===")

    print(
        "Risk Score:",
        result["risk_score"]
    )

    print(
        "Severity:",
        result["severity"]
    )

    print(
        "Priority:",
        result["priority"]
    )

    print(
        "SLA Hours:",
        result["sla_hours"]
    )

    print(
        "Scoring Mode:",
        result["scoring_mode"]
    )

    print(
        "Flow:",
        result["flow"]
    )

    print(
        "Risk Factors:",
        result["risk_factors"]
    )