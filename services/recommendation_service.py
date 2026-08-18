from typing import Any, Dict, Optional


def build_recommendation(
    playbook: Dict[str, Any],
    incident_id: str,
    severity: str,
) -> list[Dict[str, Any]]:
    """
    Convert playbook actions into individual incident recommendations.
    """

    actions = playbook.get("actions") or []

    recommendations = []

    for index, action in enumerate(actions, start=1):

        action_title = action.get(
            "action",
            f"Response Action {index}"
        )

        action_description = action.get(
            "description"
        )

        recommendations.append(
            {
                "incident_id": incident_id,
                "playbook_id": playbook["id"],
                "recommendation_reason": (
                    f"Selected {playbook['title']} "
                    f"for {playbook['incident_type']} "
                    f"incident with severity {severity}."
                ),
                "action_title": action_title,
                "action_description": action_description,
                "action_scope": "immediate",
                "action_order": action.get(
                    "order",
                    index
                ),
                "is_fallback": False,
                "priority": severity.upper(),
                "status": "pending",
            }
        )

    return recommendations