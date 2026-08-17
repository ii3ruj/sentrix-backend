"""
SentriX Backend API & Real-Time AI Decision Engine (v4.0)
---------------------------------------------------------------------------
DataRobot Prediction API + Supabase + PDF Archiving + Twilio Alerts.

هذه النسخة تنفّذ *بالضبط* المسارات التي يستدعيها الفرونت إند الحالي،
وبنفس أسماء الحقول وحالة الأحرف التي يقرأها — بدون أي تعديل على الواجهة.

المسارات:
  GET  /api/dashboard/stats
  GET  /api/incidents
  POST /api/incidents
  GET  /api/incidents/{incident_id}
  POST /api/incidents/upload-pdf
  GET  /api/ai-analysis/{incident_id}
  GET  /api/recommendations
  GET  /api/crsi-assessment
  GET  /api/crsi-recommendations
  GET  /api/archive
  POST /api/archive/verify/{incident_id}
  GET  /api/archive/{incident_id}/download      (عرض/تحميل الـPDF)
  GET  /api/team/messages   ·   POST /api/team/messages
  GET  /health              ·   GET  /api/debug/config
  POST /api/simulator/start · POST /api/simulator/stop · GET /api/simulator/status
"""

import asyncio
import hashlib
import io
import json
import os
import random
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ===========================================================================
# 1. CONFIG
# ===========================================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = (
    os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    or os.environ.get("SUPABASE_KEY")
)

DATAROBOT_API_TOKEN = os.environ.get("DATAROBOT_API_TOKEN")
DATAROBOT_DEPLOYMENT_ID = os.environ.get("DATAROBOT_DEPLOYMENT_ID")
DATAROBOT_KEY = os.environ.get("DATAROBOT_KEY")

TWILIO_SID = os.environ.get("TWILIO_SID")
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN")
TWILIO_PHONE = os.environ.get("TWILIO_PHONE")
TEAM_NUMBERS = [n.strip() for n in os.environ.get("TEAM_NUMBERS", "").split(",") if n.strip()]

SIM_ENABLED = os.environ.get("SIM_ENABLED", "true").lower() == "true"
SIM_INTERVAL = int(os.environ.get("SIM_INTERVAL_SECONDS", "45"))
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",")]

supabase = None
SUPABASE_ERROR = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:  # pragma: no cover
        SUPABASE_ERROR = str(e)
        print(f"[supabase] init error: {e}")

BASE_DIR = Path(__file__).parent
FILES_DIR = BASE_DIR / "storage" / "files"
DB_DIR = BASE_DIR / "storage" / "db"
FILES_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SentriX AI Engine", version="4.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===========================================================================
# 2. AI ENGINE CONSTANTS  (مطابقة لملفات فريق الـAI)
# ===========================================================================

FEATURE_KEYS = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Total", "Bwd IAT Total",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Avg Packet Size", "Fwd Seg Size Min",
]

ANOMALY_MEAN, ANOMALY_STD, K_FACTOR = 0.003742, 0.056496, 2.0
ANOMALY_THRESHOLD = round(ANOMALY_MEAN + K_FACTOR * ANOMALY_STD, 4)   # 0.1167

RISK_WEIGHTS = {
    "anomaly": 0.45, "criticality": 0.20, "exposure": 0.15,
    "vulnerability": 0.10, "impact": 0.10,
}
CONTEXT_MAPS = {
    "criticality":   {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0},
    "exposure":      {"internal": 0.3, "dmz": 0.7, "internet_facing": 1.0},
    "vulnerability": {"none": 0.0, "low": 0.3, "medium": 0.6, "high": 0.9, "critical": 1.0},
    "impact":        {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0},
}
DEVIATION_AMPLIFIER = 1.15

MITRE_MAP = {
    "ransomware":     {"tactics": ["Impact", "Defense Evasion"],
                       "techniques": ["T1486", "T1490", "T1070"],
                       "cia": {"confidentiality": "Medium", "integrity": "High", "availability": "High"},
                       "domains": ["endpoint_security", "backup_recovery", "detect_respond"]},
    "brute_force":    {"tactics": ["Credential Access", "Initial Access"],
                       "techniques": ["T1110", "T1078"],
                       "cia": {"confidentiality": "High", "integrity": "Medium", "availability": "Low"},
                       "domains": ["identify_access", "detect_respond"]},
    "ddos":           {"tactics": ["Impact"],
                       "techniques": ["T1498", "T1499"],
                       "cia": {"confidentiality": "Low", "integrity": "Low", "availability": "High"},
                       "domains": ["network_security", "detect_respond"]},
    "phishing":       {"tactics": ["Initial Access", "Credential Access"],
                       "techniques": ["T1566", "T1204"],
                       "cia": {"confidentiality": "High", "integrity": "Medium", "availability": "Low"},
                       "domains": ["identify_access", "nca_controls"]},
    "malware":        {"tactics": ["Execution", "Persistence"],
                       "techniques": ["T1204", "T1547", "T1059"],
                       "cia": {"confidentiality": "Medium", "integrity": "High", "availability": "Medium"},
                       "domains": ["endpoint_security", "detect_respond"]},
    "insider_threat": {"tactics": ["Exfiltration", "Collection"],
                       "techniques": ["T1041", "T1005"],
                       "cia": {"confidentiality": "High", "integrity": "Medium", "availability": "Low"},
                       "domains": ["identify_access", "nca_controls"]},
    "benign":         {"tactics": [], "techniques": [],
                       "cia": {"confidentiality": "Low", "integrity": "Low", "availability": "Low"},
                       "domains": []},
    "_default":       {"tactics": ["Execution"], "techniques": ["T1059"],
                       "cia": {"confidentiality": "Medium", "integrity": "Medium", "availability": "Medium"},
                       "domains": ["detect_respond"]},
}

PLAYBOOKS = {
    "ransomware": {
        "name": "RANSOMWARE_RESPONSE_PLAYBOOK",
        "actions": [
            ("Isolate affected host", "Disconnect the affected host from the network to prevent further spread.", "HIGH"),
            ("Block malicious IP", "Add identified malicious IP addresses to the firewall blocklist.", "HIGH"),
            ("Terminate malicious processes", "Stop suspicious processes related to the detected ransomware activity.", "HIGH"),
            ("Collect and preserve logs", "Collect endpoint, network, authentication, and security logs for investigation.", "MEDIUM"),
            ("Identify affected files", "Identify encrypted, modified, or otherwise affected files and directories.", "MEDIUM"),
            ("Reset compromised credentials", "Reset credentials associated with potentially compromised accounts.", "HIGH"),
            ("Scan connected systems", "Perform security scans across connected systems to identify additional compromise.", "MEDIUM"),
            ("Restore affected services", "Restore affected systems and services after confirming the environment is clean.", "LOW"),
        ],
    },
    "brute_force": {
        "name": "BRUTE_FORCE_RESPONSE_PLAYBOOK",
        "actions": [
            ("Lock affected account", "Temporarily lock the targeted account to stop the attack.", "HIGH"),
            ("Block source IP", "Block the originating IP address at the perimeter firewall.", "HIGH"),
            ("Force password reset", "Require a password reset for the targeted account.", "HIGH"),
            ("Enable MFA", "Enforce multi-factor authentication on the affected account.", "MEDIUM"),
            ("Review authentication logs", "Review authentication logs for successful logins from the same source.", "MEDIUM"),
        ],
    },
    "ddos": {
        "name": "DDOS_RESPONSE_PLAYBOOK",
        "actions": [
            ("Enable rate limiting", "Apply rate limiting on the affected service endpoints.", "HIGH"),
            ("Activate DDoS protection", "Enable upstream DDoS mitigation for the targeted service.", "HIGH"),
            ("Block attacking IP ranges", "Block the identified attacking address ranges.", "HIGH"),
            ("Scale edge capacity", "Temporarily increase edge capacity to absorb traffic.", "MEDIUM"),
            ("Notify ISP", "Coordinate with the service provider for upstream filtering.", "LOW"),
        ],
    },
    "phishing": {
        "name": "PHISHING_RESPONSE_PLAYBOOK",
        "actions": [
            ("Quarantine the email", "Remove the malicious message from all recipient mailboxes.", "HIGH"),
            ("Block sender domain", "Add the sender domain to the mail gateway blocklist.", "HIGH"),
            ("Reset affected credentials", "Reset credentials for users who interacted with the message.", "HIGH"),
            ("Notify affected users", "Inform affected users and confirm no credentials were submitted.", "MEDIUM"),
            ("Run awareness reminder", "Issue a targeted awareness reminder to the affected department.", "LOW"),
        ],
    },
    "malware": {
        "name": "MALWARE_RESPONSE_PLAYBOOK",
        "actions": [
            ("Isolate the endpoint", "Isolate the infected endpoint from the corporate network.", "HIGH"),
            ("Run full antivirus scan", "Execute a full scan on the affected endpoint.", "HIGH"),
            ("Remove malicious binaries", "Delete identified malicious executables and persistence entries.", "HIGH"),
            ("Patch exploited vulnerability", "Apply the security update for the exploited vulnerability.", "MEDIUM"),
            ("Monitor for reinfection", "Apply enhanced monitoring for 72 hours.", "LOW"),
        ],
    },
    "insider_threat": {
        "name": "INSIDER_THREAT_RESPONSE_PLAYBOOK",
        "actions": [
            ("Suspend user access", "Temporarily suspend the involved account's access.", "HIGH"),
            ("Preserve forensic evidence", "Preserve endpoint and access logs for investigation.", "HIGH"),
            ("Review data access history", "Review what data the account accessed over the last 30 days.", "MEDIUM"),
            ("Notify HR and legal", "Escalate to the appropriate internal stakeholders.", "MEDIUM"),
            ("Revoke elevated privileges", "Remove any elevated privileges held by the account.", "HIGH"),
        ],
    },
    "_default": {
        "name": "GENERIC_RESPONSE_PLAYBOOK",
        "actions": [
            ("Isolate the affected asset", "Isolate the asset until the scope of the incident is confirmed.", "HIGH"),
            ("Block the threat source", "Block the identified source at the perimeter.", "HIGH"),
            ("Preserve logs and evidence", "Collect and preserve all relevant logs.", "MEDIUM"),
            ("Escalate to the response team", "Assign the incident to the on-call responder.", "MEDIUM"),
        ],
    },
}

# أسماء المجالات هنا **مطابقة حرفياً** لما يعرضه الفرونت في CRSI
CRSI_DOMAINS = {
    "identify_access":  {"name": "Identify & Access", "weight": 0.18, "ref": "NIST PR.AC | ISO 27001 A.9 | NCA 2-2"},
    "network_security": {"name": "Network Security",  "weight": 0.17, "ref": "NIST PR.PT | ISO 27001 A.13 | NCA 2-5"},
    "endpoint_security":{"name": "Endpoint Security", "weight": 0.17, "ref": "NIST DE.CM | ISO 27001 A.12 | NCA 2-3"},
    "detect_respond":   {"name": "Detect & Respond",  "weight": 0.18, "ref": "NIST DE.AE | ISO 27001 A.16 | NCA 2-13"},
    "backup_recovery":  {"name": "Backup & Recovery", "weight": 0.15, "ref": "NIST RC.RP | ISO 27001 A.12.3 | NCA 2-9"},
    "nca_controls":     {"name": "NCA Controls",      "weight": 0.15, "ref": "NCA ECC-1:2018"},
}

CRSI_RECOMMENDATIONS = {
    "identify_access": [
        ("Enforce MFA on all privileged accounts", "Multi-factor authentication is not consistently enforced across administrative accounts.", "High"),
        ("Review and revoke stale access rights", "Perform a quarterly access review and revoke permissions no longer required.", "Medium"),
    ],
    "network_security": [
        ("Segment critical network zones", "Critical assets are not isolated from general user traffic.", "High"),
        ("Review firewall rule base", "Remove permissive and obsolete firewall rules.", "Medium"),
    ],
    "endpoint_security": [
        ("Review endpoint protection coverage", "Identify systems that are not adequately protected by EDR agents.", "High"),
        ("Investigate unresolved endpoint alerts", "Unresolved endpoint alerts indicate gaps in the triage process.", "High"),
    ],
    "detect_respond": [
        ("Reduce mean time to detect", "Detection coverage gaps allowed incidents to progress before being flagged.", "High"),
        ("Formalize incident response runbooks", "Document and test response runbooks for the top incident types.", "Medium"),
    ],
    "backup_recovery": [
        ("Verify offline backup integrity", "Backups must be validated and kept isolated from production networks.", "High"),
        ("Test restore procedures", "Perform a documented restore test for critical systems.", "Medium"),
    ],
    "nca_controls": [
        ("Close NCA ECC compliance gaps", "Address the control gaps identified against the NCA Essential Cybersecurity Controls.", "High"),
        ("Deliver security awareness training", "Run targeted awareness training for high-risk departments.", "Medium"),
    ],
}

# معايرة: حادثتان حرجتان يجب ألا تُبقيا المؤسسة "Strong".
# الخصم الأساسي يقع على المجالات التي أثبتت الحادثة إخفاقها،
# ويقع 25% منه على كل المجالات لأن أي اختراق يعكس ضعفاً مؤسسياً عاماً.
CRSI_PENALTY = {"Critical": 12.0, "High": 7.0, "Medium": 3.0, "Low": 1.0}
CRSI_SPILLOVER = 0.25
CRSI_WINDOW = 20          # نافذة تقييم متدحرجة — آخر 20 حادثة

INCIDENT_TITLES = {
    "ransomware":     "Ransomware detected on {asset}",
    "brute_force":    "Repeated failed authentication attempts on {asset}",
    "ddos":           "Traffic flood detected on {asset}",
    "phishing":       "Phishing email reported targeting {asset}",
    "malware":        "Suspicious file execution on {asset}",
    "insider_threat": "Unusual data access from {asset}",
    "benign":         "Routine network activity on {asset}",
}

# ===========================================================================
# 3. LOCAL MIRROR (مرآة محلية للقراءة السريعة — Supabase هي المصدر الدائم)
# ===========================================================================

PKG_FILE = DB_DIR / "packages.json"


def _read_mirror() -> list:
    if PKG_FILE.exists():
        try:
            return json.loads(PKG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _write_mirror(rows: list) -> None:
    PKG_FILE.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )


PACKAGES: list = _read_mirror()


def sb_insert(table: str, row: dict) -> None:
    """إدراج best-effort — فشله لا يوقف تحليل الحادثة."""
    if not supabase:
        return
    try:
        supabase.table(table).insert(row).execute()
    except Exception as e:
        print(f"[supabase] insert {table} failed: {e}")


def hydrate_from_supabase() -> None:
    """يعيد بناء المرآة من incident_reports بعد إعادة تشغيل الخدمة."""
    global PACKAGES
    if not supabase or PACKAGES:
        return
    try:
        res = (
            supabase.table("incident_reports")
            .select("report_json")
            .order("created_at", desc=True)
            .limit(300)
            .execute()
        )
        rows = [r["report_json"] for r in (res.data or []) if r.get("report_json")]
        if rows:
            PACKAGES = rows
            _write_mirror(PACKAGES)
            print(f"[supabase] hydrated {len(rows)} packages")
    except Exception as e:
        print(f"[supabase] hydrate failed: {e}")


def next_incident_ref() -> str:
    return f"INC-{len(PACKAGES) + 1:04d}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str).encode("utf-8")


# ===========================================================================
# 4. AI ENGINE
# ===========================================================================

def call_datarobot(features: dict) -> tuple[float | None, str]:
    """
    يرجع (anomaly_score, model_name).
    None يعني أن النموذج لم يعمل — وهذا يختلف عن 'عمل ولم يجد شذوذاً'.
    """
    if not (DATAROBOT_API_TOKEN and DATAROBOT_DEPLOYMENT_ID):
        return None, "unavailable"

    url = (
        f"https://app.datarobot.com/api/v2/deployments/"
        f"{DATAROBOT_DEPLOYMENT_ID}/predictions"
    )
    headers = {
        "Authorization": f"Bearer {DATAROBOT_API_TOKEN}",
        "Content-Type": "application/json",
    }
    if DATAROBOT_KEY:
        headers["datarobot-key"] = DATAROBOT_KEY

    try:
        resp = requests.post(url, json=[features], headers=headers, timeout=25)
        resp.raise_for_status()
        row = resp.json().get("data", [{}])[0]

        # DataRobot يغيّر اسم حقل الناتج حسب نوع النشر — نجرّب المعروفة بالترتيب
        for key in ("prediction", "predictionValue", "anomalyScore", "score"):
            if key in row and row[key] is not None:
                return round(float(row[key]), 4), "Isolation Forest (DataRobot)"

        preds = row.get("predictionValues") or []
        if preds:
            return round(float(preds[0].get("value", 0)), 4), "Isolation Forest (DataRobot)"

        print(f"[datarobot] unrecognised response shape: {row}")
    except Exception as e:
        print(f"[datarobot] prediction failed: {e}")

    return None, "unavailable"


def risk_engine(anomaly_score, ctx: dict) -> dict:
    """Weighted risk scoring. يعيد توزيع وزن الشذوذ عند غياب النموذج."""
    has_anomaly = anomaly_score is not None

    if has_anomaly:
        weights = dict(RISK_WEIGHTS)
    else:
        rest = {k: v for k, v in RISK_WEIGHTS.items() if k != "anomaly"}
        total = sum(rest.values())
        weights = {k: v / total for k, v in rest.items()}

    is_deviating = has_anomaly and float(anomaly_score) > ANOMALY_THRESHOLD

    breakdown = {}
    if has_anomaly:
        breakdown["anomaly"] = round(weights["anomaly"] * min(float(anomaly_score), 1.0), 4)

    for field in ("criticality", "exposure", "vulnerability", "impact"):
        value = str(ctx.get(field, "medium")).lower().strip()
        norm = CONTEXT_MAPS[field].get(value, 0.5)
        breakdown[field] = round(weights[field] * norm, 4)

    total = sum(breakdown.values())
    if is_deviating:
        total = min(total * DEVIATION_AMPLIFIER, 1.0)

    score = round(total * 100)

    if score >= 75:
        severity, priority, sla = "Critical", "P1", 1
    elif score >= 50:
        severity, priority, sla = "High", "P2", 4
    elif score >= 25:
        severity, priority, sla = "Medium", "P3", 24
    else:
        severity, priority, sla = "Low", "P4", 72

    return {
        "risk_score": score,
        "severity": severity,          # Capitalized — يقرأه الفرونت هكذا
        "priority": priority,
        "sla_hours": sla,
        "is_deviating": is_deviating,
        "dynamic_threshold": ANOMALY_THRESHOLD if has_anomaly else None,
        "scoring_mode": "ml_assisted" if has_anomaly else "context_only",
        "weights_used": {k: round(v, 4) for k, v in weights.items()},
        "risk_factors": breakdown,
        "flow": "short_path" if (severity == "Low" and not is_deviating) else "full_path",
    }


def threat_engine(incident_type: str, severity: str) -> dict:
    key = str(incident_type).lower().strip()
    entry = MITRE_MAP.get(key, MITRE_MAP["_default"])
    cia = dict(entry["cia"])
    if severity == "Critical":
        order = ["Low", "Medium", "High"]
        cia = {
            k: (order[min(order.index(v) + 1, 2)] if v in order and v != "Low" else v)
            for k, v in cia.items()
        }
    return {
        "matched_profile": key if key in MITRE_MAP else "_default",
        "is_unmapped": key not in MITRE_MAP,
        "mitre_tactics": entry["tactics"],
        "mitre_techniques": entry["techniques"],
        "cia_impact": cia,
        "failed_domains": entry["domains"],
    }


def recommendation_engine(incident_type: str, severity: str) -> dict:
    key = str(incident_type).lower().strip()
    book = PLAYBOOKS.get(key, PLAYBOOKS["_default"])

    limit = {"Critical": 8, "High": 5, "Medium": 3, "Low": 2}.get(severity, 3)
    chosen = book["actions"][:limit]

    actions = [
        {
            "id": i + 1,
            "title": title,
            "description": desc,
            "priority": prio.capitalize(),
            "status": "Pending",
            "action_order": i + 1,
        }
        for i, (title, desc, prio) in enumerate(chosen)
    ]
    return {
        "playbook": book["name"],
        "is_fallback": key not in PLAYBOOKS,
        "actions": actions,
    }


def key_findings(incident_type: str, asset: str, anomaly_score, risk: dict) -> list:
    findings = [
        f"{incident_type.replace('_', ' ').title()} activity detected on {asset}.",
        f"Risk scored {risk['risk_score']}/100 and classified as {risk['severity']}.",
    ]
    if anomaly_score is not None:
        state = "above" if risk["is_deviating"] else "below"
        findings.append(
            f"Network anomaly score {anomaly_score} is {state} the dynamic threshold "
            f"({ANOMALY_THRESHOLD})."
        )
    else:
        findings.append(
            "Network flow features were unavailable; scoring used organizational "
            "context only (context_only mode)."
        )
    findings.append(
        f"Response priority {risk['priority']} with a {risk['sla_hours']}-hour SLA."
    )
    return findings


def compute_crsi(packages: list) -> dict:
    """CRSI = Σ(Wi × Fi) على ستة مجالات. كل مجال يبدأ 100 وتُخصم إخفاقاته."""
    scores = {k: 100.0 for k in CRSI_DOMAINS}
    hits = {k: 0 for k in CRSI_DOMAINS}

    window = packages[:CRSI_WINDOW]        # PACKAGES مرتّبة من الأحدث

    for pkg in window:
        sev = pkg.get("risk", {}).get("severity", "Medium")
        penalty = CRSI_PENALTY.get(sev, 3.0)
        failed = pkg.get("threat", {}).get("failed_domains", [])

        if not failed:                     # حادثة غير خطرة لا تخصم شيئاً
            continue

        for dom in scores:
            deduct = penalty if dom in failed else penalty * CRSI_SPILLOVER
            scores[dom] = max(scores[dom] - deduct, 0.0)
            if dom in failed:
                hits[dom] += 1

    breakdown = []
    for key, meta in CRSI_DOMAINS.items():
        s = round(scores[key], 1)
        breakdown.append({
            "domain_key": key,
            "name": meta["name"],          # الفرونت يقرأ name + score
            "score": s,
            "weight": meta["weight"],
            "contribution": round(meta["weight"] * s, 2),
            "incident_hits": hits[key],
            "is_weak": s < 60,
            "control_reference": meta["ref"],
        })

    overall = round(sum(b["contribution"] for b in breakdown), 1)
    maturity = (
        "Strong" if overall >= 80 else
        "Moderate" if overall >= 60 else
        "Weak" if overall >= 40 else "Critical"
    )
    return {
        "score": overall,
        "maturity_level": maturity,
        "breakdown": sorted(breakdown, key=lambda b: b["score"]),
        "incident_count": len(window),
        "assessment_window": CRSI_WINDOW,
    }


def crsi_actions(crsi: dict) -> list:
    """توصيات مؤسسية مشتقة من المجالات الأضعف فعلياً — لا قائمة ثابتة."""
    out, idx = [], 1
    for entry in crsi["breakdown"]:
        if entry["score"] >= 85 and len(out) >= 3:
            continue
        for title, desc, prio in CRSI_RECOMMENDATIONS.get(entry["domain_key"], []):
            out.append({
                "id": idx,
                "title": title,
                "description": f"{desc} (Domain score: {entry['score']}/100 · {entry['control_reference']})",
                "priority": "High" if entry["is_weak"] else prio,
                "status": "Pending",
            })
            idx += 1
        if len(out) >= 8:
            break
    return out or [{
        "id": 1, "title": "Maintain current security posture",
        "description": "No weak control domains were identified in the current assessment window.",
        "priority": "Low", "status": "Pending",
    }]


def daily_scores(packages: list) -> list:
    """آخر 5 أيام — كل يوم محسوب من الحوادث حتى نهايته."""
    out = []
    today = datetime.now(timezone.utc).date()
    for i in range(5):
        day = today - timedelta(days=i)
        upto = [
            p for p in packages
            if _pkg_date(p) is not None and _pkg_date(p) <= day
        ]
        crsi = compute_crsi(upto)
        s = crsi["score"]
        out.append({
            "date": day.strftime("%b %d, %Y"),
            "score": s,
            "status": "Good" if s >= 70 else "Fair" if s >= 50 else "Poor",
        })
    return out


def _pkg_date(pkg: dict):
    raw = pkg.get("incident", {}).get("created_at")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
    except Exception:
        return None


# ===========================================================================
# 5. TWILIO
# ===========================================================================

def notify_twilio(ref: str, severity: str, incident_type: str, risk_score: int) -> dict:
    if severity != "Critical":
        return {"sent": False, "reason": "severity_not_critical"}
    if not (TWILIO_SID and TWILIO_TOKEN and TWILIO_PHONE and TEAM_NUMBERS):
        print("[twilio] skipped — missing TWILIO_SID / TWILIO_TOKEN / TWILIO_PHONE / TEAM_NUMBERS")
        return {"sent": False, "reason": "missing_config"}

    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        body = (
            f"SentriX ALERT: Critical {incident_type} incident {ref}. "
            f"Risk {risk_score}/100. Immediate response required."
        )
        sent = []
        for num in TEAM_NUMBERS:
            msg = client.messages.create(body=body, from_=TWILIO_PHONE, to=num)
            print(f"[twilio] queued sid={msg.sid} to={num} status={msg.status}")
            sent.append({"to": num, "sid": msg.sid, "status": msg.status})
        return {"sent": True, "messages": sent}
    except Exception as e:
        # الأسباب الشائعة: 21608 رقم غير موثّق في حساب تجريبي · 21606 مُرسل غير صالح
        print(f"[twilio] FAILED: {type(e).__name__}: {e}")
        return {"sent": False, "reason": str(e)}


# ===========================================================================
# 6. PDF
# ===========================================================================

def render_pdf(pkg: dict) -> bytes:
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"SentriX Report {pkg['incident']['id']}")

    inc, risk = pkg["incident"], pkg["risk"]
    threat, rec, crsi = pkg["threat"], pkg["recommendation"], pkg["crsi"]

    story = [
        Paragraph("SentriX — Cybersecurity Incident Report", styles["Title"]),
        Spacer(1, 6),
        Paragraph(
            f"Report ID: {pkg['report']['report_id']} &nbsp;|&nbsp; "
            f"Generated: {pkg['report']['generated_at'][:19]} UTC",
            styles["Normal"],
        ),
        Spacer(1, 14),
    ]

    def table(title, rows):
        story.append(Paragraph(title, styles["Heading2"]))
        t = Table(rows, colWidths=[150, 340])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend([t, Spacer(1, 12)])

    table("1. Incident Information", [
        ["Incident ID", inc["id"]],
        ["Title", inc["title"]],
        ["Type", inc["incident_type"]],
        ["Source", inc["source"]],
        ["Input Method", inc["input_method"]],
        ["Asset", f"{inc['asset_type']} ({inc['asset_criticality']} criticality)"],
        ["Source IP", inc.get("source_ip") or "N/A"],
        ["Detected At", str(inc["created_at"])[:19]],
    ])

    table("2. AI Detection", [
        ["Model", pkg["ai_result"]["model_name"]],
        ["Anomaly Score", str(pkg["ai_result"]["anomaly_score"])],
        ["Dynamic Threshold", str(risk["dynamic_threshold"])],
        ["Exceeded Threshold", "Yes" if risk["is_deviating"] else "No"],
        ["Scoring Mode", risk["scoring_mode"]],
    ])

    table("3. Risk Assessment", [
        ["Risk Score", f"{risk['risk_score']} / 100"],
        ["Severity", risk["severity"]],
        ["Priority", risk["priority"]],
        ["Response SLA", f"{risk['sla_hours']} hour(s)"],
        ["Risk Factors", json.dumps(risk["risk_factors"])],
        ["Weights Used", json.dumps(risk["weights_used"])],
    ])

    table("4. Threat Intelligence", [
        ["MITRE Tactics", ", ".join(threat["mitre_tactics"]) or "N/A"],
        ["MITRE Techniques", ", ".join(threat["mitre_techniques"]) or "N/A"],
        ["Confidentiality", threat["cia_impact"]["confidentiality"]],
        ["Integrity", threat["cia_impact"]["integrity"]],
        ["Availability", threat["cia_impact"]["availability"]],
    ])

    story.append(Paragraph("5. Key Findings", styles["Heading2"]))
    for f in pkg["key_findings"]:
        story.append(Paragraph(f"• {f}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"6. Response Playbook — {rec['playbook']}", styles["Heading2"]))
    rows = [["#", "Action", "Priority"]] + [
        [str(a["id"]), a["title"], a["priority"]] for a in rec["actions"]
    ]
    t = Table(rows, colWidths=[30, 380, 80])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]))
    story.extend([t, Spacer(1, 12)])

    table("7. Organizational Posture (CRSI)", [
        ["CRSI Score", f"{crsi['score']} / 100"],
        ["Maturity Level", crsi["maturity_level"]],
        ["Weak Domains", ", ".join(d["name"] for d in crsi["breakdown"] if d["is_weak"]) or "None"],
        ["Incidents Considered", str(crsi["incident_count"])],
    ])

    story.append(Paragraph(
        f"<font size=7 color='#666666'>Engine v4.0 · Threshold {ANOMALY_THRESHOLD} "
        f"· Weights {json.dumps(RISK_WEIGHTS)} · This report is an immutable archived "
        f"snapshot; its SHA-256 fingerprint is recorded in the archive.</font>",
        styles["Normal"],
    ))

    doc.build(story)
    return buf.getvalue()


# ===========================================================================
# 7. CORE PIPELINE
# ===========================================================================

class IncidentIn(BaseModel):
    title: str | None = None
    incident_type: str = "malware"
    source: str = "Manual Entry"
    input_method: str = "manual"          # manual | pdf | server
    source_ip: str | None = None
    destination_ip: str | None = None
    description: str | None = None
    asset_type: str = "Server"
    asset_criticality: str = "medium"     # low | medium | high | critical
    exposure: str = "internal"            # internal | dmz | internet_facing
    vulnerability_level: str = "medium"
    business_impact: str = "medium"
    flow_features: dict | None = None


def features_complete(features: dict | None) -> bool:
    if not features:
        return False
    return all(k in features and features[k] is not None for k in FEATURE_KEYS)


def process_incident(payload: IncidentIn) -> dict:
    incident_uuid = str(uuid.uuid4())
    ref = next_incident_ref()
    created_at = now_iso()

    itype = str(payload.incident_type).lower().strip()
    title = payload.title or INCIDENT_TITLES.get(itype, "Security incident on {asset}").format(
        asset=payload.asset_type
    )

    # --- 1) كشف الشذوذ ------------------------------------------------------
    if features_complete(payload.flow_features):
        anomaly_score, model_name = call_datarobot(payload.flow_features)
    else:
        anomaly_score, model_name = None, "context_only (no flow features)"

    # --- 2) الخطورة --------------------------------------------------------
    risk = risk_engine(anomaly_score, {
        "criticality": payload.asset_criticality,
        "exposure": payload.exposure,
        "vulnerability": payload.vulnerability_level,
        "impact": payload.business_impact,
    })

    # --- 3) التهديد + 4) التوصيات ------------------------------------------
    threat = threat_engine(itype, risk["severity"])
    rec = recommendation_engine(itype, risk["severity"])

    findings = key_findings(itype, payload.asset_type, anomaly_score, risk)

    incident_row = {
        "id": ref,                       # الفرونت يبحث بهذا المعرّف
        "uuid": incident_uuid,
        "title": title,
        "incident_type": itype,
        "source": payload.source,
        "input_method": payload.input_method,
        "source_ip": payload.source_ip,
        "destination_ip": payload.destination_ip,
        "description": payload.description or f"{itype} activity detected on {payload.asset_type}.",
        "asset_type": payload.asset_type,
        "asset_criticality": payload.asset_criticality,
        "exposure": payload.exposure,
        "vulnerability_level": payload.vulnerability_level,
        "business_impact": payload.business_impact,
        "created_at": created_at,
        "status": "Analyzed",
        "severity": risk["severity"],
        "risk_score": risk["risk_score"],
    }

    package = {
        "incident": incident_row,
        "ai_result": {
            "anomaly_score": anomaly_score,
            "is_anomaly": risk["is_deviating"] if anomaly_score is not None else None,
            "model_name": model_name,
            "dynamic_threshold": risk["dynamic_threshold"],
        },
        "risk": risk,
        "threat": threat,
        "recommendation": rec,
        "key_findings": findings,
    }

    # --- 5) CRSI بعد إضافة هذه الحادثة -------------------------------------
    package["crsi"] = compute_crsi(PACKAGES + [package])

    package["report"] = {
        "report_id": f"RPT-{ref.replace('INC-', '')}",
        "generated_at": created_at,
        "report_version": "4.0",
    }

    # --- 6) PDF + الأرشفة ---------------------------------------------------
    pdf_bytes = render_pdf(package)
    (FILES_DIR / f"{ref}.pdf").write_bytes(pdf_bytes)

    snapshot = {k: v for k, v in package.items()}
    package["archive"] = {
        "archive_id": str(uuid.uuid4()),
        "report_id": package["report"]["report_id"],
        "incident_id": ref,
        "title": f"Incident Report - {ref}",
        "type": "Incident Report",
        "archived_at": created_at.replace("T", " ")[:16],
        "sha256": sha256_of(canonical_json(snapshot)),
        "pdf_sha256": sha256_of(pdf_bytes),
        "archived_by": "SentriX Engine",
        "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(),
        "storage_type": "WORM (Immutable)",
        "pdf_path": f"/api/archive/{ref}/download",
    }

    # --- 7) الحفظ ----------------------------------------------------------
    PACKAGES.insert(0, package)
    _write_mirror(PACKAGES)
    persist_to_supabase(package, incident_uuid, pdf_bytes)

    # --- 8) التنبيه --------------------------------------------------------
    package["notification"] = notify_twilio(
        ref, risk["severity"], itype, risk["risk_score"]
    )

    return package


def persist_to_supabase(pkg: dict, incident_uuid: str, pdf_bytes: bytes) -> None:
    """يكتب في الجداول بالأسماء والقيم التي تقبلها السكيما (UPPERCASE للشدة)."""
    if not supabase:
        return

    inc, risk, threat = pkg["incident"], pkg["risk"], pkg["threat"]
    sev_db = risk["severity"].upper()

    sb_insert("incidents", {
        "id": incident_uuid,
        "title": inc["title"],
        "source": inc["source"],
        "incident_type": inc["incident_type"],
        "source_ip": inc["source_ip"],
        "destination_ip": inc["destination_ip"],
        "description": inc["description"],
        "flow_features": None,
        "asset_type": inc["asset_type"],
        "asset_criticality": inc["asset_criticality"],
        "input_method": inc["input_method"],
        "exposure": inc["exposure"],
        "vulnerability_level": inc["vulnerability_level"],
        "business_impact": inc["business_impact"],
        "incident_time": inc["created_at"],
        "created_at": inc["created_at"],
    })

    sb_insert("ai_results", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_uuid,
        "anomaly_score": pkg["ai_result"]["anomaly_score"],
        "is_anomaly": pkg["ai_result"]["is_anomaly"],
        "model_name": "Isolation Forest",
        "model_version": "v1.0",
        "prediction_metadata": {
            "threshold": ANOMALY_THRESHOLD,
            "feature_count": len(FEATURE_KEYS),
            "scoring_mode": risk["scoring_mode"],
        },
    })

    sb_insert("risk_results", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_uuid,
        "risk_score": risk["risk_score"],
        "severity": sev_db,
        "risk_factors": risk["risk_factors"],
        "scoring_mode": risk["scoring_mode"],
        "flow": risk["flow"],
        "priority": risk["priority"],
        "sla_hours": risk["sla_hours"],
        "weights_used": risk["weights_used"],
        "dynamic_threshold": risk["dynamic_threshold"],
    })

    sb_insert("threat_analysis", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_uuid,
        "threat_type": inc["incident_type"],
        "matched_profile": threat["matched_profile"],
        "is_unmapped": threat["is_unmapped"],
        "mitre_tactics": threat["mitre_tactics"],
        "mitre_techniques": threat["mitre_techniques"],
        "confidentiality_impact": threat["cia_impact"]["confidentiality"],
        "integrity_impact": threat["cia_impact"]["integrity"],
        "availability_impact": threat["cia_impact"]["availability"],
        "intel_version": "1.0",
    })

    for a in pkg["recommendation"]["actions"]:
        sb_insert("incident_recommendations", {
            "id": str(uuid.uuid4()),
            "incident_id": incident_uuid,
            "recommendation_reason": f"Matched playbook {pkg['recommendation']['playbook']}",
            "action_title": a["title"],
            "action_description": a["description"],
            "action_scope": "immediate",
            "action_order": a["action_order"],
            "is_fallback": pkg["recommendation"]["is_fallback"],
            "priority": a["priority"].upper(),
            "status": "pending",
        })

    report_uuid = str(uuid.uuid4())
    sb_insert("incident_reports", {
        "id": report_uuid,
        "incident_id": incident_uuid,
        "report_json": pkg,
        "pdf_path": pkg["archive"]["pdf_path"],
        "report_version": "4.0",
    })

    sb_insert("archives", {
        "id": pkg["archive"]["archive_id"],
        "report_id": report_uuid,
        "report_snapshot": pkg,
        "storage_path": f"local://{pkg['incident']['id']}.pdf",
        "pdf_path": pkg["archive"]["pdf_path"],
        "archive_period": datetime.now(timezone.utc).strftime("%Y-%m"),
        "sha256_hash": pkg["archive"]["sha256"],
    })

    crsi = pkg["crsi"]
    score_uuid = str(uuid.uuid4())
    today = date.today().isoformat()
    sb_insert("organizational_security_scores", {
        "id": score_uuid,
        "score": crsi["score"],
        "period_start": today,
        "period_end": today,
        "maturity_level": crsi["maturity_level"],
        "incident_count": crsi["incident_count"],
        "calculation_metadata": {"engine": "4.0", "domains": len(CRSI_DOMAINS)},
    })
    for d in crsi["breakdown"]:
        sb_insert("organizational_score_details", {
            "id": str(uuid.uuid4()),
            "security_score_id": score_uuid,
            "domain_key": d["domain_key"],
            "domain_name": d["name"],
            "score": d["score"],
            "weight": d["weight"],
            "contribution": d["contribution"],
            "incident_hits": d["incident_hits"],
            "is_weak": d["is_weak"],
            "control_reference": d["control_reference"],
        })


def find_package(incident_id: str) -> dict | None:
    wanted = str(incident_id).strip()
    for p in PACKAGES:
        inc = p["incident"]
        if wanted in (inc["id"], inc.get("uuid"), p["report"]["report_id"]):
            return p
    return None


# ===========================================================================
# 8. ENDPOINTS  (مطابقة حرفياً لما يستدعيه services/api.js)
# ===========================================================================

@app.get("/api/dashboard/stats")
async def dashboard_stats():
    counts = {}
    for p in PACKAGES:
        t = p["incident"]["incident_type"].replace("_", " ").title()
        counts[t] = counts.get(t, 0) + 1

    attack_types = sorted(
        [{"name": k, "value": v} for k, v in counts.items()],
        key=lambda x: x["value"], reverse=True,
    )[:6]

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for p in PACKAGES:
        s = p["risk"]["severity"]
        if s in sev:
            sev[s] += 1

    analyzed = sum(1 for p in PACKAGES if p["ai_result"]["anomaly_score"] is not None)

    # نسب التغيّر محسوبة فعلياً: آخر 24 ساعة مقابل الـ24 التي قبلها
    now = datetime.now(timezone.utc)
    def in_window(p, start_h, end_h):
        try:
            t = datetime.fromisoformat(str(p["incident"]["created_at"]).replace("Z", "+00:00"))
        except Exception:
            return False
        age = (now - t).total_seconds() / 3600
        return start_h <= age < end_h

    cur = [p for p in PACKAGES if in_window(p, 0, 24)]
    prev = [p for p in PACKAGES if in_window(p, 24, 48)]

    def pct(a, b):
        if b == 0:
            return {"change": f"{len(a) * 100 if False else 100 if a else 0}%", "positive": len(a) >= 0}
        delta = (len(a) - len(b)) / len(b) * 100
        return {"change": f"{abs(round(delta))}%", "positive": delta >= 0}

    cur_crit = [p for p in cur if p["risk"]["severity"] == "Critical"]
    prev_crit = [p for p in prev if p["risk"]["severity"] == "Critical"]

    return {
        "attackTypes": attack_types or [{"name": "No data", "value": 0}],
        "totals": {
            "total": len(PACKAGES),
            "critical": sev["Critical"],
            "analyzed": analyzed,
            "pending": len(PACKAGES) - analyzed,
        },
        "severityCounts": sev,
        "trends": {
            "total": pct(cur, prev),
            "critical": pct(cur_crit, prev_crit),
            "analyzed": pct([p for p in cur if p["ai_result"]["anomaly_score"] is not None],
                            [p for p in prev if p["ai_result"]["anomaly_score"] is not None]),
            "pending": pct([p for p in cur if p["ai_result"]["anomaly_score"] is None],
                           [p for p in prev if p["ai_result"]["anomaly_score"] is None]),
        },
        "crsi": compute_crsi(PACKAGES),
    }


@app.get("/api/incidents")
async def list_incidents():
    return [
        {
            **p["incident"],
            "risk_score": p["risk"]["risk_score"],
            "severity": p["risk"]["severity"],
            "hasAiResult": True,
            "ai_score": p["ai_result"]["anomaly_score"],
            "playbook": p["recommendation"]["playbook"],
        }
        for p in PACKAGES
    ]


@app.post("/api/incidents")
async def create_incident(payload: IncidentIn):
    return process_incident(payload)


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    p = find_package(incident_id)
    if not p:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        **p["incident"],
        "risk_score": p["risk"]["risk_score"],
        "severity": p["risk"]["severity"],
        "priority": p["risk"]["priority"],
        "sla_hours": p["risk"]["sla_hours"],
        "scoring_mode": p["risk"]["scoring_mode"],
        "flow": p["risk"]["flow"],
        "risk_factors": p["risk"]["risk_factors"],
        "anomaly_score": p["ai_result"]["anomaly_score"],
        "model_used": p["ai_result"]["model_name"],
        "dynamic_threshold": p["ai_result"]["dynamic_threshold"],
        "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A",
        "cia_impact": p["threat"]["cia_impact"],
        "key_findings": p["key_findings"],
        "playbook": p["recommendation"]["playbook"],
        "recommended_actions": p["recommendation"]["actions"],
        "crsi": p["crsi"],
        "report": p["report"],
        "archive": p["archive"],
        "pdf_url": p["archive"]["pdf_path"],
        "hasAiResult": True,
    }


@app.post("/api/incidents/upload-pdf")
async def upload_pdf(
    file: UploadFile = File(...),
    incident_id: str = Form(None),
    actual_time: str = Form(None),
    analyst: str = Form(None),
    sha256: str = Form(None),
):
    data = await file.read()
    extracted: dict = {}
    itype = "malware"
    src_ip = None

    try:
        import pdfplumber
        tmp = FILES_DIR / f"_tmp_{uuid.uuid4()}.pdf"
        tmp.write_bytes(data)
        try:
            with pdfplumber.open(tmp) as pdf:
                text = "\n".join(pg.extract_text() or "" for pg in pdf.pages)
                for page in pdf.pages:
                    for tbl in page.extract_tables():
                        for row in tbl:
                            if row and len(row) >= 2 and row[0] and str(row[0]).strip() in FEATURE_KEYS:
                                try:
                                    extracted[str(row[0]).strip()] = float(str(row[1]).strip())
                                except (TypeError, ValueError):
                                    pass
        finally:
            tmp.unlink(missing_ok=True)

        # Protocol يقع في قسم Network Information لا في جدول الـfeatures
        if "Protocol" not in extracted:
            upper = text.upper()
            for name, num in (("TCP", 6), ("UDP", 17), ("ICMP", 1)):
                if name in upper:
                    extracted["Protocol"] = num
                    break

        lower = text.lower()
        for candidate in ("ransomware", "brute force", "ddos", "phishing",
                          "malware", "insider"):
            if candidate in lower:
                itype = candidate.replace(" ", "_").replace("insider", "insider_threat")
                break

        import re
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m:
            src_ip = m.group(1)
    except Exception as e:
        print(f"[pdf] extraction failed: {e}")

    complete = features_complete(extracted)

    payload = IncidentIn(
        title=f"Incident report — {file.filename}",
        incident_type=itype,
        source="PDF Report",
        input_method="pdf",
        source_ip=src_ip,
        asset_type="Server",
        asset_criticality="high",
        exposure="internet_facing" if itype in ("ddos", "ransomware") else "internal",
        vulnerability_level="high",
        business_impact="high",
        flow_features=extracted if complete else None,
    )

    result = process_incident(payload)
    result["pdf_extraction"] = {
        "matched_features": len(extracted),
        "required": len(FEATURE_KEYS),
        "used_for_model": complete,
        "uploaded_sha256": sha256_of(data),
        "client_sha256": sha256,
        "analyst": analyst,
        "actual_time": actual_time,
    }
    return result


@app.get("/api/ai-analysis/{incident_id}")
async def ai_analysis(incident_id: str):
    p = find_package(incident_id)
    if not p:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        "incident_id": p["incident"]["id"],
        "incident_title": p["incident"]["title"],
        "severity": p["risk"]["severity"],
        "risk_score": p["risk"]["risk_score"],
        "risk_detected": p["risk"]["flow"] == "full_path",
        "analysis_id": f"AI-ANL-{p['incident']['id'].replace('INC-', '')}",
        "model_used": p["ai_result"]["model_name"],
        "analysis_time": p["report"]["generated_at"],
        "data_sources": f"{p['incident']['source']}, Threat Intel, Behavioral Logs",
        "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A",
        "cia_impact": p["threat"]["cia_impact"],
        "key_findings": p["key_findings"],
        "anomaly_score": p["ai_result"]["anomaly_score"],
        "threat_type": p["incident"]["incident_type"],
    }


@app.get("/api/recommendations")
async def recommendations(incident_id: str | None = None):
    p = find_package(incident_id) if incident_id else (PACKAGES[0] if PACKAGES else None)
    if not p:
        return {"playbook": "NO_INCIDENTS", "actions": [], "score": 0}
    return {
        "incident_id": p["incident"]["id"],
        "title": p["incident"]["title"],
        "severity": p["risk"]["severity"],
        "riskScore": p["risk"]["risk_score"],
        "playbook": p["recommendation"]["playbook"],
        "actions": p["recommendation"]["actions"],
    }


@app.get("/api/crsi-assessment")
async def crsi_assessment():
    crsi = compute_crsi(PACKAGES)
    return {
        "score": crsi["score"],
        "maturity_level": crsi["maturity_level"],
        "breakdown": crsi["breakdown"],
        "dailyScores": daily_scores(PACKAGES),
        "incident_count": crsi["incident_count"],
    }


@app.get("/api/crsi-recommendations")
async def crsi_recommendations():
    crsi = compute_crsi(PACKAGES)
    weak = [d["name"] for d in crsi["breakdown"] if d["is_weak"]]
    return {
        "score": crsi["score"],
        "maturity_level": crsi["maturity_level"],
        "breakdown": crsi["breakdown"],
        "playbook": "ORGANIZATIONAL_SECURITY_IMPROVEMENT_PLAN",
        "weak_domains": weak,
        "actions": crsi_actions(crsi),
    }


@app.get("/api/archive")
async def list_archive():
    rows = [
        {
            **p["archive"],
            "content": {
                "incidentTitle": p["incident"]["title"],
                "severity": p["risk"]["severity"],
                "riskScore": f"{p['risk']['risk_score']} / 100",
                "source": p["incident"]["source"],
                "asset": f"{p['incident']['asset_type']} ({p['incident']['asset_criticality']} criticality)",
                "threatType": p["incident"]["incident_type"],
                "keyFindings": p["key_findings"],
                "playbook": p["recommendation"]["playbook"],
                "recommendedActions": [a["title"] for a in p["recommendation"]["actions"]],
            },
        }
        for p in PACKAGES
    ]

    if PACKAGES:
        crsi = compute_crsi(PACKAGES)
        rows.append({
            "archive_id": "CRSI-CURRENT",
            "report_id": f"RPT-CRSI-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            "incident_id": None,
            "title": "CRSI Report - Organizational Assessment",
            "type": "CRSI Report",
            "archived_at": now_iso().replace("T", " ")[:16],
            "sha256": sha256_of(canonical_json(crsi)),
            "archived_by": "SentriX Engine",
            "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(),
            "storage_type": "WORM (Immutable)",
            "isCrsi": True,
            "content": {
                "overallScore": f"{crsi['score']} / 100",
                "maturityLevel": crsi["maturity_level"],
                **{d["name"]: f"{d['score']} / 100" for d in crsi["breakdown"]},
            },
        })
    return rows


@app.post("/api/archive/verify/{incident_id}")
async def verify_archive(incident_id: str, body: dict | None = None):
    p = find_package(incident_id)
    if not p:
        raise HTTPException(404, f"Archive record for {incident_id} not found")

    snapshot = {k: v for k, v in p.items() if k not in ("archive", "notification")}
    current = sha256_of(canonical_json(snapshot))
    stored = p["archive"]["sha256"]

    return {
        "incident_id": p["incident"]["id"],
        "integrity_ok": current == stored,
        "stored_sha256": stored,
        "current_sha256": current,
        "verified_at": now_iso(),
        "storage_type": "WORM (Immutable)",
    }


@app.get("/api/archive/{incident_id}/download")
async def download_archive(incident_id: str):
    p = find_package(incident_id)
    if not p:
        raise HTTPException(404, f"Incident {incident_id} not found")

    path = FILES_DIR / f"{p['incident']['id']}.pdf"
    if not path.exists():
        path.write_bytes(render_pdf(p))

    return Response(
        content=path.read_bytes(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{p["report"]["report_id"]}.pdf"'
        },
    )


TEAM_MESSAGES: list = []


@app.get("/api/team/messages")
async def get_team_messages():
    return TEAM_MESSAGES


@app.post("/api/team/messages")
async def post_team_message(body: dict):
    msg = {
        "id": str(uuid.uuid4()),
        "author": body.get("author", "Analyst"),
        "text": body.get("text") or body.get("message", ""),
        "created_at": now_iso(),
    }
    TEAM_MESSAGES.append(msg)
    return msg


# ===========================================================================
# 9. SIMULATOR / OPS
# ===========================================================================

SIM_TYPES = [
    ("benign", 0.30), ("ransomware", 0.15), ("brute_force", 0.15),
    ("ddos", 0.12), ("phishing", 0.12), ("malware", 0.10), ("insider_threat", 0.06),
]

SIM_PROFILES = {
    "benign":         {"crit": "low",      "exp": "internal",        "vuln": "low",      "imp": "low",      "hot": False},
    "ransomware":     {"crit": "critical", "exp": "internet_facing", "vuln": "critical", "imp": "critical", "hot": True},
    "ddos":           {"crit": "high",     "exp": "internet_facing", "vuln": "medium",   "imp": "high",     "hot": True},
    "brute_force":    {"crit": "medium",   "exp": "dmz",             "vuln": "medium",   "imp": "medium",   "hot": False},
    "phishing":       {"crit": "medium",   "exp": "internal",        "vuln": "medium",   "imp": "medium",   "hot": False},
    "malware":        {"crit": "high",     "exp": "internal",        "vuln": "high",     "imp": "medium",   "hot": True},
    "insider_threat": {"crit": "high",     "exp": "internal",        "vuln": "low",      "imp": "high",     "hot": False},
}


def synth_features(hot: bool) -> dict:
    out = {}
    for f in FEATURE_KEYS:
        if f == "Protocol":
            out[f] = random.choice([6, 17, 1])
        elif "Flag Count" in f:
            out[f] = random.randint(1, 3) if hot else random.randint(0, 1)
        elif f in ("Flow Bytes/s", "Flow Packets/s"):
            out[f] = round(random.uniform(6000, 10000) if hot else random.uniform(200, 2500), 2)
        elif f == "Flow Duration":
            out[f] = round(random.uniform(1_200_000, 2_000_000) if hot else random.uniform(50_000, 600_000), 2)
        elif "Ratio" in f:
            out[f] = round(random.uniform(0, 5), 2)
        else:
            out[f] = round(random.uniform(0, 1500), 2)
    return out


def build_sim_incident() -> IncidentIn:
    names = [t for t, _ in SIM_TYPES]
    weights = [w for _, w in SIM_TYPES]
    itype = random.choices(names, weights=weights)[0]
    prof = SIM_PROFILES[itype]

    return IncidentIn(
        incident_type=itype,
        source=random.choice(["EDR", "SIEM", "Firewall", "IDS", "DLP"]),
        input_method="server",
        source_ip=f"{random.randint(11, 220)}.{random.randint(0, 255)}."
                  f"{random.randint(0, 255)}.{random.randint(1, 254)}",
        destination_ip=f"10.0.{random.randint(0, 20)}.{random.randint(1, 254)}",
        asset_type=random.choice(["Server", "Workstation", "Database", "Network Device"]),
        asset_criticality=prof["crit"],
        exposure=prof["exp"],
        vulnerability_level=prof["vuln"],
        business_impact=prof["imp"],
        flow_features=synth_features(prof["hot"]),
    )


SIM_STATE = {"running": SIM_ENABLED, "generated": 0}


async def simulator_loop():
    while True:
        await asyncio.sleep(SIM_INTERVAL)
        if not SIM_STATE["running"]:
            continue
        try:
            process_incident(build_sim_incident())
            SIM_STATE["generated"] += 1
        except Exception as e:
            print(f"[simulator] error: {e}")


@app.post("/api/simulator/start")
async def sim_start():
    SIM_STATE["running"] = True
    return {"status": "started", "interval_seconds": SIM_INTERVAL, **SIM_STATE}


@app.post("/api/simulator/stop")
async def sim_stop():
    SIM_STATE["running"] = False
    return {"status": "stopped", **SIM_STATE}


@app.post("/api/simulator/burst")
async def sim_burst(count: int = 5):
    made = []
    for _ in range(min(count, 15)):
        pkg = process_incident(build_sim_incident())
        SIM_STATE["generated"] += 1
        made.append({
            "id": pkg["incident"]["id"],
            "type": pkg["incident"]["incident_type"],
            "severity": pkg["risk"]["severity"],
            "risk_score": pkg["risk"]["risk_score"],
        })
    return {"created": len(made), "incidents": made}


@app.get("/api/simulator/status")
async def sim_status():
    return {**SIM_STATE, "interval_seconds": SIM_INTERVAL, "total_incidents": len(PACKAGES)}


@app.get("/health")
async def health():
    return {"status": "ok", "version": "4.0.0", "incidents": len(PACKAGES)}


@app.get("/api/debug/config")
async def debug_config():
    """تشخيص الإعداد — يعرض أي المفاتيح مضبوطة دون كشف قيمها."""
    return {
        "supabase_connected": supabase is not None,
        "supabase_url_set": bool(SUPABASE_URL),
        "supabase_key_set": bool(SUPABASE_KEY),
        "supabase_key_kind": (
            "service_role" if SUPABASE_KEY and "service_role" in str(SUPABASE_KEY)
            else "publishable/anon (⚠️ RLS قد يمنع الكتابة)" if SUPABASE_KEY and
            str(SUPABASE_KEY).startswith(("sb_publishable", "eyJ"))
            else "unknown" if SUPABASE_KEY else "missing"
        ),
        "supabase_init_error": SUPABASE_ERROR,
        "datarobot_token_set": bool(DATAROBOT_API_TOKEN),
        "datarobot_deployment_set": bool(DATAROBOT_DEPLOYMENT_ID),
        "twilio_ready": bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_PHONE),
        "twilio_recipients": len(TEAM_NUMBERS),
        "allowed_origins": ALLOWED_ORIGINS,
        "anomaly_threshold": ANOMALY_THRESHOLD,
        "simulator": SIM_STATE,
        "packages_in_memory": len(PACKAGES),
    }


@app.get("/")
async def root():
    return {"service": "SentriX AI Engine", "version": "4.0.0", "docs": "/docs"}


@app.on_event("startup")
async def startup_event():
    hydrate_from_supabase()
    if not PACKAGES:
        # تعبئة أولية حتى لا تظهر المنصة فارغة
        for _ in range(8):
            try:
                process_incident(build_sim_incident())
            except Exception as e:
                print(f"[seed] {e}")
    asyncio.create_task(simulator_loop())


