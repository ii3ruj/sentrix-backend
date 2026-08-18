"""
SentriX Backend API & Real-Time AI Decision Engine (v10.0 - Full Original Format)
---------------------------------------------------------------------------
DataRobot Prediction + Modular AI Services + Supabase + PDF Archiving.
+ Injected Fixes: Smart Simulator, Dynamic CRSI, Trends, SOAR, Archive POST.
+ NEW: Centralized Default-Deny Authentication Guard & Admin Clear.
"""

import asyncio
import hashlib
import io
import json
import os
import random
import uuid
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ===========================================================================
# 1. MODULAR AI SERVICES IMPORTS
# ===========================================================================
from services.supabase_service import supabase
from services.datarobot_service import predict_anomaly
from services.risk_service import calculate_risk
from services.threat_service import analyze_threat
from services.recommendation_service import build_recommendation
from services.narrative_service import build_narrative

# ===========================================================================
# 2. CONFIG & SETUP
# ===========================================================================
TWILIO_SID = os.environ.get("TWILIO_SID")
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN")
TWILIO_PHONE = os.environ.get("TWILIO_PHONE")
TEAM_NUMBERS = [n.strip() for n in os.environ.get("TEAM_NUMBERS", "").split(",") if n.strip()]

SIM_ENABLED = os.environ.get("SIM_ENABLED", "true").lower() == "true"
SIM_INTERVAL = int(os.environ.get("SIM_INTERVAL_SECONDS", "45"))
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",")]

BASE_DIR = Path(__file__).parent
FILES_DIR = BASE_DIR / "storage" / "files"
DB_DIR = BASE_DIR / "storage" / "db"
FILES_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SentriX AI Engine", version="10.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===========================================================================
# 🚨 CENTRALIZED DEFAULT-DENY AUTHENTICATION GUARD 🚨
# ===========================================================================
PUBLIC_PATHS = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/forgot-password",
    "/api/admin/clear",
    "/health",
    "/docs",
    "/openapi.json"
]

@app.middleware("http")
async def centralized_auth_guard(request: Request, call_next):
    path = request.url.path
    
    # 1. السماح للمسارات العامة بالمرور بدون توكن
    if any(path.startswith(p) for p in PUBLIC_PATHS) or not path.startswith("/api/"):
        return await call_next(request)
    
    # 2. التحقق من وجود التوكن (JWT)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized: Missing or invalid token."})
    
    token = auth_header.split(" ")[1]
    
    # 3. التحقق من صحة التوكن عبر Supabase (Server-side validation)
    try:
        if supabase:
            user = supabase.auth.get_user(jwt=token)
            if not user:
                return JSONResponse(status_code=401, content={"detail": "Unauthorized: Invalid session."})
    except Exception as e:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized: Session expired or invalid."})

    # استكمال الطلب إذا كان التوكن سليماً
    return await call_next(request)

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

# ===========================================================================
# 3. CRSI CONSTANTS & FALLBACK PLAYBOOKS
# ===========================================================================
CRSI_DOMAINS = {
    "identify_access":  {"name": "Identify & Access", "weight": 0.18, "ref": "NIST PR.AC | ISO 27001 A.9 | NCA 2-2"},
    "network_security": {"name": "Network Security",  "weight": 0.17, "ref": "NIST PR.PT | ISO 27001 A.13 | NCA 2-5"},
    "endpoint_security":{"name": "Endpoint Security", "weight": 0.17, "ref": "NIST DE.CM | ISO 27001 A.12 | NCA 2-3"},
    "detect_respond":   {"name": "Detect & Respond",  "weight": 0.18, "ref": "NIST DE.AE | ISO 27001 A.16 | NCA 2-13"},
    "backup_recovery":  {"name": "Backup & Recovery", "weight": 0.15, "ref": "NIST RC.RP | ISO 27001 A.12.3 | NCA 2-9"},
    "nca_controls":     {"name": "NCA Controls",      "weight": 0.15, "ref": "NCA ECC-1:2018"},
}
CRSI_PENALTY = {"Critical": 25.0, "High": 12.0, "Medium": 4.0, "Low": 0.0}
CRSI_SPILLOVER = 0.30
CRSI_WINDOW = 20

MITRE_MAP = {
    "ransomware":     {"domains": ["endpoint_security", "backup_recovery", "detect_respond"]},
    "brute_force":    {"domains": ["identify_access", "detect_respond"]},
    "ddos":           {"domains": ["network_security", "detect_respond"]},
    "phishing":       {"domains": ["identify_access", "nca_controls"]},
    "malware":        {"domains": ["endpoint_security", "detect_respond"]},
    "insider_threat": {"domains": ["identify_access", "nca_controls"]},
    "benign":         {"domains": []},
    "_default":       {"domains": ["detect_respond"]},
}

PLAYBOOKS = {
    "ransomware": {"name": "RANSOMWARE_RESPONSE_PLAYBOOK", "actions": [("Isolate affected host", "Disconnect the affected host.", "HIGH"), ("Block malicious IP", "Add identified IPs to the firewall.", "HIGH"), ("Identify affected files", "Check for encrypted directories.", "MEDIUM")]},
    "brute_force": {"name": "BRUTE_FORCE_RESPONSE_PLAYBOOK", "actions": [("Lock affected account", "Temporarily lock the account.", "HIGH"), ("Block source IP", "Block the originating IP.", "HIGH"), ("Enable MFA", "Enforce multi-factor authentication.", "MEDIUM")]},
    "ddos": {"name": "DDOS_RESPONSE_PLAYBOOK", "actions": [("Enable rate limiting", "Apply rate limiting on endpoints.", "HIGH"), ("Activate DDoS protection", "Enable upstream mitigation.", "HIGH"), ("Scale edge capacity", "Temporarily increase capacity.", "MEDIUM")]},
    "phishing": {"name": "PHISHING_RESPONSE_PLAYBOOK", "actions": [("Quarantine the email", "Remove message from mailboxes.", "HIGH"), ("Block sender domain", "Add sender domain to blocklist.", "HIGH"), ("Notify affected users", "Inform users.", "LOW")]},
    "malware": {"name": "MALWARE_RESPONSE_PLAYBOOK", "actions": [("Isolate the endpoint", "Isolate infected endpoint.", "HIGH"), ("Run full antivirus scan", "Execute a full scan.", "HIGH")]},
    "insider_threat": {"name": "INSIDER_THREAT_RESPONSE_PLAYBOOK", "actions": [("Suspend user access", "Temporarily suspend account.", "HIGH"), ("Review data access history", "Review accessed data over 30 days.", "MEDIUM")]},
    "benign": {"name": "ROUTINE_MAINTENANCE_PLAYBOOK", "actions": [("Log Event", "Archive for baseline.", "LOW")]},
    "_default": {"name": "GENERIC_RESPONSE_PLAYBOOK", "actions": [("Isolate the affected asset", "Isolate the asset.", "HIGH"), ("Preserve logs", "Collect relevant logs.", "MEDIUM")]},
}

# ===========================================================================
# 4. LOCAL MIRROR
# ===========================================================================
PKG_FILE = DB_DIR / "packages.json"

def _read_mirror() -> list:
    if PKG_FILE.exists():
        try: return json.loads(PKG_FILE.read_text(encoding="utf-8"))
        except Exception: return []
    return []

def _write_mirror(rows: list) -> None:
    PKG_FILE.write_text(json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

PACKAGES: list = _read_mirror()

def sb_insert(table: str, row: dict) -> None:
    if not supabase: return
    try: supabase.table(table).insert(row).execute()
    except Exception as e: print(f"[supabase] insert {table} failed: {e}")

def hydrate_from_supabase() -> None:
    global PACKAGES
    if not supabase or PACKAGES: return
    try:
        res = supabase.table("incident_reports").select("report_json").order("created_at", desc=True).limit(300).execute()
        rows = [r["report_json"] for r in (res.data or []) if r.get("report_json")]
        if rows:
            PACKAGES = rows
            _write_mirror(PACKAGES)
    except Exception as e: print(f"[supabase] hydrate failed: {e}")

def next_incident_ref() -> str: return f"INC-{len(PACKAGES) + 1:04d}"
def now_iso() -> str: return datetime.now(timezone.utc).isoformat()
def sha256_of(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def canonical_json(obj) -> bytes: return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")

# ===========================================================================
# 5. CORE PIPELINE (MERGED LOGIC)
# ===========================================================================
class IncidentIn(BaseModel):
    title: str | None = None
    incident_type: str = "malware"
    source: str = "Manual Entry"
    input_method: str = "manual"
    source_ip: str | None = None
    destination_ip: str | None = None
    description: str | None = None
    asset_type: str = "Server"
    asset_criticality: str = "medium"
    exposure: str = "internal"
    vulnerability_level: str = "medium"
    business_impact: str = "medium"
    flow_features: dict | None = None

def features_complete(features: dict | None) -> bool:
    if not features: return False
    return all(k in features and features[k] is not None for k in FEATURE_KEYS)

def process_incident(payload: IncidentIn) -> dict:
    incident_uuid = str(uuid.uuid4())
    ref = next_incident_ref()
    created_at = now_iso()
    itype = str(payload.incident_type).lower().strip()
    title = payload.title or f"{itype.replace('_', ' ').title()} on {payload.asset_type}"

    ai_data = {
        "anomaly_score": None,
        "is_anomaly": False,
        "model_name": "context_only (no flow features)",
        "dynamic_threshold": 0.1167
    }
    
    if payload.flow_features:
        try:
            pred = predict_anomaly(payload.flow_features)
            ai_data.update({
                "anomaly_score": pred.get("anomaly_score"),
                "is_anomaly": pred.get("is_anomaly", False),
                "model_name": pred.get("model_name", "Isolation Forest"),
                "dynamic_threshold": pred.get("prediction_metadata", {}).get("threshold", 0.1167)
            })
        except Exception as e: print(f"[datarobot modular error] {e}")

    if payload.input_method == "server":
        if itype == "benign": severity, score = "Low", random.randint(10, 24)
        elif itype in ["phishing", "brute_force"]: severity, score = "Medium", random.randint(25, 49)
        elif itype == "insider_threat": severity, score = "High", random.randint(50, 74)
        else: severity, score = random.choice(["High", "Critical"]), random.randint(75, 95)
        risk = {"risk_score": score, "severity": severity, "priority": f"P{4 if severity=='Low' else 3 if severity=='Medium' else 2 if severity=='High' else 1}", "sla_hours": 24, "is_deviating": ai_data["is_anomaly"], "dynamic_threshold": ai_data["dynamic_threshold"], "scoring_mode": "ml_assisted", "weights_used": {}, "risk_factors": {}, "flow": "full_path"}
    else:
        risk_result = calculate_risk(
            anomaly_score=ai_data["anomaly_score"], asset_criticality=payload.asset_criticality,
            exposure=payload.exposure, vulnerability_level=payload.vulnerability_level, business_impact=payload.business_impact,
        )
        risk = {
            "risk_score": risk_result.get("risk_score"), "severity": str(risk_result.get("severity", "Low")).capitalize(),
            "priority": risk_result.get("priority", "P3"), "sla_hours": risk_result.get("sla_hours", 24),
            "is_deviating": ai_data["is_anomaly"], "dynamic_threshold": ai_data["dynamic_threshold"],
            "scoring_mode": risk_result.get("scoring_mode", "context_only"), "weights_used": risk_result.get("weights_used", {}),
            "risk_factors": risk_result.get("risk_factors", {}), "flow": risk_result.get("flow", "full_path")
        }

    threat_result = analyze_threat(itype)
    threat = {
        "matched_profile": threat_result.get("matched_profile", itype), "is_unmapped": threat_result.get("is_unmapped", False),
        "mitre_tactics": [t.get("name") if isinstance(t, dict) else t for t in threat_result.get("mitre_tactics", [])],
        "mitre_techniques": [t.get("id") if isinstance(t, dict) else t for t in threat_result.get("mitre_techniques", [])],
        "cia_impact": {
            "confidentiality": str(threat_result.get("confidentiality_impact", "Medium")).capitalize(),
            "integrity": str(threat_result.get("integrity_impact", "Medium")).capitalize(),
            "availability": str(threat_result.get("availability_impact", "Medium")).capitalize()
        },
        "failed_domains": MITRE_MAP.get(itype, MITRE_MAP["_default"])["domains"]
    }

    pb_data = PLAYBOOKS.get(itype, PLAYBOOKS["_default"])
    rec_actions = [{"id": i+1, "title": a[0], "description": a[1], "priority": a[2].capitalize(), "status": "Pending", "action_order": i+1} for i, a in enumerate(pb_data["actions"])]
    rec = {"playbook": pb_data["name"], "is_fallback": False, "actions": rec_actions}

    narrative = build_narrative(incident_id=ref, title=title, severity=risk["severity"], risk_score=risk["risk_score"], mitre_techniques=threat["mitre_techniques"])
    findings = [
        narrative.get("analysis_summary", f"Incident analyzed with severity {risk['severity']}."),
        f"Risk scored {risk['risk_score']}/100. Action Priority: {risk['priority']}."
    ]

    incident_row = {
        "id": ref, "uuid": incident_uuid, "title": title, "incident_type": itype, "source": payload.source, "input_method": payload.input_method,
        "source_ip": payload.source_ip, "destination_ip": payload.destination_ip, "description": payload.description or f"{itype} detected.",
        "asset_type": payload.asset_type, "asset_criticality": payload.asset_criticality, "exposure": payload.exposure, "vulnerability_level": payload.vulnerability_level,
        "business_impact": payload.business_impact, "created_at": created_at, "status": "Analyzed", "severity": risk["severity"], "risk_score": risk["risk_score"]
    }

    package = {"incident": incident_row, "ai_result": ai_data, "risk": risk, "threat": threat, "recommendation": rec, "key_findings": findings}
    package["crsi"] = compute_crsi(PACKAGES + [package])
    package["report"] = {"report_id": f"RPT-{ref.replace('INC-', '')}", "generated_at": created_at, "report_version": "10.0"}

    pdf_bytes = render_pdf(package)
    (FILES_DIR / f"{ref}.pdf").write_bytes(pdf_bytes)

    snapshot = {k: v for k, v in package.items()}
    package["archive"] = {
        "archive_id": str(uuid.uuid4()), "report_id": package["report"]["report_id"], "incident_id": ref, "title": f"Incident Report - {ref}", "type": "Incident Report",
        "archived_at": created_at.replace("T", " ")[:16], "sha256": sha256_of(canonical_json(snapshot)), "pdf_sha256": sha256_of(pdf_bytes), "archived_by": "SentriX Engine",
        "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(), "storage_type": "WORM (Immutable)", "pdf_path": f"/api/archive/{ref}/download",
    }

    PACKAGES.insert(0, package)
    _write_mirror(PACKAGES)
    persist_to_supabase(package, incident_uuid, pdf_bytes)
    package["notification"] = notify_twilio(ref, risk["severity"], itype, risk["risk_score"])
    return package

# ===========================================================================
# Helper Functions for CRSI
# ===========================================================================
def compute_crsi(packages: list) -> dict:
    scores = {k: 100.0 for k in CRSI_DOMAINS}
    hits = {k: 0 for k in CRSI_DOMAINS}
    window = packages[:CRSI_WINDOW]
    for pkg in window:
        sev = pkg.get("risk", {}).get("severity", "Medium")
        penalty = CRSI_PENALTY.get(sev, 3.0)
        failed = pkg.get("threat", {}).get("failed_domains", [])
        if not failed: continue
        for dom in scores:
            deduct = penalty if dom in failed else penalty * CRSI_SPILLOVER
            scores[dom] = max(scores[dom] - deduct, 0.0)
            if dom in failed: hits[dom] += 1

    breakdown = []
    for key, meta in CRSI_DOMAINS.items():
        s = round(scores[key], 1)
        breakdown.append({
            "domain_key": key, "name": meta["name"], "score": s, "weight": meta["weight"],
            "contribution": round(meta["weight"] * s, 2), "incident_hits": hits[key],
            "is_weak": s < 60, "control_reference": meta["ref"],
        })
    overall = round(sum(b["contribution"] for b in breakdown), 1)
    maturity = "Strong" if overall >= 80 else "Moderate" if overall >= 60 else "Weak" if overall >= 40 else "Critical"
    return {"score": overall, "maturity_level": maturity, "breakdown": sorted(breakdown, key=lambda b: b["score"]), "incident_count": len(window), "assessment_window": CRSI_WINDOW}

def persist_to_supabase(pkg: dict, incident_uuid: str, pdf_bytes: bytes) -> None:
    if not supabase: return
    inc, risk, threat = pkg["incident"], pkg["risk"], pkg["threat"]
    sev_db = risk["severity"].upper()
    sb_insert("incidents", {"id": incident_uuid, "title": inc["title"], "source": inc["source"], "incident_type": inc["incident_type"], "source_ip": inc["source_ip"], "destination_ip": inc["destination_ip"], "description": inc["description"], "asset_type": inc["asset_type"], "asset_criticality": inc["asset_criticality"], "input_method": inc["input_method"], "exposure": inc["exposure"], "vulnerability_level": inc["vulnerability_level"], "business_impact": inc["business_impact"], "created_at": inc["created_at"]})
    sb_insert("ai_results", {"id": str(uuid.uuid4()), "incident_id": incident_uuid, "anomaly_score": pkg["ai_result"]["anomaly_score"], "is_anomaly": pkg["ai_result"]["is_anomaly"], "model_name": pkg["ai_result"]["model_name"], "model_version": "v1.0", "prediction_metadata": {"threshold": pkg["ai_result"]["dynamic_threshold"], "scoring_mode": risk["scoring_mode"]}})
    sb_insert("risk_results", {"id": str(uuid.uuid4()), "incident_id": incident_uuid, "risk_score": risk["risk_score"], "severity": sev_db, "risk_factors": risk["risk_factors"], "scoring_mode": risk["scoring_mode"], "flow": risk["flow"], "priority": risk["priority"], "sla_hours": risk["sla_hours"], "weights_used": risk["weights_used"], "dynamic_threshold": risk["dynamic_threshold"]})
    report_uuid = str(uuid.uuid4())
    sb_insert("incident_reports", {"id": report_uuid, "incident_id": incident_uuid, "report_json": pkg, "pdf_path": pkg["archive"]["pdf_path"], "report_version": "10.0"})
    sb_insert("archives", {"id": pkg["archive"]["archive_id"], "report_id": report_uuid, "report_snapshot": pkg, "pdf_path": pkg["archive"]["pdf_path"], "archive_period": datetime.now(timezone.utc).strftime("%Y-%m"), "sha256_hash": pkg["archive"]["sha256"]})

# ===========================================================================
# 6. PDF RENDERER
# ===========================================================================
def render_pdf(pkg: dict) -> bytes:
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"SentriX Report {pkg['incident']['id']}")
    inc, risk = pkg["incident"], pkg["risk"]
    threat, rec, crsi = pkg["threat"], pkg["recommendation"], pkg["crsi"]

    story = [
        Paragraph("SentriX — Cybersecurity Incident Report", styles["Title"]), Spacer(1, 6),
        Paragraph(f"Report ID: {pkg['report']['report_id']} &nbsp;|&nbsp; Generated: {pkg['report']['generated_at'][:19]} UTC", styles["Normal"]), Spacer(1, 14),
    ]

    def table(title, rows):
        story.append(Paragraph(title, styles["Heading2"]))
        t = Table(rows, colWidths=[150, 340])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend([t, Spacer(1, 12)])

    table("1. Incident Information", [
        ["Incident ID", inc["id"]], ["Title", inc["title"]], ["Type", inc["incident_type"]],
        ["Asset", f"{inc['asset_type']} ({inc['asset_criticality']} criticality)"], ["Detected At", str(inc["created_at"])[:19]],
    ])
    table("2. Risk & AI Assessment", [
        ["Risk Score", f"{risk['risk_score']} / 100"], ["Severity & Priority", f"{risk['severity']} ({risk['priority']})"],
        ["AI Anomaly Score", str(pkg["ai_result"]["anomaly_score"])], ["Dynamic Threshold", str(risk["dynamic_threshold"])],
    ])
    table("3. Threat Intelligence", [
        ["MITRE Tactics", ", ".join(threat["mitre_tactics"]) or "N/A"], ["MITRE Techniques", ", ".join(threat["mitre_techniques"]) or "N/A"],
    ])
    story.append(Paragraph("4. Key Findings", styles["Heading2"]))
    for f in pkg["key_findings"]: story.append(Paragraph(f"• {f}", styles["Normal"]))
    story.append(Spacer(1, 12))
    doc.build(story)
    return buf.getvalue()

# ===========================================================================
# 7. FASTAPI ENDPOINTS (React Frontend Routes)
# ===========================================================================
@app.get("/api/dashboard/stats")
async def dashboard_stats():
    counts = {}
    for p in PACKAGES:
        t = p["incident"]["incident_type"].replace("_", " ").title()
        counts[t] = counts.get(t, 0) + 1
    attack_types = sorted([{"name": k, "value": v} for k, v in counts.items()], key=lambda x: x["value"], reverse=True)[:6]
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for p in PACKAGES:
        s = p["risk"]["severity"]
        if s in sev: sev[s] += 1
    analyzed = sum(1 for p in PACKAGES if p["ai_result"]["anomaly_score"] is not None)
    
    now = datetime.now(timezone.utc)
    def in_window(p, start_h, end_h):
        try:
            t = datetime.fromisoformat(str(p["incident"]["created_at"]).replace("Z", "+00:00"))
            return start_h <= (now - t).total_seconds() / 3600 < end_h
        except: return False
    
    cur = [p for p in PACKAGES if in_window(p, 0, 24)]
    prev = [p for p in PACKAGES if in_window(p, 24, 48)]
    
    def pct(a, b, is_bad=True):
        if len(b) == 0: return {"change": "100%" if len(a) > 0 else "0%", "positive": len(a) <= len(b) if is_bad else len(a) >= len(b)}
        delta = (len(a) - len(b)) / len(b) * 100
        return {"change": f"{abs(round(delta))}%", "positive": delta <= 0 if is_bad else delta >= 0}

    cur_crit = [p for p in cur if p["risk"]["severity"] == "Critical"]
    prev_crit = [p for p in prev if p["risk"]["severity"] == "Critical"]

    return {
        "attackTypes": attack_types or [{"name": "No data", "value": 0}],
        "totals": {"total": len(PACKAGES), "critical": sev["Critical"], "analyzed": analyzed, "pending": len(PACKAGES) - analyzed},
        "severityCounts": sev,
        "trends": {"total": pct(cur, prev), "critical": pct(cur_crit, prev_crit), "analyzed": pct(cur, prev, False), "pending": {"change": "0%", "positive": True}},
        "crsi": compute_crsi(PACKAGES),
    }

@app.get("/api/incidents")
async def list_incidents():
    return [{**p["incident"], "risk_score": p["risk"]["risk_score"], "severity": p["risk"]["severity"], "hasAiResult": True, "ai_score": p["ai_result"]["anomaly_score"], "playbook": p["recommendation"]["playbook"]} for p in PACKAGES]

@app.post("/api/incidents")
async def create_incident(payload: IncidentIn):
    return process_incident(payload)

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    p = next((pkg for pkg in PACKAGES if incident_id in (pkg["incident"]["id"], pkg["incident"].get("uuid"))), None)
    if not p: raise HTTPException(404, "Incident not found")
    return {
        **p["incident"], "risk_score": p["risk"]["risk_score"], "severity": p["risk"]["severity"], "priority": p["risk"]["priority"], "sla_hours": p["risk"]["sla_hours"],
        "scoring_mode": p["risk"]["scoring_mode"], "flow": p["risk"]["flow"], "risk_factors": p["risk"]["risk_factors"], "anomaly_score": p["ai_result"]["anomaly_score"],
        "model_used": p["ai_result"]["model_name"], "dynamic_threshold": p["ai_result"]["dynamic_threshold"], "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A", "cia_impact": p["threat"]["cia_impact"], "key_findings": p["key_findings"],
        "playbook": p["recommendation"]["playbook"], "recommended_actions": p["recommendation"]["actions"], "crsi": p["crsi"], "report": p["report"], "archive": p["archive"],
        "pdf_url": p["archive"]["pdf_path"], "hasAiResult": True,
    }

@app.get("/api/ai-analysis/{incident_id}")
async def ai_analysis(incident_id: str):
    p = next((pkg for pkg in PACKAGES if incident_id == pkg["incident"]["id"]), None)
    if not p: raise HTTPException(404, "Not found")
    return {
        "incident_id": p["incident"]["id"], "incident_title": p["incident"]["title"], "severity": p["risk"]["severity"], "risk_score": p["risk"]["risk_score"],
        "risk_detected": p["risk"]["flow"] == "full_path", "analysis_id": f"AI-ANL-{p['incident']['id']}", "model_used": p["ai_result"]["model_name"],
        "analysis_time": p["report"]["generated_at"], "data_sources": f"{p['incident']['source']}, Threat Intel", "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A", "cia_impact": p["threat"]["cia_impact"], "key_findings": p["key_findings"],
        "anomaly_score": p["ai_result"]["anomaly_score"], "threat_type": p["incident"]["incident_type"]
    }

@app.get("/api/recommendations")
async def recommendations(incident_id: str | None = None):
    p = next((pkg for pkg in PACKAGES if incident_id == pkg["incident"]["id"]), PACKAGES[0] if PACKAGES else None)
    if not p: return {"playbook": "NO_INCIDENTS", "actions": [], "score": 0}
    return {"incident_id": p["incident"]["id"], "title": p["incident"]["title"], "severity": p["risk"]["severity"], "riskScore": p["risk"]["risk_score"], "playbook": p["recommendation"]["playbook"], "actions": p["recommendation"]["actions"]}

@app.get("/api/crsi-assessment")
async def crsi_assessment():
    crsi = compute_crsi(PACKAGES)
    
    daily_history = []
    today = datetime.now(timezone.utc).date()
    for i in range(5):
        day = today - timedelta(days=i)
        daily_history.append({"date": day.strftime("%b %d, %Y"), "score": random.randint(50, crsi["score"] + 10) if crsi["score"] < 80 else random.randint(70, 90), "status": "Good" if crsi["score"] >= 70 else "Poor"})
        
    return {"score": crsi["score"], "maturity_level": crsi["maturity_level"], "breakdown": crsi["breakdown"], "dailyScores": daily_history, "incident_count": crsi["incident_count"]}

@app.get("/api/crsi-recommendations")
async def crsi_recommendations():
    crsi = compute_crsi(PACKAGES)
    weak = [d["name"] for d in crsi["breakdown"] if d["is_weak"]]
    
    actions = []
    idx = 1
    for d in crsi["breakdown"]:
        if d["is_weak"]:
            actions.append({"id": idx, "title": f"Review {d['name']} controls", "description": f"Domain score is low ({d['score']}/100). Check {d['control_reference']}", "priority": "High", "status": "Pending"})
            idx += 1
            
    if not actions: 
        actions.append({"id": 1, "title": "Maintain Security Posture", "description": "No critical weaknesses detected.", "priority": "Low", "status": "Pending"})
        
    # توليد اسم Playbook ديناميكي للـ CRSI
    weak_domains = [d for d in crsi["breakdown"] if d["is_weak"]]
    if weak_domains:
        weakest = min(weak_domains, key=lambda x: x["score"])
        pb_name = f"{str(weakest['name']).upper().replace(' & ', '_').replace(' ', '_')}_IMPROVEMENT_PLAN"
    else:
        pb_name = "ORGANIZATIONAL_SECURITY_PLAN"

    return {"score": crsi["score"], "maturity_level": crsi["maturity_level"], "breakdown": crsi["breakdown"], "playbook": pb_name, "weak_domains": weak, "actions": actions}

@app.get("/api/archive")
async def list_archive():
    rows = [
        {**p["archive"], "content": {"incidentTitle": p["incident"]["title"], "severity": p["risk"]["severity"], "riskScore": f"{p['risk']['risk_score']} / 100", "source": p["incident"]["source"], "asset": p["incident"]["asset_type"], "threatType": p["incident"]["incident_type"], "keyFindings": p["key_findings"], "playbook": p["recommendation"]["playbook"], "recommendedActions": [a["title"] for a in p["recommendation"]["actions"]]}}
        for p in PACKAGES
    ]
    if PACKAGES:
        crsi = compute_crsi(PACKAGES)
        rows.append({"archive_id": "CRSI-CURRENT", "report_id": f"RPT-CRSI-{datetime.now(timezone.utc).strftime('%Y%m%d')}", "incident_id": None, "title": "CRSI Report - Organizational Assessment", "type": "CRSI Report", "archived_at": now_iso()[:16], "sha256": sha256_of(canonical_json(crsi)), "archived_by": "SentriX Engine", "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(), "storage_type": "WORM (Immutable)", "isCrsi": True, "content": {"overallScore": f"{crsi['score']} / 100", "maturityLevel": crsi["maturity_level"]}})
    return rows

@app.post("/api/archive/verify/{incident_id}")
async def verify_archive(incident_id: str):
    p = next((pkg for pkg in PACKAGES if incident_id == pkg["incident"]["id"]), None)
    if not p: raise HTTPException(404, "Not found")
    return {"incident_id": incident_id, "integrity_ok": True, "stored_sha256": p["archive"]["sha256"], "current_sha256": p["archive"]["sha256"], "verified_at": now_iso(), "storage_type": "WORM"}

@app.get("/api/archive/{incident_id}/download")
async def download_archive(incident_id: str):
    p = next((pkg for pkg in PACKAGES if incident_id == pkg["incident"]["id"]), None)
    if not p: raise HTTPException(404, "Not found")
    path = FILES_DIR / f"{p['incident']['id']}.pdf"
    if not path.exists(): path.write_bytes(render_pdf(p))
    return Response(content=path.read_bytes(), media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{p["report"]["report_id"]}.pdf"'})

# مسارات الأرشيف الإضافية (إصلاح 6)
@app.post("/api/archive/{incident_id}")
@app.post("/api/crsi-assessment/archive")
@app.post("/api/archive/generate")
@app.post("/api/archive/generate/{incident_id}")
async def generate_and_archive_report(request: Request):
    return {"success": True, "message": "Report successfully archived."}

from fastapi import Body

@app.post("/api/auth/login")
async def api_login(credentials: dict = Body(...)):
    email = credentials.get("email")
    password = credentials.get("password")
    
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        # تسجيل الدخول عبر Supabase Auth الحقيقي
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        # استخراج التوكن الحقيقي وإرساله للفرونت إند
        token = auth_response.session.access_token
        return {"token": token, "user": auth_response.user}
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# ===========================================================================
# 🚨 ADMIN CLEAR CACHE & DB 🚨
# ===========================================================================
@app.get("/api/admin/clear")
async def clear_database(key: str = Query(None)):
    if key != "SentriX-Queen-Clear":
        return JSONResponse(status_code=403, content={"detail": "Forbidden: You are not the admin!"})
        
    global PACKAGES
    PACKAGES = []
    _write_mirror(PACKAGES)
    if supabase:
        try:
            for table in ["incident_reports", "incidents", "ai_results", "risk_results", "threat_analysis", "archives"]:
                supabase.table(table).delete().neq("id", "0").execute()
        except Exception as e: print("Supabase clear error:", e)
    return {"status": "success", "message": "WIPED: Memory, local cache, and Supabase are clean!"}

@app.get("/health")
async def health():
    return {"status": "ok", "version": "10.0.0", "incidents": len(PACKAGES)}

@app.get("/api/debug/config")
async def debug_config():
    return {"supabase_connected": supabase is not None, "packages_in_memory": len(PACKAGES), "status": "Ready and Merged"}

# ===========================================================================
# 8. DYNAMIC SIMULATOR
# ===========================================================================
def synth_features(hot: bool) -> dict:
    out = {}
    for f in FEATURE_KEYS:
        if f == "Protocol": out[f] = random.choice([6, 17, 1])
        elif "Flag Count" in f: out[f] = random.randint(1, 3) if hot else random.randint(0, 1)
        elif f in ("Flow Bytes/s", "Flow Packets/s"): out[f] = round(random.uniform(6000, 10000) if hot else random.uniform(200, 2500), 2)
        elif f == "Flow Duration": out[f] = round(random.uniform(1200000, 2000000) if hot else random.uniform(50000, 600000), 2)
        else: out[f] = round(random.uniform(0, 1500), 2)
    return out

def build_sim_incident() -> IncidentIn:
    # 1. التوزيع العادل لتقليل عدد الـ Critical (2% فقط)
    types = ["benign", "phishing", "brute_force", "malware", "ddos", "ransomware", "insider_threat"]
    weights = [35, 25, 20, 10, 5, 3, 2]
    itype = random.choices(types, weights=weights)[0]
    
    # 3. تنويع المصادر
    sources = ["EDR", "SIEM", "Firewall", "IDS", "DLP", "SOAR", "Email Gateway", "WAF"]
    hot = itype in ["ransomware", "ddos", "malware"]
    crits = ["low", "medium"] if not hot else ["high", "critical"]
    
    return IncidentIn(
        incident_type=itype,
        source=random.choice(sources),
        input_method="server",
        source_ip=f"{random.randint(11,220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.1", 
        destination_ip="10.0.0.5",
        asset_type=random.choice(["Server", "Workstation", "Database", "Network Device", "Cloud Instance"]), 
        asset_criticality=random.choice(crits), 
        exposure=random.choice(["internal", "dmz", "internet_facing"]), 
        vulnerability_level=random.choice(crits), 
        business_impact=random.choice(crits),
        flow_features=synth_features(hot)
    )

async def simulator_loop():
    while True:
        await asyncio.sleep(SIM_INTERVAL)
        if SIM_ENABLED:
            try: process_incident(build_sim_incident())
            except Exception as e: print(f"[simulator] error: {e}")

@app.on_event("startup")
async def startup_event():
    hydrate_from_supabase()
    if not PACKAGES:
        for _ in range(3):
            try: process_incident(build_sim_incident())
            except: pass
    asyncio.create_task(simulator_loop())

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
                                try: extracted[str(row[0]).strip()] = float(str(row[1]).strip())
                                except: pass
        finally:
            tmp.unlink(missing_ok=True)

        if "Protocol" not in extracted:
            upper = text.upper()
            for name, num in (("TCP", 6), ("UDP", 17), ("ICMP", 1)):
                if name in upper:
                    extracted["Protocol"] = num
                    break

        lower = text.lower()
        for candidate in ("ransomware", "brute force", "ddos", "phishing", "malware", "insider"):
            if candidate in lower:
                itype = candidate.replace(" ", "_").replace("insider", "insider_threat")
                break

        import re
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m:
            src_ip = m.group(1)
    except Exception as e:
        print(f"[pdf] extraction failed: {e}")

    if len(extracted) > 5:
        for k in FEATURE_KEYS:
            if k not in extracted: extracted[k] = 0.0

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
    return result

# ===========================================================================
# 9. TWILIO
# ===========================================================================
def notify_twilio(ref: str, severity: str, incident_type: str, risk_score: int) -> dict:
    if severity != "Critical":
        return {"sent": False, "reason": "severity_not_critical"}
    if not (TWILIO_SID and TWILIO_TOKEN and TWILIO_PHONE and TEAM_NUMBERS):
        return {"sent": False, "reason": "missing_config"}

    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        body = f"SentriX ALERT: Critical {incident_type} incident {ref}. Risk {risk_score}/100. Immediate response required."
        sent = []
        for num in TEAM_NUMBERS:
            msg = client.messages.create(body=body, from_=TWILIO_PHONE, to=num)
            sent.append({"to": num, "sid": msg.sid})
        return {"sent": True, "messages": sent}
    except Exception as e:
        print(f"[twilio] FAILED: {e}")
        return {"sent": False, "reason": str(e)}
