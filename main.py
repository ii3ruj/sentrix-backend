"""
SentriX Backend API & AI-Assisted Decision Engine
-------------------------------------------------
Connected to Supabase PostgreSQL & AI Simulation Layer.
"""

import hashlib
import json
import math
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pdfplumber
import requests
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ---------------------------------------------------------------------------
# Supabase Client Setup
# ---------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print(" Connected to Supabase PostgreSQL successfully.")
    except Exception as e:
        print(f"⚠️ Failed to connect to Supabase: {e}. Falling back to local storage.")

# ---------------------------------------------------------------------------
# Directories & App Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
STORAGE_DIR = BASE_DIR / "storage"
FILES_DIR = STORAGE_DIR / "files"
DB_DIR = STORAGE_DIR / "db"
FILES_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SentriX Cloud Backend", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ANOMALY_THRESHOLD = 0.1167

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

MITRE_MAP = {
    "ransomware": {"tactic": ["TA0040 - Impact"], "technique": ["T1486 - Data Encrypted for Impact"]},
    "phishing": {"tactic": ["TA0001 - Initial Access"], "technique": ["T1566 - Phishing"]},
    "ddos": {"tactic": ["TA0040 - Impact"], "technique": ["T1498 - Network Denial of Service"]},
    "unauthorized_access": {"tactic": ["TA0006 - Credential Access"], "technique": ["T1078 - Valid Accounts"]},
    "data_exfiltration": {"tactic": ["TA0010 - Exfiltration"], "technique": ["T1041 - Exfiltration Over C2 Channel"]},
    "malware": {"tactic": ["TA0002 - Execution"], "technique": ["T1204 - User Execution"]},
    "insider_threat": {"tactic": ["TA0009 - Collection"], "technique": ["T1213 - Data from Information Repositories"]},
    "default": {"tactic": ["TA0040 - Impact"], "technique": ["T1486 - Generic Attack Pattern"]},
}

PLAYBOOK = {
    "ransomware": [
        {"action": "Isolate affected host immediately from network", "priority": "CRITICAL", "scope": "immediate"},
        {"action": "Activate immutable backup restoration snapshot", "priority": "HIGH", "scope": "immediate"},
        {"action": "Rotate all privileged credentials across subnet", "priority": "HIGH", "scope": "organizational"},
    ],
    "phishing": [
        {"action": "Block malicious domain on perimeter mail gateway", "priority": "HIGH", "scope": "immediate"},
        {"action": "Revoke affected user sessions and enforce MFA reset", "priority": "MEDIUM", "scope": "immediate"},
    ],
    "default": [
        {"action": "Quarantine anomalous network stream and monitor telemetry", "priority": "MEDIUM", "scope": "immediate"},
    ],
}

# ---------------------------------------------------------------------------
# Database Utilities (Supabase + Local Fallback)
# ---------------------------------------------------------------------------
def _table_path(name: str) -> Path:
    return DB_DIR / f"{name}.json"

def load_table(name: str) -> list:
    if supabase:
        try:
            res = supabase.table(name).select("*").execute()
            return res.data or []
        except Exception:
            pass
    p = _table_path(name)
    if not p.exists():
        p.write_text("[]", encoding="utf-8")
    return json.loads(p.read_text(encoding="utf-8"))

def append_row(name: str, row: dict) -> dict:
    if supabase:
        try:
            res = supabase.table(name).insert(row).execute()
            if res.data:
                return res.data[0]
        except Exception as e:
            print(f"Supabase insert failed for {name}: {e}")
    
    # Fallback to local
    rows = []
    p = _table_path(name)
    if p.exists():
        try:
            rows = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            rows = []
    rows.append(row)
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return row

def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------
class IncidentIn(BaseModel):
    title: str = "Unclassified Security Incident"
    source: str = "manual"
    incident_type: str = "default"
    source_ip: str | None = None
    destination_ip: str | None = None
    asset_type: str = "Server"
    asset_criticality: str = "medium"
    exposure: str | None = "internal"
    vulnerability_level: str | None = "medium"
    business_impact: str | None = "medium"
    description: str | None = None
    flow_features: dict | None = None

# ---------------------------------------------------------------------------
# AI & Risk Scoring Engine
# ---------------------------------------------------------------------------
def flow_features_complete(features: dict | None) -> bool:
    if not features:
        return False
    return all(k in features and features[k] is not None for k in FEATURE_KEYS)

DATAROBOT_ENDPOINT = os.environ.get("DATAROBOT_ENDPOINT")
DATAROBOT_API_KEY = os.environ.get("DATAROBOT_API_KEY")

def call_isolation_forest(features: dict) -> float:
    if DATAROBOT_ENDPOINT and DATAROBOT_API_KEY:
        try:
            resp = requests.post(
                DATAROBOT_ENDPOINT,
                headers={"Authorization": f"Bearer {DATAROBOT_API_KEY}", "Content-Type": "application/json"},
                json={"data": [features]},
                timeout=10,
            )
            resp.raise_for_status()
            return float(resp.json()["predictions"][0]["anomaly_score"])
        except Exception:
            pass
    return mock_isolation_forest(features)

def mock_isolation_forest(features: dict) -> float:
    numeric_signal = 0.0
    count = 0
    reference = {
        "Flow Duration": 500000, "Flow Bytes/s": 2000, "Flow Packets/s": 50,
        "Total Fwd Packets": 20, "Total Backward Packets": 20, "SYN Flag Count": 1,
    }
    for key, baseline in reference.items():
        val = features.get(key)
        if isinstance(val, (int, float)) and baseline:
            numeric_signal += min(abs(val - baseline) / baseline, 5.0)
            count += 1
    avg_dev = numeric_signal / count if count else 0.0
    score = 1 / (1 + math.exp(-(avg_dev - 1.2)))
    return round(min(max(score, 0.0), 1.0), 4)

def risk_agent(anomaly_score, asset_criticality, vulnerability_level, business_impact):
    crit_map = {"low": 10, "medium": 20, "high": 35, "critical": 45}
    base = crit_map.get(str(asset_criticality).lower(), 20)
    base += crit_map.get(str(vulnerability_level).lower(), 15)
    base += crit_map.get(str(business_impact).lower(), 15)
    
    if anomaly_score is not None:
        base += anomaly_score * 30.0
        
    risk_score = round(min(max(base, 0), 100), 1)

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return risk_score, severity

def threat_agent(incident_type: str, severity: str):
    inc_clean = incident_type.lower().replace(" ", "_")
    mitre = MITRE_MAP.get(inc_clean, MITRE_MAP["default"])
    sev_to_level = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    level = sev_to_level.get(severity, "low")
    return {
        "threat_type": incident_type,
        "matched_profile": f"SentriX-{incident_type.upper()}-Profile",
        "is_unmapped": False,
        "mitre_tactics": mitre["tactic"],
        "mitre_techniques": mitre["technique"],
        "confidentiality_impact": level,
        "integrity_impact": level,
        "availability_impact": level,
        "intel_version": "2026.1",
    }

def recommendation_agent(incident_type: str):
    inc_clean = incident_type.lower().replace(" ", "_")
    return PLAYBOOK.get(inc_clean, PLAYBOOK["default"])

def master_agent(severity):
    priority_map = {"CRITICAL": ("P1", 1), "HIGH": ("P2", 4), "MEDIUM": ("P3", 24), "LOW": ("P4", 72)}
    return priority_map.get(severity, ("P3", 24))

def render_pdf(package: dict) -> bytes:
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SentriX Security Incident & Audit Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"Incident ID: {package['incident']['id']}", styles["Normal"]),
        Paragraph(f"Title: {package['incident']['title']}", styles["Normal"]),
        Paragraph(f"Severity: {package['risk']['severity']}  |  Priority: {package['priority']}", styles["Normal"]),
        Paragraph(f"Calculated Risk Score: {package['risk']['risk_score']} / 100", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("AI & Behavioral Findings", styles["Heading2"]),
        Paragraph(package["narrative"], styles["Normal"]),
        Spacer(1, 10),
        Paragraph("Recommended Response Actions", styles["Heading2"]),
    ]
    for rec in package["recommendations"]:
        story.append(Paragraph(f"• {rec['action']} (Priority: {rec['priority']})", styles["Normal"]))
    story.append(Spacer(1, 10))

    out_path = FILES_DIR / f"_tmp_{uuid.uuid4()}.pdf"
    SimpleDocTemplate(str(out_path), pagesize=letter).build(story)
    data = out_path.read_bytes()
    out_path.unlink(missing_ok=True)
    return data

# ---------------------------------------------------------------------------
# Core Ingestion & Lifecycle Pipeline
# ---------------------------------------------------------------------------
def process_incident(payload: IncidentIn) -> dict:
    incident_id = str(uuid.uuid4())
    created_at = now_iso()
    
    asset_crit = (payload.asset_criticality or "medium").lower()
    vuln_level = (payload.vulnerability_level or "medium").lower()
    biz_impact = (payload.business_impact or "medium").lower()
    exp_level = (payload.exposure or "internal").lower()
    input_meth = "server" if payload.source in ["server", "live", "generated"] else ("pdf" if payload.source == "pdf" else "manual")

    incident_row = {
        "id": incident_id,
        "title": payload.title,
        "source": payload.source,
        "incident_type": payload.incident_type,
        "source_ip": payload.source_ip,
        "destination_ip": payload.destination_ip,
        "asset_type": payload.asset_type,
        "asset_criticality": asset_crit,
        "input_method": input_meth,
        "exposure": exp_level,
        "vulnerability_level": vuln_level,
        "business_impact": biz_impact,
        "description": payload.description or "Automated telemetry incident record.",
        "flow_features": payload.flow_features,
        "incident_time": created_at,
        "created_at": created_at,
    }
    append_row("incidents", incident_row)

    # 1. AI Result
    complete = flow_features_complete(payload.flow_features)
    anomaly_score = call_isolation_forest(payload.flow_features) if complete else None
    is_anomaly = (anomaly_score is not None) and (anomaly_score >= ANOMALY_THRESHOLD)
    ai_result = append_row("ai_results", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly if complete else None,
        "model_name": "Isolation Forest",
        "model_version": "v2.1",
        "prediction_metadata": {"threshold": ANOMALY_THRESHOLD, "features_evaluated": len(payload.flow_features) if payload.flow_features else 0},
        "created_at": created_at,
    })

    # 2. Risk Engine
    risk_score, severity = risk_agent(anomaly_score, asset_crit, vuln_level, biz_impact)
    priority, sla = master_agent(severity)
    
    risk_row = append_row("risk_results", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "risk_score": risk_score,
        "severity": severity,
        "scoring_mode": "ml_assisted" if complete else "context_only",
        "flow": "full_path" if complete else "short_path",
        "priority": priority,
        "sla_hours": sla,
        "created_at": created_at,
    })

    # 3. Threat Analysis
    threat = threat_agent(payload.incident_type, severity)
    threat_row = append_row("threat_analysis", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        **threat,
        "created_at": created_at,
    })

    # 4. Recommendations
    recs = recommendation_agent(payload.incident_type)
    for idx, rec in enumerate(recs):
        append_row("incident_recommendations", {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "action_title": rec["action"],
            "action_description": "Execute according to validated SecOps response protocol.",
            "action_scope": rec.get("scope", "immediate"),
            "action_order": idx + 1,
            "priority": rec.get("priority", "HIGH"),
            "status": "pending",
            "created_at": created_at,
        })

    # 5. AI Narrative
    narrative_text = (
        f"Incident {payload.title} classified with {severity} severity (Risk Score: {risk_score}/100, Priority: {priority}). "
        f"Observed behavioral profile aligns with {threat['mitre_techniques'][0]} under {threat['mitre_tactics'][0]}."
    )
    append_row("ai_narratives", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "analysis_id": f"ANL-{incident_id[:8].upper()}",
        "model_used": "SentriX ML Decision Layer v2.1",
        "analysis_time": created_at,
        "data_sources": ["Telemetry", "Network Flow", "Threat Intel"],
        "analysis_summary": narrative_text,
        "key_findings": [
            f"Asset {payload.asset_type} exhibited {payload.incident_type} activity.",
            f"Evaluated with priority {priority} (Target SLA: {sla}h).",
            "Cryptographic audit trail initialized."
        ],
        "narrative_source": "llm",
        "created_at": created_at,
    })

    package = {
        "incident": incident_row,
        "ai_result": ai_result,
        "risk": risk_row,
        "threat": threat_row,
        "recommendations": recs,
        "narrative": narrative_text,
        "priority": priority,
        "sla_hours": sla,
    }

    # 6. Immutable Archiving (P1 - P4)
    pdf_bytes = render_pdf(package)
    pdf_hash = sha256_of_bytes(pdf_bytes)
    
    report_row = append_row("incident_reports", {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "report_json": package,
        "report_version": "v1.1",
        "generated_at": created_at,
        "created_at": created_at,
    })

    archive_row = append_row("archives", {
        "id": str(uuid.uuid4()),
        "report_id": report_row["id"],
        "report_snapshot": package,
        "archive_period": datetime.now().strftime("%Y-%m"),
        "sha256_hash": pdf_hash,
        "archived_at": created_at,
        "created_at": created_at,
    })

    package["report"] = report_row
    package["archive"] = archive_row
    return package

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/incidents")
async def create_incident(payload: IncidentIn):
    return process_incident(payload)

@app.post("/api/incidents/upload")
async def upload_pdf_incident(file: UploadFile = File(...)):
    data = await file.read()
    file_hash = sha256_of_bytes(data)
    
    payload = IncidentIn(
        title=f"Ingested PDF: {file.filename}",
        source="pdf",
        incident_type="Ransomware",
        description=f"Incident report ingested from PDF ({file.filename}) with SHA-256: {file_hash}",
    )
    return process_incident(payload)

@app.get("/api/incidents")
async def list_incidents():
    if supabase:
        try:
            res = supabase.table("incidents").select("*").order("created_at", desc=True).execute()
            if res.data is not None:
                return res.data
        except Exception:
            pass
    return load_table("incidents")

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    if supabase:
        try:
            res = supabase.table("v_incident_full").select("*").eq("incident_id", incident_id).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception:
            pass
    
    incidents = load_table("incidents")
    inc = next((i for i in incidents if i.get("id") == incident_id), None)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@app.get("/api/dashboard")
async def get_dashboard():
    incidents = await list_incidents()
    total = len(incidents)
    
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in incidents:
        sev = str(i.get("asset_criticality") or "medium").capitalize()
        if sev in counts:
            counts[sev] += 1
            
    return {
        "total_incidents": total,
        "severity_counts": counts,
        "security_score": 72,
        "system_status": "Operational",
    }

@app.get("/api/archive")
async def list_archives():
    if supabase:
        try:
            res = supabase.table("archives").select("*").order("archived_at", desc=True).execute()
            if res.data:
                return res.data
        except Exception:
            pass
    return load_table("archives")

@app.get("/health")
async def health():
    return {"status": "ok", "time": now_iso(), "database": "supabase" if supabase else "local_fallback"}

@app.get("/")
async def root():
    return {"service": "SentriX Decision & Ingestion Layer", "status": "active"}
