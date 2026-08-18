"""
SentriX Backend API & Real-Time AI Decision Engine (v10.0 - Full Original Format)
---------------------------------------------------------------------------
DataRobot Prediction + Modular AI Services + Supabase + PDF Archiving.
+ Injected Fixes: Smart Simulator, Dynamic CRSI, Trends, SOAR, Archive POST.
+ NEW: Centralized Default-Deny Authentication Guard & Admin Clear.
"""

import asyncio
import base64
import hashlib
import hmac
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

# إعدادات Twilio Email API الجديدة
TWILIO_FROM_EMAIL = os.environ.get("TWILIO_FROM_EMAIL")
ALERT_EMAILS = [e.strip() for e in os.environ.get("ALERT_EMAILS", "ruba35uj@gmail.com").split(",") if e.strip()]
ARCHIVE_STORAGE_BUCKET = os.environ.get("ARCHIVE_STORAGE_BUCKET", "archives")
ARCHIVE_STORAGE_BUCKET = os.environ.get("ARCHIVE_STORAGE_BUCKET", "archives")

SIM_ENABLED = os.environ.get("SIM_ENABLED", "true").lower() == "true"
TREND_WINDOW_HOURS = float(os.environ.get("TREND_WINDOW_HOURS", "1"))
SIM_INTERVAL = int(os.environ.get("SIM_INTERVAL_SECONDS", "15"))   # 4 حوادث في الدقيقة
# 0 = بلا سقف: التوليد مستمر ما دامت الخدمة تعمل
SIM_MAX_INCIDENTS = int(os.environ.get("SIM_MAX_INCIDENTS", "0"))
MAX_PACKAGES = int(os.environ.get("MAX_PACKAGES", "100000"))
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",")]

# Render يضبط RENDER_EXTERNAL_URL تلقائياً؛ يمكن تجاوزه يدوياً بـ KEEP_ALIVE_URL
KEEP_ALIVE_URL = os.environ.get("KEEP_ALIVE_URL") or os.environ.get("RENDER_EXTERNAL_URL")
KEEP_ALIVE_INTERVAL = int(os.environ.get("KEEP_ALIVE_INTERVAL_SECONDS", "600"))

BASE_DIR = Path(__file__).parent
FILES_DIR = BASE_DIR / "storage" / "files"
DB_DIR = BASE_DIR / "storage" / "db"
FILES_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SentriX AI Engine", version="10.1.0")
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
    "/health",
    "/docs",
    "/openapi.json"
]

AUTH_SECRET = os.environ.get("AUTH_SECRET", "sentrix-local-secret-change-me")
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "12"))

DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "A123sentrix*")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "A123sentrix*")

BUILTIN_ACCOUNTS = {
    "analyst@sentrix.com": {"password": DEMO_PASSWORD, "role": "analyst",
                            "name": "SOC Analyst", "active": True},
    "admin@sentrix.com":    {"password": ADMIN_PASSWORD, "role": "admin",
                            "name": "SentriX Admin", "active": True},
    "pending@sentrix.com": {"password": DEMO_PASSWORD, "role": "analyst",
                            "name": "Pending Analyst", "active": False},
    # حساب مفتوح للتجربة — للمشرفين وأي شخص يريد استعراض المنصة
    "test@sentrix.org.sa": {"password": os.environ.get("TEST_PASSWORD", "Test*123"),
                            "role": "analyst", "name": "Test User", "active": True},
}


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(email: str, role: str | None = None) -> str:
    payload = json.dumps(
        {"email": email, "role": role, "exp": int(datetime.now(timezone.utc).timestamp()) + TOKEN_TTL_HOURS * 3600},
        separators=(",", ":"),
    ).encode()
    body = _b64e(payload)
    sig = _b64e(hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"stx.{body}.{sig}"


def verify_local_token(token: str) -> dict | None:
    try:
        prefix, body, sig = token.split(".")
        if prefix != "stx":
            return None
        expected = _b64e(hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64d(body))
        if data.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return data
    except Exception:
        return None


@app.middleware("http")
async def centralized_auth_guard(request: Request, call_next):
    path = request.url.path

    if any(path.startswith(p) for p in PUBLIC_PATHS) or not path.startswith("/api/"):
        return await call_next(request)

    if request.method == "OPTIONS":
        return await call_next(request)

    auth_header = request.headers.get("Authorization")

    if not auth_header and path.endswith("/download"):
        query_token = request.query_params.get("token")
        if query_token:
            return await _authorize(request, call_next, query_token.strip())

    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized: Missing or invalid token."})

    token = auth_header.split(" ", 1)[1].strip()

    return await _authorize(request, call_next, token)


async def _authorize(request, call_next, token: str):
    local_user = verify_local_token(token)
    if local_user:
        request.state.auth_user = local_user
        return await call_next(request)

    try:
        if supabase:
            user = supabase.auth.get_user(jwt=token)
            if user:
                supa_user = getattr(user, "user", user)
                email = str(getattr(supa_user, "email", "") or "").strip().lower()
                role = None
                if email:
                    try:
                        role_res = supabase.table("users").select("role").eq("email", email).limit(1).execute()
                        role_row = (role_res.data or [None])[0]
                        role = role_row.get("role") if role_row else None
                    except Exception:
                        role = None
                request.state.auth_user = {"email": email, "role": role, "auth_source": "supabase_auth"}
                return await call_next(request)
    except Exception:
        pass

    return JSONResponse(status_code=401, content={"detail": "Unauthorized: Session expired or invalid."})

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

CRSI_DOMAINS = {
    "identify_access":  {"name": "Identify & Access", "weight": 0.18, "ref": "NIST PR.AC | ISO 27001 A.9 | NCA 2-2"},
    "network_security": {"name": "Network Security",  "weight": 0.17, "ref": "NIST PR.PT | ISO 27001 A.13 | NCA 2-5"},
    "endpoint_security":{"name": "Endpoint Security", "weight": 0.17, "ref": "NIST DE.CM | ISO 27001 A.12 | NCA 2-3"},
    "detect_respond":   {"name": "Detect & Respond",  "weight": 0.18, "ref": "NIST DE.AE | ISO 27001 A.16 | NCA 2-13"},
    "backup_recovery":  {"name": "Backup & Recovery", "weight": 0.15, "ref": "NIST RC.RP | ISO 27001 A.12.3 | NCA 2-9"},
    "nca_controls":     {"name": "NCA Controls",       "weight": 0.15, "ref": "NCA ECC-1:2018"},
}
# توصيات مرجعية لكل مجال، مربوطة بالضوابط المعتمدة.
# التوصية السابقة كانت سطراً عاماً واحداً ("Review X controls") بلا معايير.
CRSI_PLAYBOOK = {
    "identify_access": {
        "playbook": "IDENTITY_AND_ACCESS_HARDENING_PLAN",
        "actions": [
            ("Enforce multi-factor authentication on all privileged accounts",
             "MFA is the single highest-impact control against credential attacks. Apply it to every administrative and remote-access account.",
             "NCA ECC-1:2018 2-2-3 | ISO/IEC 27001 A.9.4.2 | NIST CSF PR.AC-7"),
            ("Run a quarterly access review and revoke stale privileges",
             "Review every account against the least-privilege principle and remove permissions no longer required by the job role.",
             "NCA ECC-1:2018 2-2-1 | ISO/IEC 27001 A.9.2.5 | NIST CSF PR.AC-4"),
            ("Separate administrative accounts from daily-use accounts",
             "Administrators must hold a distinct privileged identity that is never used for email or browsing.",
             "NCA ECC-1:2018 2-2-2 | ISO/IEC 27001 A.9.2.3 | NIST CSF PR.AC-6"),
            ("Enable lockout and alerting on repeated authentication failures",
             "Lock the account after a defined number of failures and raise an alert to the SOC.",
             "ISO/IEC 27001 A.9.4.2 | NIST CSF DE.CM-1"),
        ],
    },
    "network_security": {
        "playbook": "NETWORK_SEGMENTATION_AND_PERIMETER_PLAN",
        "actions": [
            ("Segment critical assets away from general user traffic",
             "Place servers and databases in dedicated segments with explicit allow rules between zones.",
             "NCA ECC-1:2018 2-5-3 | ISO/IEC 27001 A.13.1.3 | NIST CSF PR.AC-5"),
            ("Review and clean the firewall rule base",
             "Remove permissive any-any rules and obsolete entries, and document the business owner of every remaining rule.",
             "NCA ECC-1:2018 2-5-1 | ISO/IEC 27001 A.13.1.1 | NIST CSF PR.PT-4"),
            ("Restrict and monitor internet-facing services",
             "Publish only what must be public, put the rest behind VPN, and log every inbound session.",
             "NCA ECC-1:2018 2-5-2 | ISO/IEC 27001 A.13.1.2 | NIST CSF DE.CM-1"),
            ("Enable DDoS protection on public endpoints",
             "Apply rate limiting and upstream scrubbing for services exposed to the internet.",
             "NCA ECC-1:2018 2-5-4 | NIST CSF PR.PT-5"),
        ],
    },
    "endpoint_security": {
        "playbook": "ENDPOINT_PROTECTION_HARDENING_PLAN",
        "actions": [
            ("Verify EDR agent coverage across every managed endpoint",
             "Identify endpoints without a reporting agent — an unmonitored endpoint is an invisible entry point.",
             "NCA ECC-1:2018 2-3-1 | ISO/IEC 27001 A.12.6.2 | NIST CSF DE.CM-4"),
            ("Apply a hardened baseline configuration to all endpoints",
             "Disable unused services and enforce the approved security baseline through group policy.",
             "NCA ECC-1:2018 2-3-2 | ISO/IEC 27001 A.12.5.1 | NIST CSF PR.IP-1"),
            ("Enforce application allow-listing on critical systems",
             "Permit only approved executables to run on servers handling sensitive data.",
             "NCA ECC-1:2018 2-3-3 | ISO/IEC 27001 A.12.6.2 | NIST CSF PR.PT-3"),
            ("Close the endpoint patching gap within the defined SLA",
             "Track time-to-patch per severity and escalate anything exceeding the agreed window.",
             "NCA ECC-1:2018 2-10-2 | ISO/IEC 27001 A.12.6.1 | NIST CSF ID.RA-1"),
        ],
    },
    "detect_respond": {
        "playbook": "DETECTION_AND_RESPONSE_IMPROVEMENT_PLAN",
        "actions": [
            ("Close detection coverage gaps in the SIEM",
             "Map current log sources against the MITRE ATT&CK techniques seen in recent incidents and onboard what is missing.",
             "NCA ECC-1:2018 2-12-1 | ISO/IEC 27001 A.12.4.1 | NIST CSF DE.AE-3"),
            ("Reduce mean time to detect and mean time to respond",
             "Measure both metrics per incident and set an improvement target for the next quarter.",
             "NCA ECC-1:2018 2-13-2 | ISO/IEC 27001 A.16.1.5 | NIST CSF RS.AN-1"),
            ("Document and test response runbooks for the top incident types",
             "Every recurring incident type needs an approved, rehearsed runbook rather than ad-hoc handling.",
             "NCA ECC-1:2018 2-13-1 | ISO/IEC 27001 A.16.1.1 | NIST CSF RS.RP-1"),
            ("Retain security logs for the mandated retention period",
             "Logs must remain available and tamper-evident for the period required by regulation.",
             "NCA ECC-1:2018 2-12-3 | ISO/IEC 27001 A.12.4.2 | NIST CSF PR.PT-1"),
        ],
    },
    "backup_recovery": {
        "playbook": "BACKUP_AND_RECOVERY_ASSURANCE_PLAN",
        "actions": [
            ("Keep at least one backup copy offline and immutable",
             "Ransomware targets connected backups first; an isolated copy is what makes recovery possible.",
             "NCA ECC-1:2018 2-9-3 | ISO/IEC 27001 A.12.3.1 | NIST CSF PR.IP-4"),
            ("Perform a documented restore test for critical systems",
             "An untested backup is an assumption. Test the restore and record the recovery time achieved.",
             "NCA ECC-1:2018 2-9-2 | ISO/IEC 27001 A.17.1.3 | NIST CSF RC.RP-1"),
            ("Define and approve RTO and RPO for every critical service",
             "Recovery objectives must be agreed with the business owner, not assumed by IT.",
             "NCA ECC-1:2018 2-9-1 | ISO/IEC 27001 A.17.1.1 | NIST CSF RC.CO-3"),
            ("Encrypt backup media at rest and in transit",
             "Backups carry the same data classification as production and need the same protection.",
             "ISO/IEC 27001 A.10.1.1 | NIST CSF PR.DS-1"),
        ],
    },
    "nca_controls": {
        "playbook": "NCA_ECC_COMPLIANCE_PLAN",
        "actions": [
            ("Run a gap assessment against the NCA Essential Cybersecurity Controls",
             "Assess all ECC domains, record the compliance level of each control, and assign an owner to every gap.",
             "NCA ECC-1:2018 1-1-1 | ISO/IEC 27001 A.18.2.2 | NIST CSF ID.GV-3"),
            ("Deliver role-based security awareness training",
             "Target the departments most exposed to phishing and social engineering, and measure the result.",
             "NCA ECC-1:2018 1-6-1 | ISO/IEC 27001 A.7.2.2 | NIST CSF PR.AT-1"),
            ("Approve and publish the cybersecurity policy set",
             "Policies must be formally approved by senior management and communicated to all staff.",
             "NCA ECC-1:2018 1-3-1 | ISO/IEC 27001 A.5.1.1 | NIST CSF ID.GV-1"),
            ("Include cybersecurity requirements in third-party contracts",
             "Suppliers with access to systems or data must be bound by the same control expectations.",
             "NCA ECC-1:2018 4-1-2 | ISO/IEC 27001 A.15.1.2 | NIST CSF ID.SC-3"),
        ],
    },
}

CRSI_PENALTY = {"Critical": 12.0, "High": 7.0, "Medium": 3.0, "Low": 0.0}
CRSI_SPILLOVER = 0.20
CRSI_WINDOW = 20

THREAT_TYPE_ALIASES = {
    "brute_force": "Brute-force",
    "ddos": "DDoS",
    "dos": "DoS",
    "botnet": "Botnet",
    "heartbleed": "Heartbleed",
    "web_attack": "Web Attacks",
    "insider_threat": "Infiltration",
    "data_exfiltration": "Infiltration",
    "malware": "Botnet",
    "ransomware": "Infiltration",
    "phishing": "Web Attacks",
}

MITRE_MAP = {
    "ransomware":      {"domains": ["endpoint_security", "backup_recovery", "detect_respond"],
                        "tactics": ["Impact", "Defense Evasion"],
                        "techniques": ["T1486", "T1490", "T1070"]},
    "brute_force":     {"domains": ["identify_access", "detect_respond"],
                        "tactics": ["Credential Access", "Initial Access"],
                        "techniques": ["T1110", "T1078"]},
    "ddos":            {"domains": ["network_security", "detect_respond"],
                        "tactics": ["Impact"],
                        "techniques": ["T1498", "T1499"]},
    "phishing":        {"domains": ["identify_access", "nca_controls"],
                        "tactics": ["Initial Access", "Credential Access"],
                        "techniques": ["T1566", "T1204"]},
    "malware":         {"domains": ["endpoint_security", "detect_respond"],
                        "tactics": ["Execution", "Persistence"],
                        "techniques": ["T1204", "T1547", "T1059"]},
    "insider_threat": {"domains": ["identify_access", "nca_controls"],
                        "tactics": ["Exfiltration", "Collection"],
                        "techniques": ["T1041", "T1005"]},
    "benign":          {"domains": [], "tactics": [], "techniques": []},
    "_default":        {"domains": ["detect_respond"],
                        "tactics": ["Execution"], "techniques": ["T1059"]},
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

PKG_FILE = DB_DIR / "packages.json"
CRSI_FILE = DB_DIR / "crsi_archives.json"

def _read_mirror() -> list:
    if PKG_FILE.exists():
        try: return json.loads(PKG_FILE.read_text(encoding="utf-8"))
        except Exception: return []
    return []

def _write_mirror(rows: list) -> None:
    PKG_FILE.write_text(json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

PACKAGES: list = _read_mirror()

def _read_crsi_archives() -> list:
    if CRSI_FILE.exists():
        try: return json.loads(CRSI_FILE.read_text(encoding="utf-8"))
        except Exception: return []
    return []

def _write_crsi_archives(rows: list) -> None:
    CRSI_FILE.write_text(json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

CRSI_ARCHIVES: list = _read_crsi_archives()

SUPABASE_ERRORS: list = []
LAST_TWILIO: dict = {"sent": None, "reason": "no critical incident yet"}
LAST_EMAIL: dict = {"sent": None, "reason": "no critical incident yet"}

def sb_insert(table: str, row: dict) -> bool:
    if not supabase:
        SUPABASE_ERRORS.append({"table": table, "error": "supabase client not configured", "at": now_iso()})
        del SUPABASE_ERRORS[:-20]
        return False
    try:
        supabase.table(table).insert(row).execute()
        return True
    except Exception as e:
        msg = str(e)[:400]
        print(f"[supabase] insert {table} failed: {msg}")
        SUPABASE_ERRORS.append({"table": table, "error": msg, "at": now_iso()})
        del SUPABASE_ERRORS[:-20]
        return False

def hydrate_from_supabase() -> None:
    global PACKAGES
    if not supabase or PACKAGES: return
    try:
        res = supabase.table("incident_reports").select("report_json").order("created_at", desc=True).limit(100000).execute()
        rows = [r["report_json"] for r in (res.data or []) if r.get("report_json")]
        if rows:
            PACKAGES = rows
            _write_mirror(PACKAGES)
    except Exception as e: print(f"[supabase] hydrate failed: {e}")

def next_incident_ref() -> str:
    highest = 0
    for pkg in PACKAGES:
        match = re.match(r"^INC-(\d+)$", str((pkg.get("incident") or {}).get("id") or ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"INC-{highest + 1:04d}"

def find_package(incident_id: str):
    wanted = str(incident_id or "").strip().upper()
    if not wanted:
        return None
    for pkg in PACKAGES:
        inc = pkg.get("incident") or {}
        candidates = {
            str(inc.get("id") or "").upper(),
            str(inc.get("uuid") or "").upper(),
            str((pkg.get("report") or {}).get("report_id") or "").upper(),
        }
        if wanted in candidates:
            return pkg
    if wanted.isdigit():
        padded = f"INC-{int(wanted):04d}"
        for pkg in PACKAGES:
            if str((pkg.get("incident") or {}).get("id") or "").upper() == padded:
                return pkg
    return None

KSA_TZ = timezone(timedelta(hours=3))

def now_iso() -> str: return datetime.now(KSA_TZ).isoformat()
def sha256_of(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def canonical_json(obj) -> bytes: return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")


def build_archive_snapshot(package: dict) -> dict:
    return {k: v for k, v in package.items() if k not in ("archive", "notification", "persistence", "email_notification")}


def upload_pdf_to_supabase(pdf_bytes: bytes, incident_id: str) -> dict:
    if not supabase:
        return {"uploaded": False, "reason": "supabase client not configured", "storage_path": None}
    storage_path = f"incident-reports/{incident_id}.pdf"
    try:
        bucket = supabase.storage.from_(ARCHIVE_STORAGE_BUCKET)
        try:
            bucket.upload(storage_path, pdf_bytes, {"content-type": "application/pdf", "upsert": "false"})
        except Exception:
            # Some supabase-py versions expect boolean upsert metadata.
            bucket.upload(storage_path, pdf_bytes, {"content-type": "application/pdf", "upsert": False})
        return {"uploaded": True, "storage_path": storage_path, "bucket": ARCHIVE_STORAGE_BUCKET}
    except Exception as e:
        msg = str(e)[:400]
        SUPABASE_ERRORS.append({"table": "storage", "error": msg, "at": now_iso()})
        del SUPABASE_ERRORS[:-20]
        return {"uploaded": False, "reason": msg, "storage_path": None}

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
    source_file_name: str | None = None
    flow_features: dict | None = None

_FEATURE_LOOKUP = {"".join(k.lower().split()): k for k in FEATURE_KEYS}

TRAFFIC_PROFILES: dict = {}
try:
    _profiles_path = BASE_DIR / "traffic_profiles.json"
    if _profiles_path.exists():
        _loaded = json.loads(_profiles_path.read_text(encoding="utf-8"))
        TRAFFIC_PROFILES = {k: v for k, v in _loaded.items() if not k.startswith("_")}
except Exception as _e:
    pass

def _match_feature(cell) -> str | None:
    if cell is None:
        return None
    return _FEATURE_LOOKUP.get("".join(str(cell).lower().split()))

def _to_number(cell) -> float | None:
    if cell is None:
        return None
    cleaned = str(cell).replace(",", "").replace("%", "").strip()
    cleaned = re.sub(r"[^0-9eE\.\+\-]", "", cleaned)
    if cleaned in ("", "-", "+", ".", "e", "E"):
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None

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

    try:
        risk_result = calculate_risk(
            anomaly_score=ai_data["anomaly_score"], asset_criticality=payload.asset_criticality,
            exposure=payload.exposure, vulnerability_level=payload.vulnerability_level, business_impact=payload.business_impact,
        )
    except ValueError as e:
        risk_result = calculate_risk(
            anomaly_score=ai_data["anomaly_score"], asset_criticality="medium",
            exposure="internal", vulnerability_level="medium", business_impact="medium",
        )
    severity_raw = str(risk_result.get("severity", "LOW")).upper()
    flow = "short_path" if severity_raw == "LOW" else "full_path"
    risk = {
        "risk_score": risk_result.get("risk_score"), "severity": severity_raw.capitalize(),
        "priority": risk_result.get("priority", "P3"), "sla_hours": risk_result.get("sla_hours", 24),
        "is_deviating": ai_data["is_anomaly"], "dynamic_threshold": ai_data["dynamic_threshold"],
        "scoring_mode": risk_result.get("scoring_mode", "context_only"), "weights_used": risk_result.get("weights_used", {}),
        "risk_factors": risk_result.get("risk_factors", {}), "flow": flow
    }

    threat_result = analyze_threat(THREAT_TYPE_ALIASES.get(itype, itype))
    mitre_ref = MITRE_MAP.get(itype, MITRE_MAP["_default"])
    tactics = [t.get("name") if isinstance(t, dict) else t for t in threat_result.get("mitre_tactics", [])]
    techniques = [t.get("id") if isinstance(t, dict) else t for t in threat_result.get("mitre_techniques", [])]
    if not tactics:
        tactics = mitre_ref.get("tactics", [])
    if not techniques:
        techniques = mitre_ref.get("techniques", [])

    threat = {
        "matched_profile": threat_result.get("matched_profile", itype), "is_unmapped": threat_result.get("is_unmapped", False),
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "cia_impact": {
            "confidentiality": str(threat_result.get("confidentiality_impact", "Medium")).capitalize(),
            "integrity": str(threat_result.get("integrity_impact", "Medium")).capitalize(),
            "availability": str(threat_result.get("availability_impact", "Medium")).capitalize()
        },
        "failed_domains": mitre_ref["domains"]
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
        "asset_type": payload.asset_type, "asset_criticality": payload.asset_criticality, "exposure": payload.exposure, "vulnerability_level": payload.vulnerability_level, "source_file_name": payload.source_file_name,
        "business_impact": payload.business_impact, "created_at": created_at, "status": "Analyzed", "severity": risk["severity"], "risk_score": risk["risk_score"]
    }

    package = {"incident": incident_row, "ai_result": ai_data, "risk": risk, "threat": threat, "recommendation": rec, "key_findings": findings}
    package["crsi"] = compute_crsi(PACKAGES + [package])
    package["report"] = {"report_id": f"RPT-{ref.replace('INC-', '')}", "generated_at": created_at, "report_version": "10.1"}

    pdf_bytes = render_pdf(package)
    (FILES_DIR / f"{ref}.pdf").write_bytes(pdf_bytes)

    snapshot = build_archive_snapshot(package)
    storage_result = upload_pdf_to_supabase(pdf_bytes, ref)
    package["archive"] = {
        "archive_id": str(uuid.uuid4()), "report_id": package["report"]["report_id"], "incident_id": ref, "title": f"Incident Report - {ref}", "type": "Incident Report",
        "archived_at": created_at.replace("T", " ")[:16], "sha256": sha256_of(canonical_json(snapshot)), "pdf_sha256": sha256_of(pdf_bytes), "archived_by": "SentriX Engine",
        "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(), "storage_type": "WORM (Immutable)", "pdf_path": f"/api/archive/{ref}/download",
        "storage_path": storage_result.get("storage_path"), "storage_bucket": storage_result.get("bucket"),
    }

    PACKAGES.insert(0, package)
    # تم إيقاف سطر القص لكي لا يتوقف أبداً ويستمر لشهور طويلة
    # del PACKAGES[MAX_PACKAGES:]
    _write_mirror(PACKAGES)
    package["persistence"] = persist_to_supabase(package, incident_uuid, pdf_bytes)
    package["notification"] = notify_twilio(ref, risk["severity"], itype, risk["risk_score"])
    
    # استدعاء دالة إرسال الإيميل عبر Twilio API الجديد
    package["email_notification"] = notify_email(package)
    
    return package

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

def persist_to_supabase(pkg: dict, incident_uuid: str, pdf_bytes: bytes) -> dict:
    if not supabase:
        return {"stored": False, "reason": "supabase client not configured"}
    inc, risk, threat = pkg["incident"], pkg["risk"], pkg["threat"]
    sev_db = risk["severity"].upper()
    status = {}
    status["incidents"] = sb_insert("incidents", {"id": incident_uuid, "title": inc["title"], "source": inc["source"], "incident_type": inc["incident_type"], "source_ip": inc["source_ip"], "destination_ip": inc["destination_ip"], "description": inc["description"], "asset_type": inc["asset_type"], "asset_criticality": inc["asset_criticality"], "input_method": inc["input_method"], "exposure": inc["exposure"], "vulnerability_level": inc["vulnerability_level"], "business_impact": inc["business_impact"], "created_at": inc["created_at"],
        "source_file_name": inc.get("source_file_name"), "incident_time": inc["created_at"]})
    status["ai_results"] = sb_insert("ai_results", {"id": str(uuid.uuid4()), "incident_id": incident_uuid, "anomaly_score": pkg["ai_result"]["anomaly_score"], "is_anomaly": pkg["ai_result"]["is_anomaly"], "model_name": pkg["ai_result"]["model_name"], "model_version": "v1.0", "prediction_metadata": {"threshold": pkg["ai_result"]["dynamic_threshold"], "scoring_mode": risk["scoring_mode"]}})
    status["risk_results"] = sb_insert("risk_results", {"id": str(uuid.uuid4()), "incident_id": incident_uuid, "risk_score": risk["risk_score"], "severity": sev_db, "risk_factors": risk["risk_factors"], "scoring_mode": risk["scoring_mode"], "flow": risk["flow"], "priority": risk["priority"], "sla_hours": risk["sla_hours"], "weights_used": risk["weights_used"], "dynamic_threshold": risk["dynamic_threshold"]})
    status["threat_analysis"] = sb_insert("threat_analysis", {
        "id": str(uuid.uuid4()), "incident_id": incident_uuid,
        "threat_type": inc["incident_type"], "matched_profile": threat.get("matched_profile"),
        "is_unmapped": threat.get("is_unmapped", False),
        "mitre_tactics": threat.get("mitre_tactics", []), "mitre_techniques": threat.get("mitre_techniques", []),
        "confidentiality_impact": str(threat["cia_impact"].get("confidentiality", "")).lower() or None,
        "integrity_impact": str(threat["cia_impact"].get("integrity", "")).lower() or None,
        "availability_impact": str(threat["cia_impact"].get("availability", "")).lower() or None,
        "intel_version": "1.0",
    })
    report_uuid = str(uuid.uuid4())
    status["incident_reports"] = sb_insert("incident_reports", {"id": report_uuid, "incident_id": incident_uuid, "report_json": pkg, "pdf_path": pkg["archive"]["pdf_path"], "report_version": "10.1"})
    status["archives"] = sb_insert("archives", {"id": pkg["archive"]["archive_id"], "report_id": report_uuid, "report_snapshot": pkg, "pdf_path": pkg["archive"]["pdf_path"], "archive_period": datetime.now(timezone.utc).strftime("%Y-%m"), "sha256_hash": pkg["archive"]["sha256"]})
    return {"stored": all(status.values()), "tables": status}

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
    W = TREND_WINDOW_HOURS

    def in_window(p, start_h, end_h):
        try:
            ts = datetime.fromisoformat(str(p["incident"]["created_at"]).replace("Z", "+00:00"))
            age = (now - ts).total_seconds() / 3600
            return start_h <= age < end_h
        except Exception:
            return False

    cur = [p for p in PACKAGES if in_window(p, 0, W)]
    prev = [p for p in PACKAGES if in_window(p, W, 2 * W)]

    def pct(a, b, higher_is_good=False):
        ca, cb = len(a), len(b)
        if cb == 0:
            change = "100%" if ca > 0 else "0%"
            rising = ca > 0
        else:
            delta = (ca - cb) / cb * 100
            change = f"{abs(round(delta))}%"
            rising = delta >= 0
        return {
            "change": change,
            "direction": "up" if rising else "down",
            "positive": rising if higher_is_good else not rising,
            "current": ca,
            "previous": cb,
        }

    def only_critical(rows):
        return [p for p in rows if p["risk"]["severity"] == "Critical"]

    def only_analyzed(rows):
        return [p for p in rows if p["ai_result"]["anomaly_score"] is not None]

    def only_pending(rows):
        return [p for p in rows if p["ai_result"]["anomaly_score"] is None]

    return {
        "attackTypes": attack_types or [{"name": "No data", "value": 0}],
        "totals": {"total": len(PACKAGES), "critical": sev["Critical"], "analyzed": analyzed, "pending": len(PACKAGES) - analyzed},
        "severityCounts": sev,
        "trends": {
            "total": pct(cur, prev, higher_is_good=False),
            "critical": pct(only_critical(cur), only_critical(prev), higher_is_good=False),
            "analyzed": pct(only_analyzed(cur), only_analyzed(prev), higher_is_good=True),
            "pending": pct(only_pending(cur), only_pending(prev), higher_is_good=False),
        },
        "trend_window_hours": W,
        "crsi": compute_crsi(PACKAGES),
    }

@app.get("/api/incidents")
async def list_incidents():
    rows = [{
        **p["incident"],
        "risk_score": p["risk"]["risk_score"], "severity": p["risk"]["severity"],
        "priority": p["risk"]["priority"], "scoring_mode": p["risk"]["scoring_mode"],
        "flow": p["risk"]["flow"], "hasAiResult": p["ai_result"]["anomaly_score"] is not None,
        "ai_score": p["ai_result"]["anomaly_score"], "playbook": p["recommendation"]["playbook"],
    } for p in PACKAGES]
    rows.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    return rows

@app.post("/api/incidents")
async def create_incident(payload: IncidentIn):
    return process_incident(payload)

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    p = find_package(incident_id)
    if not p: raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        **p["incident"], "risk_score": p["risk"]["risk_score"], "severity": p["risk"]["severity"], "priority": p["risk"]["priority"], "sla_hours": p["risk"]["sla_hours"],
        "scoring_mode": p["risk"]["scoring_mode"], "flow": p["risk"]["flow"], "risk_factors": p["risk"]["risk_factors"], "anomaly_score": p["ai_result"]["anomaly_score"],
        "model_used": p["ai_result"]["model_name"], "dynamic_threshold": p["ai_result"]["dynamic_threshold"], "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A", "cia_impact": p["threat"]["cia_impact"], "key_findings": p["key_findings"],
        "playbook": p["recommendation"]["playbook"], "recommended_actions": p["recommendation"]["actions"], "crsi": p["crsi"], "report": p["report"], "archive": p["archive"],
        "pdf_url": p["archive"]["pdf_path"], "hasAiResult": p["ai_result"]["anomaly_score"] is not None,
    }

@app.get("/api/ai-analysis/{incident_id}")
async def ai_analysis(incident_id: str):
    p = find_package(incident_id)
    if not p: raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        "incident_id": p["incident"]["id"], "incident_title": p["incident"]["title"], "severity": p["risk"]["severity"], "risk_score": p["risk"]["risk_score"],
        "risk_detected": p["risk"]["flow"] == "full_path", "analysis_id": f"AI-ANL-{p['incident']['id']}", "model_used": p["ai_result"]["model_name"],
        "analysis_time": p["report"]["generated_at"], "data_sources": f"{p['incident']['source']}, Threat Intel", "mitre_tactics": ", ".join(p["threat"]["mitre_tactics"]) or "N/A",
        "attack_technique": ", ".join(p["threat"]["mitre_techniques"]) or "N/A", "cia_impact": p["threat"]["cia_impact"], "key_findings": p["key_findings"],
        "anomaly_score": p["ai_result"]["anomaly_score"], "threat_type": p["incident"]["incident_type"]
    }

@app.get("/api/recommendations")
async def recommendations(incident_id: str | None = None):
    p = find_package(incident_id) or (PACKAGES[0] if PACKAGES else None)
    if not p: return {"playbook": "NO_INCIDENTS", "actions": [], "score": 0}
    return {"incident_id": p["incident"]["id"], "title": p["incident"]["title"], "severity": p["risk"]["severity"], "riskScore": p["risk"]["risk_score"], "playbook": p["recommendation"]["playbook"], "actions": p["recommendation"]["actions"]}

@app.get("/api/crsi-assessment")
async def crsi_assessment():
    """
    تقييم **يومي**: درجة كل يوم تُحسب من حوادث ذلك اليوم وحده.
    الحساب السابق كان تراكمياً (كل الحوادث حتى نهاية اليوم)، فتنزل الدرجة
    باستمرار ولا تعكس أداء اليوم نفسه.
    التقييم التراكمي للمؤسسة يبقى في صفحة التوصيات (/api/crsi-recommendations).
    """
    today = datetime.now(timezone.utc).date()

    def pkg_day(pkg):
        try:
            return datetime.fromisoformat(
                str(pkg["incident"]["created_at"]).replace("Z", "+00:00")
            ).date()
        except Exception:
            return None

    daily_history = []
    for i in range(5):
        day = today - timedelta(days=i)
        of_day = [p for p in PACKAGES if pkg_day(p) == day]
        day_crsi = compute_crsi(of_day)
        score = day_crsi["score"] if of_day else 100.0

        daily_history.append({
            "date": day.strftime("%b %d, %Y"),
            "score": score,
            "status": "Good" if score >= 70 else "Fair" if score >= 40 else "Poor",
            "maturity_level": day_crsi["maturity_level"] if of_day else "Strong",
            "incident_count": len(of_day),
            # تفصيل مجالات اليوم نفسه ليعرضه الفرونت عند اختيار اليوم
            "breakdown": day_crsi["breakdown"] if of_day else compute_crsi([])["breakdown"],
        })

    latest = daily_history[0]
    return {
        "scope": "daily",
        "score": latest["score"],
        "maturity_level": latest["maturity_level"],
        "breakdown": latest["breakdown"],
        "incident_count": latest["incident_count"],
        "dailyScores": daily_history,
        # للمقارنة فقط — الدرجة التراكمية المعروضة في صفحة التوصيات
        "organizational_score": compute_crsi(PACKAGES)["score"],
    }

@app.get("/api/crsi-recommendations")
async def crsi_recommendations():
    crsi = compute_crsi(PACKAGES)
    weak = [d["name"] for d in crsi["breakdown"] if d["is_weak"]]
    
    # التوصيات مشتقة من ضوابط NCA ECC و ISO/IEC 27001 و NIST CSF،
    # ومرتبة حسب أضعف المجالات فعلياً. عدد التوصيات يتبع درجة المجال.
    ordered = sorted(crsi["breakdown"], key=lambda d: d["score"])

    def depth(score):
        if score < 40:   return 4, "High"
        if score < 60:   return 3, "High"
        if score < 75:   return 2, "Medium"
        return 1, "Low"

    actions, idx = [], 1
    for domain in ordered:
        book = CRSI_PLAYBOOK.get(domain["domain_key"])
        if not book:
            continue
        count, priority = depth(domain["score"])
        if domain["score"] >= 85 and len(actions) >= 4:
            continue
        for title, description, reference in book["actions"][:count]:
            actions.append({
                "id": idx,
                "title": title,
                "description": description,
                "domain": domain["name"],
                "domain_score": domain["score"],
                "control_reference": reference,
                "frameworks": [part.strip() for part in reference.split("|")],
                "priority": priority,
                "status": "Pending",
            })
            idx += 1
        if len(actions) >= 12:
            break

    if not actions:
        actions.append({
            "id": 1,
            "title": "Maintain the current security posture",
            "description": "No weak control domains were identified in the current assessment window. "
                           "Keep the periodic review cycle and the awareness programme running.",
            "domain": "Organizational",
            "control_reference": "NCA ECC-1:2018 1-1-1 | ISO/IEC 27001 A.18.2.2 | NIST CSF ID.GV-3",
            "frameworks": ["NCA ECC-1:2018 1-1-1", "ISO/IEC 27001 A.18.2.2", "NIST CSF ID.GV-3"],
            "priority": "Low",
            "status": "Pending",
        })

    weak_domains = [d for d in crsi["breakdown"] if d["is_weak"]]
    if weak_domains:
        weakest = min(weak_domains, key=lambda x: x["score"])
        book = CRSI_PLAYBOOK.get(weakest["domain_key"])
        pb_name = book["playbook"] if book else "ORGANIZATIONAL_SECURITY_PLAN"
    else:
        pb_name = "ORGANIZATIONAL_SECURITY_PLAN"

    return {
        # هذه الصفحة تراكمية: كل حوادث نافذة التقييم، لا يوم واحد
        "scope": "organizational",
        "assessment_window": CRSI_WINDOW,
        "score": crsi["score"],
        "maturity_level": crsi["maturity_level"],
        "breakdown": crsi["breakdown"],
        "playbook": pb_name,
        "weak_domains": weak,
        "frameworks": ["NCA ECC-1:2018", "ISO/IEC 27001:2022", "NIST CSF 2.0"],
        "incident_count": crsi["incident_count"],
        "actions": actions,
    }

@app.get("/api/archive")
async def list_archive():
    rows = [
        {**p["archive"], "content": {"incidentTitle": p["incident"]["title"], "severity": p["risk"]["severity"], "riskScore": f"{p['risk']['risk_score']} / 100", "source": p["incident"]["source"], "asset": p["incident"]["asset_type"], "threatType": p["incident"]["incident_type"], "keyFindings": p["key_findings"], "playbook": p["recommendation"]["playbook"], "recommendedActions": [a["title"] for a in p["recommendation"]["actions"]], "inputMethod": p["incident"].get("input_method"), "sourceFile": p["incident"].get("source_file_name")}}
        for p in PACKAGES
    ]
    rows.extend(CRSI_ARCHIVES)
    rows.sort(key=lambda r: str(r.get("archived_at") or ""), reverse=True)
    return rows

@app.post("/api/archive/verify/{incident_id}")
async def verify_archive(incident_id: str):
    p = find_package(incident_id)
    if not p: raise HTTPException(404, f"Archive record for {incident_id} not found")
    snapshot = build_archive_snapshot(p)
    current = sha256_of(canonical_json(snapshot))
    stored = p["archive"]["sha256"]
    return {
        "incident_id": incident_id, "integrity_ok": current == stored,
        "stored_sha256": stored, "current_sha256": current,
        "archived_by": p["archive"].get("archived_by"), "archived_at": p["archive"].get("archived_at"),
        "retention_until": p["archive"].get("retention_until"),
        "verified_at": now_iso(), "storage_type": p["archive"].get("storage_type", "WORM (Immutable)"),
    }

@app.get("/api/archive/{incident_id}/download")
async def download_archive(incident_id: str):
    p = find_package(incident_id)
    if not p: raise HTTPException(404, f"Incident {incident_id} not found")
    path = FILES_DIR / f"{p['incident']['id']}.pdf"
    if not path.exists(): path.write_bytes(render_pdf(p))
    return Response(content=path.read_bytes(), media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{p["report"]["report_id"]}.pdf"'})

@app.post("/api/crsi-assessment/archive")
async def archive_crsi_report():
    crsi = compute_crsi(PACKAGES)
    stamp = datetime.now(timezone.utc)
    snapshot = {
        "crsi_score": crsi["score"],
        "maturity_level": crsi["maturity_level"],
        "incident_count": crsi["incident_count"],
        "assessment_window": crsi["assessment_window"],
        "breakdown": crsi["breakdown"],
        "generated_at": stamp.isoformat(),
    }

    archive_uuid = str(uuid.uuid4())
    row = {
        "archive_id": archive_uuid,
        "report_id": f"RPT-CRSI-{stamp.strftime('%Y%m%d-%H%M%S')}",
        "incident_id": None,
        "title": "CRSI Report - Organizational Assessment",
        "type": "CRSI Report",
        "archived_at": stamp.isoformat().replace("T", " ")[:16],
        "sha256": sha256_of(canonical_json(snapshot)),
        "archived_by": "SentriX CRSI Engine",
        "retention_until": (date.today() + timedelta(days=365 * 7)).isoformat(),
        "storage_type": "WORM (Immutable)",
        "archive_period": stamp.strftime("%Y-%m"),
        "isCrsi": True,
        "snapshot": snapshot,
        "content": {
            "overallScore": f"{crsi['score']} / 100",
            "maturityLevel": crsi["maturity_level"],
            "incidentCount": crsi["incident_count"],
            "breakdownList": crsi["breakdown"],
        },
    }

    CRSI_ARCHIVES.insert(0, row)
    _write_crsi_archives(CRSI_ARCHIVES[:100])

    sb_insert("archives", {
        "id": archive_uuid,
        "report_snapshot": snapshot,
        "archive_period": row["archive_period"],
        "sha256_hash": row["sha256"],
    })

    sb_insert("organizational_security_scores", {
        "id": str(uuid.uuid4()),
        "score": crsi["score"],
        "period_start": date.today().isoformat(),
        "period_end": date.today().isoformat(),
        "maturity_level": crsi["maturity_level"],
        "incident_count": crsi["incident_count"],
        "calculation_metadata": {"assessment_window": crsi["assessment_window"]},
    })

    return {"success": True, "archived": row}

from fastapi import Body

@app.post("/api/auth/login")
async def api_login(credentials: dict = Body(...)):
    email = str(credentials.get("email") or "").strip().lower()
    password = str(credentials.get("password") or "")

    if not email or not password:
        raise HTTPException(status_code=401, detail="Email and password are required.")

    if supabase:
        try:
            auth_response = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            if auth_response and auth_response.session:
                return {
                    "token": auth_response.session.access_token,
                    "user": {"email": email},
                    "auth_source": "supabase_auth",
                }
        except Exception as exc:
            pass

    if supabase:
        try:
            res = supabase.table("users").select("*").eq("email", email).limit(1).execute()
            row = (res.data or [None])[0]
            if row:
                stored = str(row.get("password_hash") or "")
                given = hashlib.sha256(password.encode()).hexdigest()
                if stored and hmac.compare_digest(stored, given):
                    return {
                        "token": issue_token(email, row.get("role")),
                        "user": {"email": email, "name": row.get("name"), "role": row.get("role")},
                        "auth_source": "users_table",
                    }
        except Exception as exc:
            pass

    account = BUILTIN_ACCOUNTS.get(email)
    if account and hmac.compare_digest(password, account["password"]):
        if not account["active"]:
            raise HTTPException(
                status_code=403,
                detail="Your account is not activated yet. Please contact your administrator.",
            )
        return {
            "token": issue_token(email, account["role"]),
            "user": {"email": email, "name": account["name"], "role": account["role"]},
            "auth_source": "builtin",
        }

    raise HTTPException(status_code=401, detail="Incorrect email or password.")

@app.get("/api/admin/clear")
async def clear_database(request: Request, key: str = Query(None)):
    auth_user = getattr(request.state, "auth_user", {})
    if auth_user.get("role") != "admin":
        return JSONResponse(status_code=403, content={"detail": "Forbidden: Admin role required."})
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
    return {"status": "ok", "version": "10.1.0", "incidents": len(PACKAGES)}

@app.get("/api/debug/config")
async def debug_config():
    return {
        "supabase_connected": supabase is not None,
        "packages_in_memory": len(PACKAGES),
        "crsi_archives": len(CRSI_ARCHIVES),
        "trend_window_hours": TREND_WINDOW_HOURS,
        "simulator_enabled": SIM_ENABLED,
        "simulator_interval_seconds": SIM_INTERVAL,
        "last_supabase_errors": SUPABASE_ERRORS[-5:],
        "twilio": {
            "configured": bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_PHONE),
            "recipients": len(TEAM_NUMBERS),
            "last_result": LAST_TWILIO,
        },
        "email": {
            "configured": bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM_EMAIL),
            "recipients": ALERT_EMAILS,
            "last_result": LAST_EMAIL,
        },
        "traffic_profiles": {k: len(v) for k, v in TRAFFIC_PROFILES.items()},
        "simulator_max_incidents": SIM_MAX_INCIDENTS,
        "status": "Ready",
    }

def synth_features(profile: str = "normal") -> dict:
    bank = TRAFFIC_PROFILES.get(profile) or TRAFFIC_PROFILES.get("normal") or []
    if not bank:
        return {f: round(random.gauss(0, 0.6), 5) for f in FEATURE_KEYS}

    sample = list(random.choice(bank))
    jitter = 0.03
    return {
        f: round(sample[i] + random.gauss(0, jitter), 5)
        for i, f in enumerate(FEATURE_KEYS)
        if i < len(sample)
    }

def build_sim_incident() -> IncidentIn:
    types = ["benign", "phishing", "brute_force", "malware", "ddos", "ransomware", "insider_threat"]
    weights = [45, 25, 18, 7, 3, 1, 1] 
    itype = random.choices(types, weights=weights)[0]
    
    # ضمان أن الـ timestamp صادر باللحظة الحالية ليوم 19-8
    current_time_str = datetime.now(timezone.utc).isoformat()

    return IncidentIn(
        title=f"Auto Simulated {itype.replace('_', ' ').title()}",
        incident_type=itype,
        source="Automated Simulator",
        input_method="server",
        source_ip=f"{random.randint(11,220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.1", 
        destination_ip="10.0.0.5",
        asset_type=random.choice(["Server", "Workstation", "Database", "Network Device", "Cloud Instance"]), 
        asset_criticality=random.choice(["low", "medium", "high"]), 
        exposure="internal", 
        vulnerability_level=random.choice(["low", "medium"]), 
        business_impact="medium",
        flow_features=synth_features("normal")
    )

async def simulator_loop():
    while True:
        await asyncio.sleep(SIM_INTERVAL)
        if not SIM_ENABLED:
            continue
        # السقف اختياري الآن؛ 0 يعني توليداً مستمراً بلا توقف
        if SIM_MAX_INCIDENTS and len(PACKAGES) >= SIM_MAX_INCIDENTS:
            continue
        try:
            process_incident(build_sim_incident())
        except Exception as e:
            pass

async def keep_alive_loop():
    """
    خطة Render المجانية توقف الخدمة بعد 15 دقيقة خمول، وأول طلب بعدها
    يستغرق 30-50 ثانية — وهذا سبب بطء الاستجابة بعد كل إعادة تشغيل.
    نداء ذاتي دوري يبقيها مستيقظة طوال فترة العرض.
    """
    if not KEEP_ALIVE_URL:
        print("[keepalive] disabled — RENDER_EXTERNAL_URL not set")
        return

    await asyncio.sleep(60)
    while True:
        try:
            await asyncio.to_thread(
                requests.get, f"{KEEP_ALIVE_URL.rstrip('/')}/health", timeout=15
            )
        except Exception as e:
            print(f"[keepalive] ping failed: {e}")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)


async def bootstrap():
    """
    كل ما يحتاج شبكة يعمل هنا بعد ربط المنفذ، لا داخل startup.
    استدعاء hydrate_from_supabase داخل startup كان يؤخر استجابة الخدمة
    بعد كل إعادة تشغيل حتى يرد Supabase.
    """
    try:
        await asyncio.to_thread(hydrate_from_supabase)
    except Exception as e:
        print(f"[startup] hydrate failed: {e}")

    if not PACKAGES:
        for _ in range(3):
            try:
                await asyncio.to_thread(process_incident, build_sim_incident())
            except Exception as e:
                print(f"[startup] seed failed: {e}")
            await asyncio.sleep(0.5)

    await simulator_loop()


@app.on_event("startup")
async def startup_event():
    # يرجع فوراً حتى يُربط المنفذ بسرعة ولا يفشل النشر
    asyncio.create_task(bootstrap())
    asyncio.create_task(keep_alive_loop())

# ---------------------------------------------------------------------------
# قالب Word — مبني بمكتبة zipfile القياسية، بلا أي اعتمادية جديدة.
# ملف .docx هو في الأصل أرشيف ZIP يحتوي XML، لذلك لا حاجة لتنصيب python-docx
# على Render (وكل اعتمادية إضافية = مخاطرة نشر إضافية).
# ---------------------------------------------------------------------------

def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _docx_paragraph(text: str = "", bold: bool = False, size: int = 20,
                    color: str = "000000", space_after: int = 120) -> str:
    runs = ""
    if text:
        props = f'<w:b/>' if bold else ''
        runs = (f'<w:r><w:rPr>{props}<w:sz w:val="{size}"/>'
                f'<w:color w:val="{color}"/></w:rPr>'
                f'<w:t xml:space="preserve">{_xml_escape(text)}</w:t></w:r>')
    return (f'<w:p><w:pPr><w:spacing w:after="{space_after}"/></w:pPr>{runs}</w:p>')


def _docx_cell(text: str, width: int, bold: bool = False, shade: str = None) -> str:
    fill = f'<w:shd w:val="clear" w:fill="{shade}"/>' if shade else ""
    return (f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{fill}</w:tcPr>'
            f'{_docx_paragraph(text, bold=bold, size=18, space_after=0)}</w:tc>')


def _docx_table(rows, widths, header: bool = True) -> str:
    borders = ('<w:tblBorders>' + "".join(
        f'<w:{edge} w:val="single" w:sz="4" w:color="C9CED6"/>'
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV")
    ) + '</w:tblBorders>')

    body = ""
    for index, row in enumerate(rows):
        is_header = header and index == 0
        cells = "".join(
            _docx_cell(value, widths[i], bold=is_header,
                       shade="DBEAFE" if is_header else ("F7F9FC" if i == 0 else None))
            for i, value in enumerate(row)
        )
        body += f"<w:tr>{cells}</w:tr>"

    return (f'<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/>{borders}</w:tblPr>'
            f'{body}</w:tbl>' + _docx_paragraph(space_after=200))


def build_incident_template_docx(values: dict | None = None) -> bytes:
    """
    قالب تقرير الحادثة بصيغة Word.
    values=None يعطي قالباً فارغاً جاهزاً للتعبئة،
    وتمرير قيم يعطي نسخة معبّأة (تُستخدم في الاختبار والأمثلة).
    """
    import zipfile
    values = values or {}

    parts = [
        _docx_paragraph("SentriX — Incident Report Template", bold=True, size=32),
        _docx_paragraph(
            "Fill in the values below and upload this file on the New Incident page. "
            "Keep the field names exactly as they appear — the analysis engine matches "
            "them by name. The AI Network Features section is required for "
            "machine-learning scoring; if any of the 37 values is missing, the incident "
            "is scored from organizational context only.",
            size=18, color="4B5563"),

        _docx_paragraph("1. Incident Information", bold=True, size=24),
        _docx_table([
            ["Field", "Value"],
            ["Incident Type", ""],
            ["Source", ""],
            ["Description", ""],
        ], [3200, 6160]),

        _docx_paragraph("2. Network Information", bold=True, size=24),
        _docx_table([
            ["Field", "Value"],
            ["Protocol", ""],
            ["Source IP", ""],
            ["Destination IP", ""],
        ], [3200, 6160]),

        _docx_paragraph("3. Asset Information", bold=True, size=24),
        _docx_table([
            ["Field", "Value"],
            ["Asset Type", ""],
            ["Asset Criticality", ""],
            ["Exposure", ""],
            ["Vulnerability", ""],
            ["Business Impact", ""],
        ], [3200, 6160]),

        _docx_paragraph(f"4. AI Network Features — all {len(FEATURE_KEYS)} values required",
                        bold=True, size=24),
        _docx_paragraph(
            "Values are standardized (StandardScaler) exactly as the model was trained. "
            "Enter the values captured for your incident.",
            size=16, color="6B7280"),
        _docx_table([["Feature", "Value"]] +
                    [[name, str(values.get(name, ""))] for name in FEATURE_KEYS],
                    [5200, 4160]),

        _docx_paragraph(
            "SentriX — AI-Powered Threat Investigation & Incident Response Platform. "
            "Do not rename or reorder the fields.",
            size=14, color="9CA3AF"),
    ]

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{"".join(parts)}'
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/>'
        '</w:sectPr></w:body></w:document>'
    )

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )

    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return buf.getvalue()


def extract_docx_pairs(data: bytes) -> tuple[dict, str]:
    """
    يقرأ جداول ملف Word ويرجع (الفيتشرز المستخرجة، النص الكامل).
    ملف .docx أرشيف ZIP، فالقراءة تتم بـzipfile و ElementTree من المكتبة القياسية.
    """
    import zipfile
    import xml.etree.ElementTree as ET

    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    extracted, lines = {}, []

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        xml_bytes = archive.read("word/document.xml")

    root = ET.fromstring(xml_bytes)

    def cell_text(node) -> str:
        return "".join(t.text or "" for t in node.iter(f"{{{ns['w']}}}t")).strip()

    for table in root.iter(f"{{{ns['w']}}}tbl"):
        for row in table.iter(f"{{{ns['w']}}}tr"):
            cells = [cell_text(c) for c in row.findall(f"{{{ns['w']}}}tc")]
            if len(cells) < 2:
                continue
            lines.append(": ".join(cells[:2]))
            key = _match_feature(cells[0])
            if key and key not in extracted:
                value = _to_number(cells[1])
                if value is not None:
                    extracted[key] = value

    for para in root.iter(f"{{{ns['w']}}}p"):
        text = cell_text(para)
        if text:
            lines.append(text)

    return extracted, "\n".join(lines)


@app.get("/api/incidents/template/docx/download")
async def download_docx_template():
    """قالب Word فارغ — أسهل للتعبئة من الـPDF."""
    return Response(
        content=build_incident_template_docx(),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition":
                 'attachment; filename="SentriX_Incident_Report_Template.docx"'},
    )


@app.post("/api/debug/test-alert")
async def test_alert():
    """
    يجرّب SMS والمكالمة والبريد فوراً بحادثة وهمية، ويرجع نتيجة كل قناة
    مع رمز الخطأ — بدل انتظار حادثة حرجة حقيقية لمعرفة سبب الفشل.
    """
    sample = {
        "incident": {
            "id": "TEST-0000",
            "title": "Twilio delivery test",
            "incident_type": "test",
            "source": "Diagnostics",
            "asset_type": "Server",
            "asset_criticality": "critical",
            "created_at": now_iso(),
        },
        "risk": {
            "severity": "Critical", "risk_score": 99, "priority": "P1",
            "sla_hours": 1, "dynamic_threshold": 0.1167,
        },
        "ai_result": {"anomaly_score": 0.99},
        "threat": {"mitre_techniques": ["T1486"]},
        "recommendation": {"playbook": "TEST_PLAYBOOK", "actions": []},
    }

    sms_and_call = notify_twilio("TEST-0000", "Critical", "test", 99)
    email = notify_email(sample)

    return {
        "config": {
            "TWILIO_SID": bool(TWILIO_SID),
            "TWILIO_TOKEN": bool(TWILIO_TOKEN),
            "TWILIO_PHONE": TWILIO_PHONE or None,
            "TEAM_NUMBERS": TEAM_NUMBERS,
            "TWILIO_FROM_EMAIL": TWILIO_FROM_EMAIL or None,
            "ALERT_EMAILS": ALERT_EMAILS,
        },
        "sms_and_voice": sms_and_call,
        "email": email,
        "hint": (
            "code 21608 = رقم غير موثّق في الحساب التجريبي · "
            "21408 = الإرسال إلى المنطقة معطّل (Geo Permissions) · "
            "21606 = رقم المُرسِل لا يدعم SMS · "
            "20003 = مفاتيح خاطئة أو الرصيد نفد · "
            "email 403 = عنوان المُرسِل غير موثّق في Twilio"
        ),
    }


@app.get("/api/incidents/template/download")
async def download_pdf_template():
    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="SentriX Incident Report Template")

    sample = synth_features("normal")

    story = [
        Paragraph("SentriX — Incident Report Template", styles["Title"]),
        Spacer(1, 6),
        Paragraph(
            "Fill in the values below and upload this file on the New Incident page. "
            "Keep the field names exactly as they appear — the analysis engine matches them by name. "
            "The AI Network Features section is required for machine-learning scoring; "
            "if any of the 37 values is missing, the incident is scored from organizational context only.",
            styles["Normal"],
        ),
        Spacer(1, 14),
    ]

    def block(title, rows, widths=(190, 300)):
        story.append(Paragraph(title, styles["Heading2"]))
        table = Table(rows, colWidths=list(widths))
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.extend([table, Spacer(1, 10)])

    block("1. Incident Information", [
        ["Incident Type", "ransomware | brute force | ddos | phishing | malware | insider"],
        ["Source", "EDR"],
        ["Description", ""],
    ])

    block("2. Network Information", [
        ["Protocol", "TCP"],
        ["Source IP", "45.33.12.8"],
        ["Destination IP", "10.0.0.15"],
    ])

    block("3. Asset Information", [
        ["Asset Type", "Server | Workstation | Database | Network Device"],
        ["Asset Criticality", "low | medium | high | critical"],
        ["Exposure", "internal | dmz | internet_facing"],
        ["Vulnerability", "none | low | medium | high | critical"],
        ["Business Impact", "low | medium | high | critical"],
    ])

    story.append(Paragraph(
        f"4. AI Network Features — all {len(FEATURE_KEYS)} values required",
        styles["Heading2"]))
    story.append(Paragraph(
        "<font size=7 color='#666666'>Values are standardized (StandardScaler) exactly as the "
        "model was trained. The examples below are a real sample of normal traffic; replace them "
        "with the values captured for your incident.</font>",
        styles["Normal"]))
    story.append(Spacer(1, 4))

    feature_rows = [["Feature", "Value"]] + [
        [name, str(sample.get(name, ""))] for name in FEATURE_KEYS
    ]
    table = Table(feature_rows, colWidths=[250, 240], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#dbeafe")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(table)

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "<font size=7 color='#666666'>SentriX — AI-Powered Threat Investigation &amp; Incident "
        "Response Platform. Do not rename or reorder the fields.</font>",
        styles["Normal"]))

    doc.build(story)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="SentriX_Incident_Report_Template.pdf"'},
    )

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
    text = ""
    itype = "malware"
    src_ip = None

    try:
        if extracted:
            raise RuntimeError("already parsed as Word")   # يتخطى مسار الـPDF
        import pdfplumber
        tmp = FILES_DIR / f"_tmp_{uuid.uuid4()}.pdf"
        tmp.write_bytes(data)
        try:
            with pdfplumber.open(tmp) as pdf:
                text = "\n".join(pg.extract_text() or "" for pg in pdf.pages)

                for page in pdf.pages:
                    for tbl in (page.extract_tables() or []):
                        for row in tbl:
                            if not row or len(row) < 2:
                                continue
                            for i, cell in enumerate(row[:-1]):
                                key = _match_feature(cell)
                                if not key or key in extracted:
                                    continue
                                for candidate in row[i + 1:]:
                                    value = _to_number(candidate)
                                    if value is not None:
                                        extracted[key] = value
                                        break

                for line in text.splitlines():
                    if ":" not in line:
                        continue
                    left, _, right = line.partition(":")
                    key = _match_feature(left)
                    if key and key not in extracted:
                        value = _to_number(right)
                        if value is not None:
                            extracted[key] = value
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

        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m:
            src_ip = m.group(1)
    except Exception as e:
        pass

    complete = features_complete(extracted)
    lower_text = (text or "").lower()

    def pick(keys, options, default):
        for line in lower_text.splitlines():
            if any(k in line for k in keys):
                for opt in options:
                    if opt in line:
                        return opt
        return default

    # القيم الافتراضية كانت high/internet_facing/high/high، فأي ملف لا يُقرأ
    # منه شيء يخرج بدرجة ~98 = Critical بينما النموذج لم يعمل أصلاً
    # (فتظهر الحادثة Critical و"Pending" في صفحة التحليل معاً).
    # الافتراضي الآن medium، ولا تُرفع القيم إلا إذا نصّ عليها التقرير.
    asset_criticality = pick(["asset criticality", "criticality"],
                            ["critical", "high", "medium", "low"], "medium")
    exposure = pick(["exposure"], ["internet_facing", "internet facing", "dmz", "internal"],
                    "internal")
    exposure = exposure.replace("internet facing", "internet_facing")
    vulnerability_level = pick(["vulnerability"], ["critical", "high", "medium", "low", "none"], "medium")
    business_impact = pick(["business impact", "impact"], ["critical", "high", "medium", "low"], "medium")

    asset_type = "Server"
    for candidate in ("workstation", "database", "network device", "cloud instance", "server"):
        if candidate in lower_text:
            asset_type = candidate.title()
            break

    payload = IncidentIn(
        title=f"Incident report — {file.filename}",
        incident_type=itype,
        source="PDF Report",
        input_method="pdf",
        source_ip=src_ip,
        description=(
            f"Ingested from PDF '{file.filename}'. "
            f"{len(extracted)}/{len(FEATURE_KEYS)} network flow features extracted."
        ),
        asset_type=asset_type,
        asset_criticality=asset_criticality,
        exposure=exposure,
        vulnerability_level=vulnerability_level,
        business_impact=business_impact,
        source_file_name=file.filename,
        flow_features=extracted if complete else None,
    )

    result = process_incident(payload)
    missing = [k for k in FEATURE_KEYS if k not in extracted]
    result["pdf_extraction"] = {
        "matched_features": len(extracted),
        "required_features": len(FEATURE_KEYS),
        "missing_features": missing[:10],
        "used_for_model": complete,
        "reason": None if complete else (
            f"{len(missing)} network flow feature(s) missing from the report — "
            f"scored from organizational context only."
        ),
        "detected_incident_type": itype,
        "scoring_mode": result["risk"]["scoring_mode"],
        "severity": result["risk"]["severity"],
        "context_used": {
            "asset_criticality": asset_criticality, "exposure": exposure,
            "vulnerability_level": vulnerability_level, "business_impact": business_impact,
        },
        "uploaded_sha256": sha256_of(data),
        "client_sha256": sha256,
        "analyst": analyst,
    }
    return result
# ===========================================================================
# 9. TWILIO EMAIL, SMS & VOICE CALLS
# ===========================================================================

import requests
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse


def notify_email(pkg: dict) -> dict:
    global LAST_EMAIL
    try:
        risk = pkg["risk"]
        inc = pkg["incident"]

        if str(risk.get("severity", "")).lower() != "critical":
            result = {"sent": False, "reason": "severity_not_critical"}
            LAST_EMAIL = result
            return result

        missing = [n for n, v in (("TWILIO_SID", TWILIO_SID), ("TWILIO_TOKEN", TWILIO_TOKEN),
                                  ("TWILIO_FROM_EMAIL", TWILIO_FROM_EMAIL),
                                  ("ALERT_EMAILS", ALERT_EMAILS)) if not v]
        if missing:
            result = {"sent": False, "reason": f"missing_config: {', '.join(missing)}"}
            print(f"[email] skipped — {result['reason']}")
            LAST_EMAIL = result
            return result

        recipients = [{"address": email} for email in ALERT_EMAILS if email]
        if not recipients:
            result = {"sent": False, "reason": "no_recipients"}
            LAST_EMAIL = result
            return result

        response = requests.post(
            "https://comms.twilio.com/v1/Emails",
            auth=(TWILIO_SID, TWILIO_TOKEN),
            json={
                "from": {"address": TWILIO_FROM_EMAIL, "name": "SentriX Security"},
                "to": recipients,
                "content": {
                    "subject": f"🚨 Critical Incident Alert — {inc['id']}",
                    "html": f"<p>Critical incident {inc['id']} detected. Severity: {risk['severity']}</p>"
                }
            },
            timeout=10
        )
        ok = response.status_code in (200, 201, 202)
        if not ok:
            print(f"[email] FAILED {response.status_code}: {response.text[:300]}")
        else:
            print(f"[email] sent to {', '.join(ALERT_EMAILS)} ({response.status_code})")
        result = {"sent": ok, "status": response.status_code,
                  "to": ALERT_EMAILS,
                  "error": None if ok else response.text[:300]}
    except Exception as e:
        print(f"[email] FAILED: {type(e).__name__}: {e}")
        result = {"sent": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    LAST_EMAIL = result
    return result


def notify_twilio(ref: str, severity: str, incident_type: str, risk_score: int) -> dict:
    global LAST_TWILIO
    try:
        if severity != "Critical":
            return {"sent": False, "reason": "severity_not_critical"}

        missing = [n for n, v in (("TWILIO_SID", TWILIO_SID), ("TWILIO_TOKEN", TWILIO_TOKEN),
                                  ("TWILIO_PHONE", TWILIO_PHONE)) if not v]
        if missing:
            reason = f"missing_config: {', '.join(missing)}"
            print(f"[twilio] skipped — {reason}")
            return {"sent": False, "reason": reason}

        target_phones = TEAM_NUMBERS or []
        if not target_phones:
            reason = "missing_config: TEAM_NUMBERS is empty"
            print(f"[twilio] skipped — {reason}")
            return {"sent": False, "reason": reason}

        client = Client(TWILIO_SID, TWILIO_TOKEN)
        results = []

        sms_body = f"SentriX Alert: Critical {incident_type} detected. ID: {ref}. Risk: {risk_score}."

        for target_phone in target_phones:
            # 1. إرسال الرسالة النصية SMS
            try:
                message = client.messages.create(to=target_phone, from_=TWILIO_PHONE, body=sms_body)
                print(f"[twilio] sms sid={message.sid} to={target_phone} status={message.status}")
                results.append({"type": "sms", "sent": True, "sid": message.sid,
                                "status": message.status, "to": target_phone})
            except Exception as e:
                code = getattr(e, "code", None)
                print(f"[twilio] sms FAILED to={target_phone} code={code}: {e}")
                results.append({"type": "sms", "sent": False, "code": code,
                                "to": target_phone, "error": str(e)[:200]})

            # 2. إجراء المكالمة ونطق تفاصيل الحادثة الحقيقية بصوت الآلة
            try:
                response = VoiceResponse()
                response.say(f"Attention. SentriX Security Alert. Critical {incident_type} detected. Incident reference {ref}. Risk score {risk_score}. Please check your dashboard immediately.", language="en-US", voice="alice")
                call = client.calls.create(
                    twiml=str(response),
                    to=target_phone,
                    from_=TWILIO_PHONE
                )
                print(f"[twilio] call sid={call.sid} to={target_phone} status={call.status}")
                results.append({"type": "voice", "sent": True, "sid": call.sid,
                                "status": call.status, "to": target_phone})
            except Exception as e:
                code = getattr(e, "code", None)
                print(f"[twilio] voice FAILED to={target_phone} code={code}: {e}")
                results.append({"type": "voice", "sent": False, "code": code,
                                "to": target_phone, "error": str(e)[:200]})

        result = {"sent": any(item.get("sent") is True for item in results), "results": results}
    except Exception as e:
        result = {"sent": False, "error": str(e)[:200]}

    LAST_TWILIO = result
    return result
