"""
SentriX Test Environment API  (v2 — Full AI-cycle simulator)
--------------------------------------------------------------
هذا سيرفر اختبار "يلعب دور الباك إند الحقيقي" لحد ما يجهز فعليًا.
يستقبل حادثة (يدويًا / PDF / مولّدة تلقائيًا) ويمشي عليها *نفس* المسار
الموصوف من فريق الـ AI بالضبط:

  Incident → (flow_features كاملة؟) → Isolation Forest (mock)
           → Risk Agent → Threat Agent → Security Score Agent
           → Recommendation Agent → Master Agent (priority + narrative)
           → Save لكل الجداول → Report JSON→PDF → Archive (SHA-256)
           → رجوع Response واحد فيه كل شي (زي ما يطلبه الفرونت)

كل جدول = ملف JSON تحت storage/db/*.json (بديل مؤقت لقاعدة البيانات الحقيقية،
بنفس أسماء الجداول اللي فريق الداتا بيس جهزها: incidents, ai_results,
risk_results, threat_analysis, incident_recommendations, ai_narratives,
organizational_security_scores, incident_reports, report_archives).

نقاط لازم تُستبدل لاحقًا (معلّمة بتعليق MOCK):
  - mock_isolation_forest()   -> استدعاء حقيقي لـ DataRobot
  - narrative template        -> استدعاء حقيقي لنموذج اللغة (يشرح فقط، ما يقرر)
  - PLAYBOOK / MITRE_MAP      -> محتوى playbooks.json الحقيقي من فريق الأمن
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
# إعداد عام
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent
STORAGE_DIR = BASE_DIR / "storage"
FILES_DIR = STORAGE_DIR / "files"
DB_DIR = STORAGE_DIR / "db"
FILES_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SentriX Test Environment API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ANOMALY_THRESHOLD = 0.1167  # نفس العتبة المذكورة (μ + 2σ)

# قائمة الـ 36 feature المتفق عليها سابقًا. لو القائمة النهائية عندكم 37،
# ضيفوا/عدّلوا هنا بس — كل الكود يقرأ من FEATURE_KEYS تلقائيًا.
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
    "ransomware": {"tactic": "Impact", "technique": "T1486 - Data Encrypted for Impact"},
    "phishing": {"tactic": "Initial Access", "technique": "T1566 - Phishing"},
    "ddos": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service"},
    "unauthorized_access": {"tactic": "Credential Access", "technique": "T1078 - Valid Accounts"},
    "data_exfiltration": {"tactic": "Exfiltration", "technique": "T1041 - Exfiltration Over C2 Channel"},
    "malware": {"tactic": "Execution", "technique": "T1204 - User Execution"},
    "insider_threat": {"tactic": "Collection", "technique": "T1213 - Data from Information Repositories"},
    "default": {"tactic": "Unknown", "technique": "غير محدد — يحتاج تصنيف يدوي"},
}

CONTROL_DOMAINS = {
    "ransomware": ["endpoint_security", "backup_recovery", "awareness"],
    "phishing": ["awareness", "email_security"],
    "ddos": ["network_security", "availability_controls"],
    "unauthorized_access": ["access_control", "monitoring"],
    "data_exfiltration": ["access_control", "monitoring", "network_security"],
    "malware": ["endpoint_security", "monitoring"],
    "insider_threat": ["access_control", "awareness"],
    "default": ["general_controls"],
}

PLAYBOOK = {
    "ransomware": [
        {"action": "عزل الأصل المصاب عن الشبكة فورًا", "control_id": "NIST-IR-4", "framework": "NIST"},
        {"action": "تفعيل خطة استعادة النسخ الاحتياطية", "control_id": "ISO-A.12.3", "framework": "ISO 27001"},
        {"action": "تدوير بيانات الاعتماد المرتبطة بالأصل", "control_id": "NCA-ECC-2-6", "framework": "NCA ECC"},
    ],
    "phishing": [
        {"action": "حظر النطاق/المرسل على بوابة البريد", "control_id": "NIST-IR-3", "framework": "NIST"},
        {"action": "إشعار المستخدمين المتأثرين وتغيير كلمات المرور", "control_id": "ISO-A.7.2", "framework": "ISO 27001"},
    ],
    "default": [
        {"action": "مراقبة الأصل لمدة 24 ساعة إضافية", "control_id": "GEN-01", "framework": "Internal"},
    ],
}

# ---------------------------------------------------------------------------
# طبقة "قاعدة بيانات" JSON بسيطة — تُستبدل لاحقًا بقاعدة بيانات حقيقية
# ---------------------------------------------------------------------------

def _table_path(name: str) -> Path:
    return DB_DIR / f"{name}.json"


def load_table(name: str) -> list:
    p = _table_path(name)
    if not p.exists():
        p.write_text("[]", encoding="utf-8")
    return json.loads(p.read_text(encoding="utf-8"))


def save_table(name: str, rows: list) -> None:
    _table_path(name).write_text(json.dumps(rows, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def append_row(name: str, row: dict) -> dict:
    rows = load_table(name)
    rows.append(row)
    save_table(name, rows)
    return row


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# نماذج الطلبات
# ---------------------------------------------------------------------------

class IncidentIn(BaseModel):
    title: str = "حادثة غير معنونة"
    source: str = "manual"  # manual | pdf | generated | live
    incident_type: str = "default"
    ip_addresses: list[str] = []
    asset_type: str = "server"
    asset_criticality: int = 3  # 1-5
    exposure_score: int | None = None
    vulnerability_level: str | None = None
    business_impact: str | None = None
    flow_features: dict | None = None


# ---------------------------------------------------------------------------
# MOCK: كشف الشذوذ (بديل مؤقت لـ Isolation Forest على DataRobot)
# ---------------------------------------------------------------------------

def flow_features_complete(features: dict | None) -> bool:
    if not features:
        return False
    return all(k in features and features[k] is not None for k in FEATURE_KEYS)


# نقطة الربط الحقيقي — لما فريق الـ AI يعطيكم رابط DataRobot، حطّوه بمتغيرات بيئة
# DATAROBOT_ENDPOINT و DATAROBOT_API_KEY (بدون تعديل أي سطر كود آخر). لو غير موجودة،
# يشتغل بالـ mock تلقائيًا — عشان الويب ما ينكسر أبدًا وهو ينتظر.
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
            # عدّلوا هذا السطر حسب شكل رد DataRobot الفعلي (اسم الحقل قد يختلف)
            return float(resp.json()["predictions"][0]["anomaly_score"])
        except Exception:
            # لو فشل الاتصال الحقيقي لأي سبب، نرجع للـ mock بدل ما نكسر السايكل كامل
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


def generate_synthetic_features() -> dict:
    fwd_pkts = random.randint(1, 500)
    bwd_pkts = random.randint(0, 500)
    return {
        "Protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "Flow Duration": random.randint(100, 2_000_000),
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Fwd Packets Length Total": round(random.uniform(0, 50000), 2),
        "Bwd Packets Length Total": round(random.uniform(0, 50000), 2),
        "Fwd Packet Length Max": round(random.uniform(0, 1500), 2),
        "Fwd Packet Length Min": round(random.uniform(0, 100), 2),
        "Fwd Packet Length Mean": round(random.uniform(0, 800), 2),
        "Bwd Packet Length Max": round(random.uniform(0, 1500), 2),
        "Bwd Packet Length Min": round(random.uniform(0, 100), 2),
        "Bwd Packet Length Mean": round(random.uniform(0, 800), 2),
        "Flow Bytes/s": round(random.uniform(0, 10000), 2),
        "Flow Packets/s": round(random.uniform(0, 500), 2),
        "Flow IAT Mean": round(random.uniform(0, 100000), 2),
        "Flow IAT Std": round(random.uniform(0, 50000), 2),
        "Fwd IAT Total": round(random.uniform(0, 500000), 2),
        "Bwd IAT Total": round(random.uniform(0, 500000), 2),
        "Fwd Header Length": random.randint(20, 2000),
        "Bwd Header Length": random.randint(20, 2000),
        "Fwd Packets/s": round(random.uniform(0, 300), 2),
        "Bwd Packets/s": round(random.uniform(0, 300), 2),
        "Packet Length Min": round(random.uniform(0, 100), 2),
        "Packet Length Max": round(random.uniform(100, 1500), 2),
        "Packet Length Mean": round(random.uniform(0, 800), 2),
        "Packet Length Std": round(random.uniform(0, 400), 2),
        "Packet Length Variance": round(random.uniform(0, 160000), 2),
        "FIN Flag Count": random.randint(0, 1),
        "SYN Flag Count": random.randint(0, 3),
        "RST Flag Count": random.randint(0, 1),
        "PSH Flag Count": random.randint(0, 5),
        "ACK Flag Count": random.randint(0, fwd_pkts + bwd_pkts),
        "URG Flag Count": random.randint(0, 1),
        "ECE Flag Count": random.randint(0, 1),
        "Down/Up Ratio": round(random.uniform(0, 5), 2),
        "Avg Packet Size": round(random.uniform(0, 800), 2),
        "Fwd Seg Size Min": random.randint(20, 40),
    }


# ---------------------------------------------------------------------------
# سلسلة الوكلاء (Mock Agent Chain)
# ---------------------------------------------------------------------------

def risk_agent(anomaly_score, asset_criticality, vulnerability_level, business_impact, exposure_score):
    context_weights = {"Low": 10, "Medium": 25, "High": 40, None: 15}
    base = context_weights.get(vulnerability_level, 15) + context_weights.get(business_impact, 15)
    base += (asset_criticality or 3) * 5
    if exposure_score:
        base += exposure_score * 0.2
    if anomaly_score is not None:
        base += anomaly_score * 100 * 0.5
    risk_score = round(min(max(base, 0), 100), 1)

    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 55:
        severity = "High"
    elif risk_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"
    return risk_score, severity


def threat_agent(incident_type: str, severity: str):
    mitre = MITRE_MAP.get(incident_type, MITRE_MAP["default"])
    sev_to_level = {"Critical": "High", "High": "High", "Medium": "Medium", "Low": "Low"}
    level = sev_to_level.get(severity, "Low")
    return {
        "mitre_tactic": mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "cia_impact": {"confidentiality": level, "integrity": level, "availability": level},
    }


def recommendation_agent(incident_type: str):
    return PLAYBOOK.get(incident_type, PLAYBOOK["default"])


def master_agent(risk_score, severity):
    priority_map = {"Critical": ("P1", 15), "High": ("P2", 60), "Medium": ("P3", 240), "Low": ("P4", 1440)}
    return priority_map[severity]


def build_narrative(incident_id, anomaly_score, risk_score, severity, priority, threat):
    anomaly_txt = f"{anomaly_score:.4f}" if anomaly_score is not None else "غير متاحة (إدخال يدوي بدون flow_features)"
    return (
        f"الحادثة {incident_id}: درجة الشذوذ {anomaly_txt}، "
        f"درجة الخطورة {risk_score}/100 ({severity})، الأولوية {priority}. "
        f"تكتيك MITRE المرجّح: {threat['mitre_tactic']} ({threat['mitre_technique']}). "
        f"[توليد آلي مبدئي — يُستبدل لاحقًا بشرح نموذج اللغة الفعلي]"
    )


# ---------------------------------------------------------------------------
# الدرجة الأمنية المؤسسية (Organizational Security Score / CRSI)
# ---------------------------------------------------------------------------

BASELINE_DOMAINS = {
    "endpoint_security": 80, "backup_recovery": 80, "awareness": 80,
    "network_security": 80, "access_control": 80, "monitoring": 80,
    "email_security": 80, "availability_controls": 80, "general_controls": 80,
}
SEVERITY_PENALTY = {"Critical": 4, "High": 3, "Medium": 1.5, "Low": 0.5}


def recompute_org_score(incident_type: str, severity: str) -> dict:
    history = load_table("organizational_security_scores")
    domains = dict(history[-1]["domains"]) if history else dict(BASELINE_DOMAINS)

    penalty = SEVERITY_PENALTY.get(severity, 0.5)
    for domain in CONTROL_DOMAINS.get(incident_type, CONTROL_DOMAINS["default"]):
        domains[domain] = round(max(domains.get(domain, 80) - penalty, 0), 1)

    crsi = round(sum(domains.values()) / len(domains), 1)
    standards_score = crsi  # MOCK: بدون تدقيق معايير منفصل بعد
    incidents = load_table("incidents")
    recent_critical_high = sum(1 for i in incidents[-50:] if i.get("_last_severity") in ("Critical", "High"))
    incidents_score = round(max(100 - recent_critical_high * 3, 0), 1)
    overall = round(crsi * 0.5 + standards_score * 0.25 + incidents_score * 0.25, 1)

    row = {
        "id": str(uuid.uuid4()), "computed_at": now_iso(), "trigger_incident_type": incident_type,
        "domains": domains, "crsi": crsi, "standards_score": standards_score,
        "incidents_score": incidents_score, "overall_score": overall,
    }
    return append_row("organizational_security_scores", row)


# ---------------------------------------------------------------------------
# التقرير + الأرشفة
# ---------------------------------------------------------------------------

def archive_bytes(filename: str, data: bytes, source: str, content_type: str) -> dict:
    archive_id = str(uuid.uuid4())
    key = f"{archive_id}_{filename}"
    (FILES_DIR / key).write_bytes(data)
    record = {
        "id": archive_id, "filename": filename, "key": key, "content_type": content_type,
        "source": source, "sha256": sha256_of_bytes(data), "size_bytes": len(data),
        "created_at": now_iso(),
    }
    return append_row("report_archives", record)


def render_pdf(package: dict) -> bytes:
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SentriX Incident Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"Incident ID: {package['incident']['id']}", styles["Normal"]),
        Paragraph(f"Title: {package['incident']['title']}", styles["Normal"]),
        Paragraph(f"Severity: {package['risk']['severity']}  |  Priority: {package['priority']}", styles["Normal"]),
        Paragraph(f"Risk score: {package['risk']['risk_score']}/100", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("AI narrative", styles["Heading2"]),
        Paragraph(package["narrative"], styles["Normal"]),
        Spacer(1, 10),
        Paragraph("Recommendations", styles["Heading2"]),
    ]
    for rec in package["recommendations"]:
        story.append(Paragraph(f"• {rec['action']}  ({rec['framework']} {rec['control_id']})", styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Threat analysis", styles["Heading2"]))
    story.append(Paragraph(f"MITRE: {package['threat']['mitre_tactic']} — {package['threat']['mitre_technique']}", styles["Normal"]))
    cia = package["threat"]["cia_impact"]
    rows = [["Confidentiality", "Integrity", "Availability"], [cia["confidentiality"], cia["integrity"], cia["availability"]]]
    t = Table(rows, colWidths=[145, 145, 145])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C2C2A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)

    out_path = FILES_DIR / f"_tmp_{uuid.uuid4()}.pdf"
    SimpleDocTemplate(str(out_path), pagesize=letter).build(story)
    data = out_path.read_bytes()
    out_path.unlink(missing_ok=True)
    return data


# ---------------------------------------------------------------------------
# المسار الأساسي: معالجة حادثة كاملة
# ---------------------------------------------------------------------------

def process_incident(payload: IncidentIn) -> dict:
    incident_id = str(uuid.uuid4())
    created_at = now_iso()

    incident_row = {
        "id": incident_id, "title": payload.title, "source": payload.source,
        "incident_type": payload.incident_type, "ip_addresses": payload.ip_addresses,
        "asset_type": payload.asset_type, "asset_criticality": payload.asset_criticality,
        "exposure_score": payload.exposure_score, "vulnerability_level": payload.vulnerability_level,
        "business_impact": payload.business_impact,
        "has_full_flow_features": flow_features_complete(payload.flow_features),
        "created_at": created_at, "status": "processing",
    }
    append_row("incidents", incident_row)
    append_row("incident_inputs", {
        "id": str(uuid.uuid4()), "incident_id": incident_id, "input_method": payload.source,
        "raw_payload": payload.model_dump(), "created_at": created_at,
    })

    complete = flow_features_complete(payload.flow_features)
    anomaly_score = call_isolation_forest(payload.flow_features) if complete else None
    is_anomaly = (anomaly_score is not None) and (anomaly_score >= ANOMALY_THRESHOLD)
    ai_result = append_row("ai_results", {
        "id": str(uuid.uuid4()), "incident_id": incident_id, "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly, "threshold": ANOMALY_THRESHOLD, "model_version": "mock-0.1",
        "created_at": now_iso(),
    })

    risk_score, severity = risk_agent(
        anomaly_score, payload.asset_criticality, payload.vulnerability_level,
        payload.business_impact, payload.exposure_score,
    )
    risk_row = append_row("risk_results", {
        "id": str(uuid.uuid4()), "incident_id": incident_id, "risk_score": risk_score,
        "severity": severity, "created_at": now_iso(),
    })

    short_path = severity == "Low" and not is_anomaly

    if short_path:
        threat = {"mitre_tactic": "N/A", "mitre_technique": "N/A",
                   "cia_impact": {"confidentiality": "Low", "integrity": "Low", "availability": "Low"}}
        recs = [{"action": "إشعار فقط — لا يتطلب إجراء إضافي حاليًا", "control_id": "GEN-00", "framework": "Internal"}]
        priority, sla = "P4", 1440
    else:
        threat = threat_agent(payload.incident_type, severity)
        recs = recommendation_agent(payload.incident_type)
        priority, sla = master_agent(risk_score, severity)

    threat_row = append_row("threat_analysis", {
        "id": str(uuid.uuid4()), "incident_id": incident_id, **threat, "created_at": now_iso(),
    })
    for rec in recs:
        append_row("incident_recommendations", {
            "id": str(uuid.uuid4()), "incident_id": incident_id, **rec, "created_at": now_iso(),
        })

    narrative = build_narrative(incident_id, anomaly_score, risk_score, severity, priority, threat)
    append_row("ai_narratives", {
        "id": str(uuid.uuid4()), "incident_id": incident_id, "narrative": narrative, "created_at": now_iso(),
    })

    org_score = recompute_org_score(payload.incident_type, severity)

    incidents = load_table("incidents")
    for row in incidents:
        if row["id"] == incident_id:
            row["status"] = "resolved"
            row["_last_severity"] = severity
            row["priority"] = priority
            row["sla_minutes"] = sla
    save_table("incidents", incidents)

    package = {
        "incident": incident_row, "ai_result": ai_result, "risk": risk_row,
        "threat": threat_row, "recommendations": recs, "narrative": narrative,
        "priority": priority, "sla_minutes": sla, "organizational_security_score": org_score,
    }

    report_json = json.dumps(package, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    json_archive = archive_bytes(f"incident_{incident_id}.json", report_json, payload.source, "application/json")
    pdf_bytes = render_pdf(package)
    pdf_archive = archive_bytes(f"incident_{incident_id}.pdf", pdf_bytes, payload.source, "application/pdf")

    report_row = append_row("incident_reports", {
        "id": str(uuid.uuid4()), "incident_id": incident_id,
        "json_archive_id": json_archive["id"], "pdf_archive_id": pdf_archive["id"],
        "created_at": now_iso(),
    })

    package["report"] = report_row
    package["archives"] = {"json": json_archive, "pdf": pdf_archive}
    return package


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/incidents")
async def create_incident(payload: IncidentIn):
    return process_incident(payload)


@app.post("/api/test/generate-incident")
async def generate_test_incident(mode: str = "full", incident_type: str = "ransomware"):
    payload = IncidentIn(
        title=f"[TEST] {incident_type} incident",
        source="generated",
        incident_type=incident_type,
        ip_addresses=[f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"],
        asset_type=random.choice(["server", "workstation", "database"]),
        asset_criticality=random.randint(1, 5),
        exposure_score=random.randint(10, 90),
        vulnerability_level=random.choice(["Low", "Medium", "High"]),
        business_impact=random.choice(["Low", "Medium", "High"]),
        flow_features=generate_synthetic_features() if mode == "full" else None,
    )
    return process_incident(payload)


@app.post("/api/incidents/from-pdf")
async def create_incident_from_pdf(file: UploadFile = File(...), incident_type: str = "default"):
    data = await file.read()
    tmp = FILES_DIR / f"_tmp_{uuid.uuid4()}.pdf"
    tmp.write_bytes(data)
    extracted_features = {}
    try:
        with pdfplumber.open(tmp) as pdf:
            for page in pdf.pages:
                for table in page.extract_tables():
                    for row in table:
                        if len(row) >= 2 and row[0] in FEATURE_KEYS:
                            try:
                                extracted_features[row[0]] = float(row[1])
                            except (TypeError, ValueError):
                                extracted_features[row[0]] = row[1]
    finally:
        tmp.unlink(missing_ok=True)

    complete_enough = len(extracted_features) >= len(FEATURE_KEYS)
    payload = IncidentIn(
        title=f"PDF report — {file.filename}", source="pdf", incident_type=incident_type,
        flow_features=extracted_features if complete_enough else None,
    )
    result = process_incident(payload)
    result["pdf_extraction"] = {
        "matched_features": len(extracted_features), "required": len(FEATURE_KEYS),
        "used_for_model": complete_enough,
    }
    return result


@app.get("/api/incidents")
async def list_incidents():
    return load_table("incidents")


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    def find_one(table):
        return next((r for r in load_table(table) if r.get("incident_id") == incident_id), None)

    def find_all(table):
        return [r for r in load_table(table) if r.get("incident_id") == incident_id]

    incident = next((r for r in load_table("incidents") if r["id"] == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident": incident, "ai_result": find_one("ai_results"), "risk": find_one("risk_results"),
        "threat": find_one("threat_analysis"), "recommendations": find_all("incident_recommendations"),
        "narrative": find_one("ai_narratives"), "report": find_one("incident_reports"),
    }


@app.get("/api/dashboard")
async def dashboard():
    incidents = load_table("incidents")
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in incidents:
        sev = i.get("_last_severity")
        if sev in counts:
            counts[sev] += 1
    org_history = load_table("organizational_security_scores")
    return {
        "total_incidents": len(incidents), "severity_counts": counts,
        "latest_org_score": org_history[-1] if org_history else None,
    }


@app.get("/api/org-score")
async def org_score():
    history = load_table("organizational_security_scores")
    return {"latest": history[-1] if history else None, "history": history}


@app.get("/api/archive")
async def list_archive():
    return load_table("report_archives")


@app.get("/api/archive/{archive_id}")
async def get_archive(archive_id: str):
    record = next((r for r in load_table("report_archives") if r["id"] == archive_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Archive record not found")
    stored = (FILES_DIR / record["key"]).read_bytes()
    current_hash = sha256_of_bytes(stored)
    return {**record, "integrity_ok": current_hash == record["sha256"], "current_sha256": current_hash}


@app.get("/api/archive/{archive_id}/download")
async def download_archive(archive_id: str):
    record = next((r for r in load_table("report_archives") if r["id"] == archive_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Archive record not found")
    return FileResponse(FILES_DIR / record["key"], media_type=record["content_type"], filename=record["filename"])


@app.get("/health")
async def health():
    return {"status": "ok", "time": now_iso()}


@app.get("/")
async def root():
    return {
        "service": "SentriX Test Environment API — Full AI-cycle simulator",
        "try_this_first": "POST /api/test/generate-incident?mode=full&incident_type=ransomware",
        "endpoints": [
            "POST /api/incidents", "POST /api/test/generate-incident?mode=full|manual&incident_type=...",
            "POST /api/incidents/from-pdf", "GET /api/incidents", "GET /api/incidents/{id}",
            "GET /api/dashboard", "GET /api/org-score", "GET /api/archive",
            "GET /api/archive/{id}", "GET /api/archive/{id}/download", "GET /health",
        ],
    }
