import os
import json
from functools import wraps

from flask import Flask, request, jsonify, Response
import firebase_admin
from firebase_admin import auth, firestore, credentials
from google import genai
from scanner.target import validate_target_url
from scanner.job import ScanJob
from scanner.engine import run_assessment
import threading
import time

app = Flask(__name__)

_public_scan_hits = {}  # {ip: [timestamps]} in-memory rate limit for anonymous scans
_user_action_hits = {}  # {(uid, action): [timestamps]} in-memory rate limit for logged-in users


# ============================================================
# FIREBASE ADMIN
# ============================================================

if not firebase_admin._apps:
    service_account_data = None

    # Try Render Environment Variable
    service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")

    if service_account_json:
        try:
            service_account_data = json.loads(service_account_json)

            # Handle accidentally double-encoded JSON
            if isinstance(service_account_data, str):
                service_account_data = json.loads(service_account_data)

        except (json.JSONDecodeError, TypeError):
            service_account_data = None

    # Try Render Secret File if environment variable failed
    if service_account_data is None:
        secret_file = "/etc/secrets/firebase-service-account.json"

        if os.path.exists(secret_file):
            try:
                with open(secret_file, "r") as f:
                    service_account_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                service_account_data = None

    if service_account_data is None:
        raise RuntimeError(
            "Firebase service account credentials could not be loaded."
        )

    cred = credentials.Certificate(service_account_data)
    firebase_admin.initialize_app(cred)

db = firestore.client()


# ============================================================
# GEMINI
# ============================================================

gemini = (
    genai.Client(
        api_key=os.environ["GEMINI_API_KEY"]
    )
    if os.environ.get("GEMINI_API_KEY")
    else None
)

MODEL = os.environ.get(
    "GEMINI_MODEL",
    "gemini-2.5-flash"
)

# ============================================================
# PAYMENTS (UPI - manually verified, no gateway integration yet)
# ============================================================

UPI_ID = os.environ.get("UPI_ID", "your-upi-id@bank")
UPI_PAYEE_NAME = os.environ.get("UPI_PAYEE_NAME", "CyberLens AI")
PRO_PLAN_AMOUNT = os.environ.get("PRO_PLAN_AMOUNT", "499")

CATEGORY_CONTEXT = {
    "web": (
        "Focus area: Web Applications. Consider OWASP Top 10 style risks "
        "(injection, broken auth, access control, misconfiguration, "
        "outdated components, security headers, TLS/transport security)."
    ),
    "mobile": (
        "Focus area: Mobile Applications (iOS & Android). Consider risks "
        "such as insecure local storage, weak API/backend communication, "
        "improper platform permission usage, hardcoded secrets, weak "
        "certificate/SSL pinning, and insecure inter-app communication. "
        "Reference relevant OWASP Mobile Top 10 categories where useful."
    ),
    "cloud": (
        "Focus area: Cloud & Infrastructure (AWS/Azure/GCP or similar). "
        "Consider risks such as misconfigured storage buckets/permissions, "
        "overly broad IAM roles, exposed management ports/services, "
        "missing encryption at rest/in transit, insecure default "
        "configurations, and logging/monitoring gaps."
    ),
    "code": (
        "Focus area: Source Code Review. Consider secure coding risks such "
        "as injection flaws, insecure deserialization, hardcoded secrets/"
        "credentials, unsafe dependency usage, improper input validation, "
        "and insecure error handling. Reference safe coding patterns and "
        "what a manual code review checklist should include."
    ),
}


# ============================================================
# FRONTEND
# ============================================================

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberLens AI — AI-Powered Security Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@500;600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<style>

:root{
    --bg:#050a13;
    --bg-soft:#081120;
    --surface:#0b1523;
    --surface-2:#101d30;
    --border:#1c2f48;
    --border-soft:#16253a;
    --text:#eef4ff;
    --text-muted:#8ea0bd;
    --text-dim:#5f7290;
    --accent:#4b8bff;
    --accent-2:#8b5cf6;
    --accent-soft:rgba(75,139,255,.12);
    --success:#34d399;
    --warning:#fbbf24;
    --danger:#f87171;
    --radius-lg:26px;
    --radius-md:16px;
    --radius-sm:10px;
    --shadow-lg:0 24px 60px -12px rgba(0,0,0,.55);
}

*{box-sizing:border-box}

html{scroll-behavior:smooth}

body{
    margin:0;
    font-family:'Inter',system-ui,sans-serif;
    background:
        radial-gradient(900px 500px at 85% -10%,rgba(139,92,246,.16),transparent 60%),
        radial-gradient(700px 420px at 5% 10%,rgba(75,139,255,.14),transparent 55%),
        var(--bg);
    color:var(--text);
    -webkit-font-smoothing:antialiased;
}

h1,h2,h3,h4{
    font-family:'Sora',system-ui,sans-serif;
    margin:0;
    letter-spacing:-.01em;
}

p{color:var(--text-muted);line-height:1.65;margin:0}

code,.mono{font-family:'JetBrains Mono',monospace}

a{color:inherit}

.wrap{max-width:1180px;margin:0 auto;padding:0 24px}

.hidden{display:none !important}

.muted{color:var(--text-dim);font-size:13px}

/* ---------- Buttons ---------- */

button,.btn{
    font-family:'Inter',sans-serif;
    border:0;
    cursor:pointer;
    font-weight:600;
    font-size:14.5px;
    transition:transform .15s ease,box-shadow .15s ease,background .15s ease,border-color .15s ease;
}

.btn-primary{
    background:linear-gradient(135deg,var(--accent),var(--accent-2));
    color:#fff;
    padding:14px 24px;
    border-radius:12px;
    box-shadow:0 10px 30px -8px rgba(75,139,255,.55);
}

.btn-primary:hover{transform:translateY(-2px);box-shadow:0 16px 36px -8px rgba(75,139,255,.65)}

.btn-primary:disabled{opacity:.6;cursor:not-allowed;transform:none}

.btn-ghost{
    background:var(--surface-2);
    color:var(--text);
    border:1px solid var(--border);
    padding:13px 22px;
    border-radius:12px;
}

.btn-ghost:hover{border-color:var(--accent);color:#fff}

.btn-sm{padding:9px 16px;font-size:13px;border-radius:9px}

.btn-full{width:100%}

/* ---------- Nav ---------- */

.nav{
    position:sticky;top:0;z-index:40;
    background:rgba(5,10,19,.78);
    backdrop-filter:blur(14px);
    border-bottom:1px solid var(--border-soft);
}

.nav-inner{
    display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:16px 24px;max-width:1180px;margin:0 auto;
}

.brand{display:flex;align-items:center;gap:9px;font-family:'Sora';font-weight:700;font-size:19px;min-width:0;flex-shrink:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

.brand svg{flex-shrink:0}

.brand span.hl{background:linear-gradient(90deg,var(--accent),var(--accent-2));-webkit-background-clip:text;color:transparent}

.nav-links{display:flex;gap:32px;align-items:center;flex-shrink:0}

.nav-links a{color:var(--text-muted);text-decoration:none;font-size:14px;font-weight:500}

.nav-links a:hover{color:var(--text)}

.nav-cta{display:flex;gap:8px;align-items:center;flex-shrink:0}

@media(max-width:820px){.nav-links{display:none}}

@media(max-width:480px){
    .nav-inner{padding:13px 16px}
    .brand{font-size:15px;gap:7px}
    .brand svg{width:21px;height:21px}
    .nav-cta .btn-sm{padding:9px 12px;font-size:12.5px;white-space:nowrap}
}

/* ---------- Hero ---------- */

.hero{
    display:grid;grid-template-columns:1.05fr .95fr;gap:56px;
    align-items:center;padding:88px 0 76px;
}

.pill{
    display:inline-flex;align-items:center;gap:8px;
    font-size:12.5px;font-weight:600;color:var(--text-muted);
    background:var(--surface-2);border:1px solid var(--border);
    padding:7px 14px;border-radius:99px;
}

.pill .dot{width:6px;height:6px;border-radius:50%;background:var(--success);box-shadow:0 0 0 3px rgba(52,211,153,.18)}

.hero h1{font-size:52px;line-height:1.08;margin:20px 0 18px}

.hero h1 .grad{background:linear-gradient(90deg,var(--accent),var(--accent-2));-webkit-background-clip:text;color:transparent}

.hero p.lead{font-size:17px;max-width:480px;margin-bottom:30px}

.hero-actions{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:34px}

.trust-row{display:flex;gap:22px;flex-wrap:wrap;align-items:center}

.trust-row .item{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-dim)}

.live-counter{
    display:flex;align-items:center;gap:10px;margin-top:18px;
    font-size:13px;color:var(--text-muted);
}

.live-counter b{color:var(--text);font-family:'Sora';font-size:16px}

.live-dot{
    width:8px;height:8px;border-radius:50%;background:var(--success);
    box-shadow:0 0 0 4px rgba(52,211,153,.15);flex-shrink:0;
    animation:pulse-dot 2s ease-in-out infinite;
}

@keyframes pulse-dot{
    0%,100%{opacity:1}
    50%{opacity:.4}
}

/* Hero visual: mock report card */

.report-card{
    background:linear-gradient(160deg,var(--surface),var(--surface-2));
    border:1px solid var(--border);
    border-radius:var(--radius-lg);
    padding:22px;
    box-shadow:var(--shadow-lg);
    position:relative;
}

.report-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}

.report-head .url{font-size:13px;color:var(--text-muted);font-family:'JetBrains Mono'}

.status-chip{
    font-size:11px;font-weight:700;padding:5px 10px;border-radius:99px;
    background:rgba(52,211,153,.14);color:var(--success);border:1px solid rgba(52,211,153,.3);
}

.report-score{
    display:flex;align-items:baseline;gap:10px;margin:6px 0 18px;
}

.report-score .num{font-family:'Sora';font-size:44px;font-weight:800}

.finding-row{
    display:flex;align-items:center;gap:12px;
    padding:12px 0;border-top:1px solid var(--border-soft);
    font-size:13.5px;
}

.finding-row:first-of-type{border-top:none}

.sev-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

.sev-high{background:var(--danger)}

.sev-med{background:var(--warning)}

.sev-low{background:var(--accent)}

.finding-row .label{flex:1;color:var(--text)}

.finding-row .tag{font-size:11px;color:var(--text-dim);font-family:'JetBrains Mono'}

@media(max-width:900px){
    .hero{grid-template-columns:1fr;padding:52px 0 44px}
    .hero h1{font-size:37px}
}

/* ---------- Sections ---------- */

.section{padding:74px 0}

.section-head{max-width:560px;margin-bottom:44px}

.section-tag{color:var(--accent);font-size:13px;font-weight:700;margin-bottom:10px;display:block}

.section-head h2{font-size:32px;line-height:1.2;margin-bottom:12px}

.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}

.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}

@media(max-width:900px){.grid-3,.grid-4{grid-template-columns:1fr}}

.feature-card{
    background:var(--surface);border:1px solid var(--border-soft);
    border-radius:var(--radius-md);padding:26px;
}

.feature-icon{
    width:42px;height:42px;border-radius:11px;
    background:var(--accent-soft);display:grid;place-items:center;
    color:var(--accent);margin-bottom:16px;
}

.feature-card h3{font-size:17px;margin-bottom:8px}

.feature-card p{font-size:14px}

.step{display:flex;gap:18px;align-items:flex-start}

.step-num{
    width:34px;height:34px;border-radius:9px;flex-shrink:0;
    background:var(--surface-2);border:1px solid var(--border);
    display:grid;place-items:center;font-family:'Sora';font-weight:700;font-size:14px;color:var(--accent);
}

.step h4{font-size:15.5px;margin-bottom:5px}

.step p{font-size:13.5px}

.steps-row{display:grid;grid-template-columns:repeat(3,1fr);gap:28px}

@media(max-width:900px){.steps-row{grid-template-columns:1fr;gap:22px}}

.compare-table{
    background:var(--surface);border:1px solid var(--border-soft);
    border-radius:var(--radius-md);overflow:hidden;
}

.compare-row{
    display:grid;grid-template-columns:1fr 1.3fr 1.3fr;gap:16px;
    padding:16px 22px;border-top:1px solid var(--border-soft);
    font-size:13.5px;align-items:center;color:var(--text-muted);
}

.compare-row:first-child{border-top:none}

.compare-row div:first-child{font-weight:700;color:var(--text);font-size:13px}

.compare-head{background:var(--bg-soft);font-family:'Sora';font-weight:700;color:var(--text);font-size:13px}

.compare-row .hl-col{color:#cfe1ff;font-weight:600}

.compare-head .hl-col{color:var(--accent)}

@media(max-width:700px){
    .compare-row{grid-template-columns:1fr;gap:4px;padding:16px}
    .compare-row div:first-child{color:var(--accent);margin-bottom:2px}
}

.cta-band{
    margin:20px 0 0;
    background:linear-gradient(135deg,rgba(75,139,255,.14),rgba(139,92,246,.14));
    border:1px solid var(--border);
    border-radius:var(--radius-lg);
    padding:48px;
    display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap;
}

.cta-band h3{font-size:24px;margin-bottom:6px}

footer{border-top:1px solid var(--border-soft);padding:36px 0;margin-top:40px}

.footer-row{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px}

.footer-row .disclaimer{font-size:12.5px;color:var(--text-dim);max-width:520px}

/* ---------- Auth ---------- */

.auth-shell{
    min-height:calc(100vh - 73px);
    display:grid;place-items:center;
    padding:60px 20px;
}

.auth-card{
    width:100%;max-width:420px;
    background:var(--surface);border:1px solid var(--border);
    border-radius:var(--radius-lg);padding:36px 32px;
    box-shadow:var(--shadow-lg);
}

.auth-icon{
    width:48px;height:48px;border-radius:13px;
    background:linear-gradient(135deg,var(--accent),var(--accent-2));
    display:grid;place-items:center;margin-bottom:18px;
}

.auth-card h2{font-size:23px;margin-bottom:6px}

.auth-card p.sub{font-size:13.5px;margin-bottom:24px}

.field-label{font-size:12.5px;font-weight:600;color:var(--text-muted);margin:0 0 6px 2px;display:block}

input,textarea,select{
    width:100%;background:var(--bg-soft);
    border:1px solid var(--border);border-radius:11px;
    color:var(--text);padding:13px 14px;margin:0 0 16px;
    font:inherit;font-size:14.5px;outline:none;
    transition:border-color .15s ease,box-shadow .15s ease;
}

input:focus,textarea:focus,select:focus{
    border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);
}

.auth-actions{display:flex;gap:10px;margin-top:4px}

#msg{color:var(--danger);font-size:13.5px;min-height:18px;margin-top:12px}

/* ---------- App / Dashboard ---------- */

.app-topbar{
    display:flex;justify-content:space-between;align-items:center;
    padding:18px 0;border-bottom:1px solid var(--border-soft);margin-bottom:28px;
}

.app-topbar h2{font-size:19px}

.who-row{display:flex;align-items:center;gap:10px;margin-top:3px}

.avatar{
    width:28px;height:28px;border-radius:50%;
    background:linear-gradient(135deg,var(--accent),var(--accent-2));
    display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff;
}

.dash-grid{display:grid;grid-template-columns:1.4fr 1fr;gap:22px;padding-bottom:60px}

@media(max-width:980px){.dash-grid{grid-template-columns:1fr}}

.panel{
    background:var(--surface);border:1px solid var(--border-soft);
    border-radius:var(--radius-md);padding:24px;margin-bottom:20px;
}

.panel-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;gap:14px}

.panel-head h3{font-size:17px;margin-bottom:4px}

.panel-head p{font-size:13px}

.eyebrow{
    font-size:11.5px;font-weight:700;color:var(--accent);
    display:block;margin-bottom:6px;
}

.quick-checks{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:2px 0 14px}

.cat-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}

.cat-tab{
    background:var(--bg-soft);border:1px solid var(--border);
    color:var(--text-muted);border-radius:10px;padding:9px 14px;
    font-size:13px;font-weight:600;cursor:pointer;transition:.15s ease;
}

.cat-tab:hover{border-color:var(--accent);color:var(--text)}

.cat-tab.active{
    background:var(--accent-soft);border-color:var(--accent);color:#cfe1ff;
}

.quick-btn{
    background:var(--surface-2);border:1px solid var(--border);
    color:#b9cdf0;border-radius:99px;padding:8px 13px;
    font-size:12px;font-weight:600;cursor:pointer;transition:.15s ease;
}

.quick-btn:hover{border-color:var(--accent);color:#fff;background:var(--accent-soft)}

.input-meta{
    display:flex;justify-content:space-between;align-items:center;gap:12px;
    margin:-8px 0 16px;color:var(--text-dim);font-size:12px;
}

#charCount{font-family:'JetBrains Mono';font-variant-numeric:tabular-nums;white-space:nowrap}

.clear-btn{
    background:transparent;border:1px solid var(--border);
    border-radius:8px;color:var(--text-muted);padding:6px 11px;
    font-size:11.5px;font-weight:600;
}

.clear-btn:hover{border-color:var(--danger);color:var(--danger)}

.analyze-row{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:4px}

#out{margin-top:16px}

#out pre{
    white-space:pre-wrap;line-height:1.65;background:var(--bg-soft);
    border:1px solid var(--border-soft);border-radius:14px;
    padding:18px;color:#dce7fb;font-size:13.5px;font-family:'Inter';margin:0;
}

.exec-card{
    margin-top:10px;background:var(--accent-soft);border:1px solid rgba(75,139,255,.3);
    border-radius:14px;padding:16px;font-size:13.5px;line-height:1.6;color:#dce7fb;
}

.finding-ask{margin-top:8px}

.finding-ask textarea{margin:8px 0;min-height:60px;font-size:13px;padding:10px}

.finding-ask-answer{
    margin-top:6px;background:var(--bg-soft);border:1px solid var(--border-soft);
    border-radius:10px;padding:12px;font-size:12.5px;line-height:1.55;color:#cfe1ff;
}

.status-badge{
    padding:5px 11px;border:1px solid var(--border);border-radius:99px;
    color:var(--accent);font-size:10.5px;font-weight:700;
}

.scan-authorization{
    display:flex;align-items:flex-start;gap:10px;
    margin:2px 0 18px;color:var(--text-muted);font-size:13px;
}

.scan-authorization input{width:16px;height:16px;margin:2px 0 0;accent-color:var(--accent);flex-shrink:0}

.scan-controls{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:end}

.scan-progress{
    margin-top:18px;padding:16px;border-radius:14px;
    background:var(--bg-soft);border:1px solid var(--border-soft);
}

.scan-progress-top{
    display:flex;justify-content:space-between;gap:12px;
    margin-bottom:10px;color:var(--text-muted);font-size:12.5px;
}

.scan-progress-bar{height:6px;overflow:hidden;border-radius:99px;background:var(--surface-2)}

#scanProgressFill{
    display:block;width:8%;height:100%;border-radius:inherit;
    background:linear-gradient(90deg,var(--accent),var(--accent-2));
    transition:width .5s ease;
}

#scanIdText{display:block;margin-top:9px;color:var(--text-dim);font-size:11px;font-family:'JetBrains Mono'}

.scan-results{margin-top:16px}

.findings-summary{margin-bottom:6px}

.fs-bar{display:flex;height:8px;border-radius:99px;overflow:hidden;background:var(--surface-2);margin-bottom:12px}

.fs-bar span{display:block;height:100%}

.fs-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--text-muted)}

.fs-legend span{display:flex;align-items:center;gap:6px}

.fs-legend i{width:8px;height:8px;border-radius:50%;display:inline-block}

.scan-finding{
    display:flex;gap:12px;padding:13px 0;
    border-top:1px solid var(--border-soft);font-size:13.5px;
}

.scan-finding:first-child{border-top:none}

.scan-finding .sev-dot{margin-top:5px}

.scan-finding b{display:block;color:var(--text);margin-bottom:2px;font-size:13.5px}

.scan-finding p{font-size:12.5px;margin:0}

.expert-cta{
    margin-top:14px;padding:14px;border-radius:12px;
    background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.25);
    display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;
    font-size:13px;
}

.history-list .item{
    padding:13px 0;border-top:1px solid var(--border-soft);
    color:#c7d5ec;font-size:13px;
}

.history-list .item:first-child{border-top:none}

.account-quick-links{display:flex;flex-direction:column;gap:8px;margin-top:4px}

.account-quick-links .quick-btn{width:100%;text-align:left;border-radius:10px;padding:10px 12px}

.history-list .item b{font-weight:600;color:var(--text);display:block;margin-bottom:3px;font-size:13.5px}

::-webkit-scrollbar{width:9px}

::-webkit-scrollbar-thumb{background:var(--border);border-radius:99px}

.modal-overlay{
    position:fixed;inset:0;z-index:100;
    background:rgba(2,5,12,.72);backdrop-filter:blur(4px);
    display:flex;align-items:center;justify-content:center;padding:20px;
}

.modal-box{
    width:100%;max-width:400px;background:var(--surface);
    border:1px solid var(--border);border-radius:var(--radius-lg);
    padding:28px;position:relative;box-shadow:var(--shadow-lg);
}

.modal-close{
    position:absolute;top:16px;right:16px;background:transparent;
    border:0;color:var(--text-muted);font-size:16px;cursor:pointer;
}

/* ---------- Workspace tabs ---------- */

.workspace-tabs{
    display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 22px;
    border-bottom:1px solid var(--border-soft);padding-bottom:14px;
}

.wtab-btn{
    background:transparent;border:1px solid transparent;
    color:var(--text-muted);border-radius:10px;padding:9px 15px;
    font-size:13.5px;font-weight:600;cursor:pointer;transition:.15s ease;
}

.wtab-btn:hover{color:var(--text);border-color:var(--border)}

.wtab-btn.active{background:var(--accent-soft);border-color:var(--accent);color:#cfe1ff}

.workspace-panel.hidden{display:none}

/* ---------- Readiness dashboard ---------- */

.readiness-grid{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center}

@media(max-width:560px){.readiness-grid{grid-template-columns:1fr}}

.readiness-ring{
    width:112px;height:112px;border-radius:50%;flex-shrink:0;
    display:grid;place-items:center;position:relative;
    background:conic-gradient(var(--accent) calc(var(--pct,0) * 1%),var(--surface-2) 0);
}

.readiness-ring::before{
    content:"";position:absolute;inset:9px;border-radius:50%;background:var(--surface);
}

.readiness-ring b{
    position:relative;font-family:'Sora';font-size:22px;font-weight:800;color:var(--text);
}

.readiness-stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}

.rstat{background:var(--bg-soft);border:1px solid var(--border-soft);border-radius:12px;padding:11px 13px}

.rstat b{display:block;font-family:'Sora';font-size:18px;color:var(--text)}

.rstat span{font-size:11.5px;color:var(--text-dim)}

/* ---------- GRC controls list ---------- */

.control-group-title{
    font-size:12px;font-weight:700;color:var(--accent);text-transform:uppercase;
    letter-spacing:.03em;margin:18px 0 8px;
}

.control-group-title:first-child{margin-top:4px}

.control-row{
    display:flex;justify-content:space-between;align-items:center;gap:12px;
    padding:12px 0;border-top:1px solid var(--border-soft);flex-wrap:wrap;
}

.control-row:first-of-type{border-top:none}

.control-row .ctitle{flex:1;min-width:180px;font-size:13.5px;color:var(--text)}

.control-row .ccode{color:var(--text-dim);font-family:'JetBrains Mono';font-size:11px;display:block;margin-bottom:2px}

.status-select{
    background:var(--bg-soft);border:1px solid var(--border);color:var(--text);
    border-radius:9px;padding:7px 10px;font-size:12px;font-weight:600;
}

.status-select.st-implemented{border-color:var(--success);color:var(--success)}

.status-select.st-partial{border-color:var(--warning);color:var(--warning)}

.status-select.st-not_implemented{border-color:var(--danger);color:var(--danger)}

.status-select.st-na{border-color:var(--text-dim);color:var(--text-dim)}

/* ---------- Risk register ---------- */

.risk-form{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}

.risk-form .full{grid-column:1/-1}

@media(max-width:560px){.risk-form{grid-template-columns:1fr}}

.risk-item{
    display:flex;justify-content:space-between;align-items:flex-start;gap:12px;
    padding:13px 0;border-top:1px solid var(--border-soft);
}

.risk-item:first-of-type{border-top:none}

.risk-item b{display:block;color:var(--text);font-size:13.5px;margin-bottom:3px}

.risk-item p{font-size:12px;margin:0}

.risk-badge{
    flex-shrink:0;padding:6px 11px;border-radius:99px;font-size:11px;font-weight:700;
    white-space:nowrap;
}

.risk-badge.r-low{background:rgba(52,211,153,.14);color:var(--success);border:1px solid rgba(52,211,153,.3)}

.risk-badge.r-medium{background:rgba(251,191,36,.14);color:var(--warning);border:1px solid rgba(251,191,36,.3)}

.risk-badge.r-high{background:rgba(248,113,113,.14);color:var(--danger);border:1px solid rgba(248,113,113,.3)}

.risk-badge.r-critical{background:rgba(248,113,113,.24);color:#ffb4b4;border:1px solid rgba(248,113,113,.5)}

.icon-del{
    background:transparent;border:0;color:var(--text-dim);cursor:pointer;font-size:13px;
    padding:4px 6px;flex-shrink:0;
}

.icon-del:hover{color:var(--danger)}

/* ---------- Remediation & Evidence ---------- */

.task-item{
    display:flex;justify-content:space-between;align-items:flex-start;gap:12px;
    padding:13px 0;border-top:1px solid var(--border-soft);
}

.task-item:first-of-type{border-top:none}

.task-item b{display:block;color:var(--text);font-size:13.5px;margin-bottom:3px}

.task-item .meta{font-size:11.5px;color:var(--text-dim)}

.task-actions{display:flex;gap:6px;flex-shrink:0;align-items:center}

.priority-chip{
    padding:4px 9px;border-radius:99px;font-size:10.5px;font-weight:700;
    border:1px solid var(--border);color:var(--text-muted);
}

.priority-chip.p-high{border-color:var(--danger);color:var(--danger)}

.priority-chip.p-medium{border-color:var(--warning);color:var(--warning)}

.priority-chip.p-low{border-color:var(--success);color:var(--success)}

.evidence-item{
    padding:13px 0;border-top:1px solid var(--border-soft);
    display:flex;justify-content:space-between;align-items:flex-start;gap:12px;
}

.evidence-item:first-of-type{border-top:none}

.evidence-item b{display:block;color:var(--text);font-size:13.5px;margin-bottom:3px}

.evidence-item a{color:var(--accent);font-size:12px;word-break:break-all}

.workspace-empty{color:var(--text-dim);font-size:13px;padding:8px 0}

</style>
</head>

<body>

<nav class="nav">
    <div class="nav-inner">
        <div class="brand">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L4 5.5V11c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5.5L12 2z"
                    fill="url(#g1)" stroke="none"/>
                <path d="M9 12l2 2 4-4" stroke="#050a13" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <defs><linearGradient id="g1" x1="4" y1="2" x2="20" y2="22">
                    <stop stop-color="#4b8bff"/><stop offset="1" stop-color="#8b5cf6"/>
                </linearGradient></defs>
            </svg>
            Cyber<span class="hl">Lens</span> AI
        </div>
        <div class="nav-links">
            <a href="#features">Features</a>
            <a href="#how">How it works</a>
            <a href="#grc">GRC</a>
            <a href="#pricing">Pricing</a>
        </div>
        <div class="nav-cta">
            <button class="btn-ghost btn-sm" onclick="showAuth()">Sign in</button>
            <button class="btn-primary btn-sm" onclick="showAuth()">Get started</button>
        </div>
    </div>
</nav>

<section id="landing">

<div class="wrap hero">
    <div>
        <span class="pill"><span class="dot"></span> AI-powered · Gemini inside</span>
        <h1>Know your website's<br><span class="grad">security posture</span> in minutes</h1>
        <p class="lead">CyberLens AI scans and reasons about your web application the way a security analyst would — surfacing real risks, explaining why they matter, and giving you a clear remediation path.</p>
        <div class="hero-actions">
            <button class="btn-primary" onclick="showAuth()">Start free assessment →</button>
            <button class="btn-ghost" onclick="document.getElementById('how').scrollIntoView({behavior:'smooth'})">See how it works</button>
        </div>
        <div class="trust-row">
            <span class="item">⚡ Results in minutes</span>
            <span class="item">🔒 Authorized scans only</span>
            <span class="item">🧠 Gemini-reasoned findings</span>
        </div>
        <div class="live-counter" id="liveCounter">
            <span class="live-dot"></span>
            <span><b id="liveCounterNum">0</b> vulnerabilities found across real assessments so far</span>
        </div>
    </div>

    <div class="report-card" id="publicScanCard">
        <div class="report-head">
            <span class="url">Try it — no signup needed</span>
            <span class="status-chip" id="publicScanStatus">Ready</span>
        </div>
        <input id="publicScanInput" type="url" placeholder="https://your-website.com" style="margin-bottom:12px">
        <button class="btn-primary btn-full" onclick="runPublicScan()" id="publicScanBtn">Scan free →</button>
        <div id="publicScanResults"></div>
    </div>
</div>

<div class="wrap section" id="features">
    <div class="section-head">
        <span class="section-tag">Features</span>
        <h2>Everything a defensive security review needs</h2>
        <p>Built for founders, developers and small security teams who need a fast, trustworthy read on their own web assets.</p>
    </div>
    <div class="grid-4">
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3.5V11c0 5.2-3.4 9.7-8 11-4.6-1.3-8-5.8-8-11V5.5L12 2z" stroke="currentColor" stroke-width="1.8"/></svg></div>
            <h3>Authorized scanning</h3>
            <p>Target confirmation is required before any assessment runs — built for testing what you own.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 3v3m0 12v3m9-9h-3M6 12H3m14.5-6.5l-2 2m-9 9l-2 2m13-2l-2-2m-9-9l-2-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.8"/></svg></div>
            <h3>AI-reasoned analysis</h3>
            <p>Gemini interprets scan evidence and your questions in plain language, not raw tool output.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M4 19V5m0 14h16M8 15v3m4-7v7m4-11v11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></div>
            <h3>Actionable remediation</h3>
            <p>Every finding comes with practical next steps — what to check, how to test, how to fix it.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 8v4l3 2M12 21a9 9 0 100-18 9 9 0 000 18z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></div>
            <h3>Full history</h3>
            <p>Every analysis and scan is saved to your account so you can track posture over time.</p>
        </div>
    </div>
</div>

<div class="wrap section" id="how">
    <div class="section-head">
        <span class="section-tag">How it works</span>
        <h2>From URL to report in three steps</h2>
    </div>
    <div class="steps-row">
        <div class="step">
            <div class="step-num">1</div>
            <div><h4>Confirm ownership</h4><p>Enter your website and confirm you're authorized to assess it.</p></div>
        </div>
        <div class="step">
            <div class="step-num">2</div>
            <div><h4>We assess it</h4><p>CyberLens inspects your target and collects security-relevant evidence.</p></div>
        </div>
        <div class="step">
            <div class="step-num">3</div>
            <div><h4>Get clear findings</h4><p>Review severity-ranked findings and Gemini-backed remediation guidance.</p></div>
        </div>
    </div>
</div>

<div class="wrap section" id="why-us">
    <div class="section-head">
        <span class="section-tag">Why CyberLens AI</span>
        <h2>"There are so many security tools out there —<br>why this one?"</h2>
        <p>Fair question. Most tools do one job well. CyberLens is built to close the gap between finding an issue and actually knowing what to do about it.</p>
    </div>
    <div class="compare-table">
        <div class="compare-row compare-head">
            <div></div>
            <div>Typical scanners</div>
            <div class="hl-col">CyberLens AI</div>
        </div>
        <div class="compare-row">
            <div>Output format</div>
            <div>Raw technical report you must interpret yourself</div>
            <div class="hl-col">Plain-language findings + why it matters</div>
        </div>
        <div class="compare-row">
            <div>Scope</div>
            <div>Usually one surface (just web, or just code)</div>
            <div class="hl-col">Web, mobile, cloud &amp; source code — one assistant</div>
        </div>
        <div class="compare-row">
            <div>After the scan</div>
            <div>Report ends there — you're on your own</div>
            <div class="hl-col">Ask follow-up questions and get testing steps</div>
        </div>
        <div class="compare-row">
            <div>Remediation</div>
            <div>"Here's what's wrong"</div>
            <div class="hl-col">"Here's what's wrong, and here's how to fix it"</div>
        </div>
        <div class="compare-row">
            <div>Getting started</div>
            <div>Sales calls, demos, enterprise onboarding</div>
            <div class="hl-col">Sign up and scan in under 2 minutes, free</div>
        </div>
    </div>
</div>

<div class="wrap section" id="trust">
    <div class="section-head">
        <span class="section-tag">Why teams use it</span>
        <h2>Built for how security actually gets reviewed</h2>
    </div>
    <div class="grid-4">
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 3v3m0 12v3m9-9h-3M6 12H3m14.5-6.5l-2 2m-9 9l-2 2m13-2l-2-2m-9-9l-2-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.8"/></svg></div>
            <h3>Gemini-backed reasoning</h3>
            <p>Findings are explained in plain language, not raw scanner noise you have to translate yourself.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M9 12l2 2 4-4m5-2v4c0 5-3.4 8.5-8 9.5-4.6-1-8-4.5-8-9.5V8l8-3.5L18 8z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
            <h3>Evidence, not guesses</h3>
            <p>Every finding is backed by what was actually observed on your target during the assessment.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></div>
            <h3>Severity you can prioritize</h3>
            <p>High, medium and low findings are ranked so your team fixes what matters first.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><rect x="4" y="10" width="16" height="10" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8 10V7a4 4 0 018 0v3" stroke="currentColor" stroke-width="1.8"/></svg></div>
            <h3>Your data, your account</h3>
            <p>Scans and analyses are tied to your login only — no public sharing of your results.</p>
        </div>
    </div>
</div>


<div class="wrap section" id="grc">
    <div class="section-head">
        <span class="section-tag">Governance, Risk &amp; Compliance</span>
        <h2>What we actually check, mapped to real frameworks</h2>
        <p>Not marketing copy — this is the literal list of checks CyberLens AI runs, and which framework each one speaks to.</p>
    </div>
    <div class="compare-table grc-table">
        <div class="compare-row compare-head">
            <div>Check category</div>
            <div>What we test</div>
            <div class="hl-col">Framework mapping</div>
        </div>
        <div class="compare-row">
            <div>Transport Security</div>
            <div>HTTPS enforcement, TLS protocol version, certificate expiry</div>
            <div class="hl-col">ISO 27001 A.8.24 · OWASP A02:2021</div>
        </div>
        <div class="compare-row">
            <div>Security Headers</div>
            <div>CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy</div>
            <div class="hl-col">OWASP A05:2021 · ISO 27001 A.8.9</div>
        </div>
        <div class="compare-row">
            <div>Session Management</div>
            <div>Cookie Secure / HttpOnly / SameSite attributes</div>
            <div class="hl-col">OWASP A07:2021</div>
        </div>
        <div class="compare-row">
            <div>Access Control</div>
            <div>CORS policy misconfiguration (wildcard origin + credentials)</div>
            <div class="hl-col">OWASP A01:2021</div>
        </div>
        <div class="compare-row">
            <div>Input Validation <span class="status-badge" style="margin-left:6px;font-size:9px">Active scan</span></div>
            <div>Reflected input / potential XSS, database error disclosure</div>
            <div class="hl-col">OWASP A03:2021 · CWE-79 / CWE-89</div>
        </div>
        <div class="compare-row">
            <div>Configuration</div>
            <div>Directory listing, exposed .env / .git files</div>
            <div class="hl-col">OWASP A05:2021 · CWE-538</div>
        </div>
        <div class="compare-row">
            <div>Information Disclosure</div>
            <div>Server/framework version banners</div>
            <div class="hl-col">ISO 27001 A.5.7</div>
        </div>
    </div>
    <p class="muted" style="margin-top:18px;font-size:12px">CyberLens AI provides technical security findings to support your compliance process — it does not issue certifications or replace a formal audit.</p>
</div>

<div class="wrap section" id="pricing">
    <div class="section-head">
        <span class="section-tag">Pricing</span>
        <h2>Start free, upgrade for AI-powered fixes &amp; reporting</h2>
        <p>Simple pricing, no sales calls needed to get started.</p>
    </div>
    <div class="grid-3">
        <div class="feature-card">
            <h3>Free</h3>
            <p style="margin:6px 0 18px">For individuals testing their own sites.</p>
            <div style="font-family:'Sora';font-size:32px;font-weight:800;margin-bottom:18px">₹0</div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Passive website assessments</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Web, mobile, cloud &amp; code AI guidance</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Ask AI about any finding</span></div>
            <div class="step" style="margin-bottom:18px"><span class="muted">✓ Full scan &amp; analysis history</span></div>
            <button class="btn-ghost btn-full" onclick="showAuth()">Get started</button>
        </div>
        <div class="feature-card" style="border-color:var(--accent);position:relative">
            <span class="status-badge" style="position:absolute;top:22px;right:22px">Most popular</span>
            <h3>Pro</h3>
            <p style="margin:6px 0 18px">For developers who want fixes, not just findings.</p>
            <div style="font-family:'Sora';font-size:32px;font-weight:800;margin-bottom:18px">₹499<span class="muted" style="font-size:14px;font-weight:600">/mo</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Everything in Free</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ AI Auto-Fix for source code</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Executive summary reports</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Downloadable PDF reports</span></div>
            <div class="step" style="margin-bottom:18px"><span class="muted">✓ Public verified security badge</span></div>
            <button class="btn-primary btn-full" onclick="openUpiModal()">Upgrade to Pro — ₹499/mo</button>
        </div>
        <div class="feature-card">
            <h3>Agency</h3>
            <p style="margin:6px 0 18px">For teams managing multiple client sites.</p>
            <div style="font-family:'Sora';font-size:32px;font-weight:800;margin-bottom:18px">Contact us</div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Everything in Pro</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ Multiple client sites, one account</span></div>
            <div class="step" style="margin-bottom:10px"><span class="muted">✓ White-labelled reports</span></div>
            <div class="step" style="margin-bottom:18px"><span class="muted">✓ API access</span></div>
            <button class="btn-ghost btn-full" onclick="showAuth()">Get started</button>
        </div>
    </div>
</div>

<div class="wrap">
    <div class="cta-band">
        <div>
            <h3>Run your first assessment for free</h3>
            <p>No credit card. Just sign up and scan a site you're authorized to test.</p>
        </div>
        <button class="btn-primary" onclick="showAuth()">Get started →</button>
    </div>
</div>

<footer>
    <div class="wrap footer-row">
        <div class="brand" style="font-size:15px">🛡️ CyberLens AI</div>
        <p class="disclaimer">For authorized, defensive security testing only. Only assess assets you own or have explicit permission to test.</p>
    </div>
</footer>

</section>


<section id="auth" class="hidden">
<div class="auth-shell">
<div class="auth-card">
    <div class="auth-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3.5V11c0 5.2-3.4 9.7-8 11-4.6-1.3-8-5.8-8-11V5.5L12 2z" fill="#fff"/></svg>
    </div>
    <h2>Welcome to CyberLens AI</h2>
    <p class="sub">Sign in to keep your private security analysis history.</p>

    <button class="btn-ghost btn-full" onclick="googleSignIn()" style="display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:10px">
        <svg width="16" height="16" viewBox="0 0 48 48"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.4 29.3 35 24 35c-6.1 0-11-4.9-11-11s4.9-11 11-11c2.8 0 5.3 1 7.3 2.7l6-6C33.5 6.5 29 4.5 24 4.5 12.7 4.5 3.5 13.7 3.5 25S12.7 45.5 24 45.5 44.5 36.3 44.5 25c0-1.5-.2-3-.9-4.5z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.6 16 19 13 24 13c2.8 0 5.3 1 7.3 2.7l6-6C33.5 6.5 29 4.5 24 4.5c-7.6 0-14.1 4.3-17.7 10.2z"/><path fill="#4CAF50" d="M24 45.5c5 0 9.5-1.9 12.9-5l-6.3-5.3C28.6 36.4 26.4 37 24 37c-5.3 0-9.7-3.6-11.3-8.4l-6.5 5C9.8 40.9 16.4 45.5 24 45.5z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.3-2.3 4.3-4.2 5.7l6.3 5.3C39.9 37.4 44.5 32.1 44.5 25c0-1.5-.2-3-.9-4.5z"/></svg>
        Continue with Google
    </button>

    <button class="btn-ghost btn-full" onclick="githubSignIn()" style="display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:16px;background:#161b22;border-color:#30363d;color:#fff">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="#fff"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
        Continue with GitHub
    </button>

    <div style="display:flex;align-items:center;gap:10px;margin:16px 0;color:var(--text-dim);font-size:12px">
        <div style="flex:1;height:1px;background:var(--border)"></div>
        or use email
        <div style="flex:1;height:1px;background:var(--border)"></div>
    </div>

    <label class="field-label" for="email">Email address</label>
    <input id="email" type="email" placeholder="you@company.com">

    <label class="field-label" for="pw">Password</label>
    <input id="pw" type="password" placeholder="6+ characters">

    <div class="auth-actions">
        <button class="btn-ghost btn-full" onclick="signup()">Create account</button>
        <button class="btn-primary btn-full" onclick="login()">Sign in</button>
    </div>

    <p id="msg"></p>
</div>
</div>
</section>


<section id="app" class="hidden">
<div class="wrap">

    <div class="app-topbar">
        <div>
            <h2>AI Security Assistant</h2>
            <div class="who-row">
                <span class="avatar">🛡️</span>
                <span class="muted" id="who"></span>
            </div>
        </div>
        <button class="btn-ghost btn-sm" onclick="logout()">Sign out</button>
    </div>

    <div class="workspace-tabs" id="workspaceTabs">
        <button type="button" class="wtab-btn active" data-wtab="security" onclick="setWorkspaceTab('security')">🛡️ Security</button>
        <button type="button" class="wtab-btn" data-wtab="grc" onclick="setWorkspaceTab('grc')">📋 GRC</button>
        <button type="button" class="wtab-btn" data-wtab="remediation" onclick="setWorkspaceTab('remediation')">🛠️ Remediation</button>
        <button type="button" class="wtab-btn" data-wtab="evidence" onclick="setWorkspaceTab('evidence')">📁 Evidence</button>
        <button type="button" class="wtab-btn" data-wtab="history" onclick="setWorkspaceTab('history')">🕓 History</button>
    </div>

    <div id="wtab-security" class="workspace-panel">
    <div class="dash-grid">

        <div>
            <div class="panel">
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">Ask CyberLens</span>
                        <h3>Describe a security scenario</h3>
                        <p>Get manual testing methodology, evidence to collect and remediation guidance.</p>
                    </div>
                </div>

                <div class="cat-tabs" id="catTabs">
                    <button type="button" class="cat-tab active" data-cat="web" onclick="setCategory('web')">🌐 Web</button>
                    <button type="button" class="cat-tab" data-cat="mobile" onclick="setCategory('mobile')">📱 Mobile</button>
                    <button type="button" class="cat-tab" data-cat="cloud" onclick="setCategory('cloud')">☁️ Cloud</button>
                    <button type="button" class="cat-tab" data-cat="code" onclick="setCategory('code')">📄 Source code</button>
                </div>

                <textarea id="q" rows="6" placeholder="Example: How should I manually test a web app for broken access control in an authorized lab?"></textarea>

                <div class="quick-checks" id="quickChecks">
                    <span class="muted">Quick checks</span>
                    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for SQL Injection in an authorized lab?'">SQL Injection</button>
                    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for Cross-Site Scripting (XSS) in an authorized lab?'">XSS</button>
                    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for Broken Access Control in an authorized lab?'">Access Control</button>
                    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I review security headers of an authorized web application?'">Security Headers</button>
                </div>

                <div class="input-meta">
                    <span class="input-hint">Ctrl + Enter to analyze</span>
                    <div class="input-actions" style="display:flex;align-items:center;gap:10px">
                        <span id="charCount">0 / 2000</span>
                        <button type="button" class="clear-btn" onclick="clearPrompt()">Clear</button>
                    </div>
                </div>

                <div class="panel hidden" id="autofixPanel" style="background:var(--bg-soft);border-color:var(--border-soft);margin-top:4px">
                    <div class="panel-head">
                        <div>
                            <span class="eyebrow">Pro feature</span>
                            <h3 style="font-size:15px">🔧 AI Auto-Fix</h3>
                            <p>Paste a code snippet and get a corrected, more secure version.</p>
                        </div>
                    </div>
                    <textarea id="fixCode" rows="6" placeholder="Paste the code you want reviewed and fixed..." style="font-family:'JetBrains Mono';font-size:12.5px"></textarea>
                    <button type="button" class="btn-primary btn-full" onclick="generateFix()">Generate secure fix →</button>
                    <div id="fixResult"></div>
                </div>


                <div class="analyze-row">
                    <span class="muted">Authorized / defensive testing only</span>
                    <button class="btn-primary" onclick="analyze()">Analyze with Gemini</button>
                </div>

                <div id="out"></div>
            </div>

            <div class="panel">
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">Security assessment</span>
                        <h3>Scan an authorized website</h3>
                        <p>Assess your website for security weaknesses and configuration risks.</p>
                    </div>
                    <span class="status-badge" id="scanReadyBadge">Ready</span>
                </div>

                <label class="field-label" for="scanTarget">Target website</label>
                <input id="scanTarget" type="url" placeholder="https://your-authorized-website.com" autocomplete="url">

                <label class="scan-authorization">
                    <input type="checkbox" id="scanAuthorized">
                    <span>I confirm that I am authorized to assess this website.</span>
                </label>

                <div class="scan-controls">
                    <div>
                        <label class="field-label" for="scanProfile">Scan profile</label>
                        <select id="scanProfile">
                            <option value="passive">Passive assessment</option>
                            <option value="safe_active">Safe active assessment</option>
                        </select>
                    </div>
                    <button type="button" class="btn-primary" onclick="startSecurityScan()">Start scan →</button>
                </div>

                <div id="scanStatus" class="scan-progress" hidden>
                    <div class="scan-progress-top">
                        <span id="scanStatusLabel">Initializing assessment</span>
                        <span id="scanStatusText">Queued</span>
                    </div>
                    <div class="scan-progress-bar"><span id="scanProgressFill"></span></div>
                    <small id="scanIdText"></small>
                    <div id="scanResults" class="scan-results"></div>
                </div>
            </div>
        </div>

        <div>
            <div class="panel">
                <div class="panel-head">
                    <div>
                        <span class="eyebrow">Your account</span>
                        <h3 id="planTitle" style="font-size:16px">Free plan</h3>
                        <p id="planDesc">10 scans &amp; 30 AI requests per hour.</p>
                    </div>
                </div>
                <div class="account-quick-links">
                    <button type="button" class="quick-btn" onclick="setCategory('code');document.getElementById('q').scrollIntoView({behavior:'smooth'})">🔧 Source code review</button>
                    <button type="button" class="quick-btn" onclick="openUpiModal()">⭐ Upgrade to Pro</button>
                    <button type="button" class="quick-btn" onclick="document.getElementById('scanTarget').scrollIntoView({behavior:'smooth'})">🛰️ New scan</button>
                </div>
            </div>

        </div>

    </div>
    </div>

    <div id="wtab-grc" class="workspace-panel hidden">

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">GRC readiness</span>
                    <h3>Compliance dashboard</h3>
                    <p>ISO control coverage and open risk overview for your organization.</p>
                </div>
            </div>
            <div id="grcReadiness">
                <p class="muted">Loading readiness…</p>
            </div>
        </div>

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">ISO 27001 controls</span>
                    <h3>Control status</h3>
                    <p>Mark each control's implementation status. Changes save automatically.</p>
                </div>
            </div>
            <div id="grcControls">
                <p class="muted">Loading controls…</p>
            </div>
        </div>

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">Risk register</span>
                    <h3>Add a risk</h3>
                    <p>Score = likelihood × impact.</p>
                </div>
            </div>
            <div class="risk-form">
                <div class="full">
                    <label class="field-label" for="riskTitle">Risk title</label>
                    <input id="riskTitle" type="text" placeholder="e.g. Unpatched public-facing server">
                </div>
                <div>
                    <label class="field-label" for="riskLikelihood">Likelihood (1-5)</label>
                    <select id="riskLikelihood">
                        <option value="1">1 - Rare</option>
                        <option value="2">2 - Unlikely</option>
                        <option value="3" selected>3 - Possible</option>
                        <option value="4">4 - Likely</option>
                        <option value="5">5 - Almost certain</option>
                    </select>
                </div>
                <div>
                    <label class="field-label" for="riskImpact">Impact (1-5)</label>
                    <select id="riskImpact">
                        <option value="1">1 - Negligible</option>
                        <option value="2">2 - Minor</option>
                        <option value="3" selected>3 - Moderate</option>
                        <option value="4">4 - Major</option>
                        <option value="5">5 - Severe</option>
                    </select>
                </div>
                <div class="full">
                    <label class="field-label" for="riskDesc">Description (optional)</label>
                    <input id="riskDesc" type="text" placeholder="Short context for this risk">
                </div>
            </div>
            <button type="button" class="btn-primary" onclick="addRisk()">Add to risk register →</button>
            <div id="riskList" style="margin-top:14px">
                <p class="muted">Loading risk register…</p>
            </div>
        </div>

    </div>

    <div id="wtab-remediation" class="workspace-panel hidden">

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">Remediation</span>
                    <h3>Add a task</h3>
                    <p>Track fixes through to closure.</p>
                </div>
            </div>
            <div class="risk-form">
                <div class="full">
                    <label class="field-label" for="taskTitle">Task title</label>
                    <input id="taskTitle" type="text" placeholder="e.g. Patch CVE-2024-xxxx on prod server">
                </div>
                <div>
                    <label class="field-label" for="taskPriority">Priority</label>
                    <select id="taskPriority">
                        <option value="low">Low</option>
                        <option value="medium" selected>Medium</option>
                        <option value="high">High</option>
                    </select>
                </div>
                <div>
                    <label class="field-label" for="taskDue">Due date (optional)</label>
                    <input id="taskDue" type="date">
                </div>
                <div class="full">
                    <label class="field-label" for="taskDesc">Notes (optional)</label>
                    <input id="taskDesc" type="text" placeholder="Owner, ticket link, extra context">
                </div>
            </div>
            <button type="button" class="btn-primary" onclick="addRemediationTask()">Add task →</button>
            <div id="taskList" style="margin-top:14px">
                <p class="muted">Loading tasks…</p>
            </div>
        </div>

    </div>

    <div id="wtab-evidence" class="workspace-panel hidden">

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">Evidence center</span>
                    <h3>Add evidence</h3>
                    <p>Link screenshots, reports or documents that support a control or finding.</p>
                </div>
            </div>
            <div class="risk-form">
                <div class="full">
                    <label class="field-label" for="evTitle">Title</label>
                    <input id="evTitle" type="text" placeholder="e.g. Firewall rule review — Sept 2026">
                </div>
                <div class="full">
                    <label class="field-label" for="evLink">Link (optional)</label>
                    <input id="evLink" type="url" placeholder="https://drive.google.com/...">
                </div>
                <div class="full">
                    <label class="field-label" for="evDesc">Description (optional)</label>
                    <input id="evDesc" type="text" placeholder="What this evidence shows">
                </div>
            </div>
            <button type="button" class="btn-primary" onclick="addEvidence()">Save evidence →</button>
            <div id="evidenceList" style="margin-top:14px">
                <p class="muted">Loading evidence…</p>
            </div>
        </div>

    </div>

    <div id="wtab-history" class="workspace-panel hidden">

        <div class="panel">
            <div class="panel-head">
                <div>
                    <span class="eyebrow">Activity</span>
                    <h3>Recent analyses</h3>
                </div>
            </div>
            <div id="hist" class="history-list muted">No analyses yet.</div>
        </div>

    </div>

</div>
</section>


<div id="upiModal" class="modal-overlay hidden">
    <div class="modal-box">
        <button type="button" class="modal-close" onclick="closeUpiModal()">✕</button>
        <span class="eyebrow">Upgrade to Pro</span>
        <h3 style="margin-bottom:4px">Pay via UPI</h3>
        <p class="muted" style="margin-bottom:16px">Scan the QR or pay to the UPI ID below, then submit your transaction reference so we can activate Pro on your account.</p>

        <div id="upiQrBox" style="text-align:center;margin-bottom:14px">
            <p class="muted">Loading payment details…</p>
        </div>

        <label class="field-label">UPI Transaction Reference (UTR)</label>
        <input id="upiUtr" type="text" placeholder="e.g. 123456789012">
        <button type="button" class="btn-primary btn-full" onclick="submitUpiPayment()">I've paid — submit for verification</button>
        <p id="upiResult" class="muted" style="margin-top:10px;font-size:12.5px"></p>
        <p class="muted" style="margin-top:10px;font-size:11.5px">Pro access is activated manually after we verify the payment — usually within a few hours.</p>
    </div>
</div>


<script type="module">

import {
    initializeApp
}
from "https://www.gstatic.com/firebasejs/12.0.0/firebase-app.js";

import {
    getAuth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    GoogleAuthProvider,
    GithubAuthProvider,
    signInWithPopup
}
from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";

let A;

const $ = x => document.getElementById(x);

function severityDotClass(sev){
    const s = String(sev || "").toLowerCase();
    if(s.includes("high") || s.includes("critical")) return "sev-high";
    if(s.includes("med")) return "sev-med";
    return "sev-low";
}

function escText(value){
    return String(value).replace(/[&<>"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[c]));
}

let publicScanTimer = null;

window.runPublicScan = async function(){

    const input = $("publicScanInput");
    const btn = $("publicScanBtn");
    const statusChip = $("publicScanStatus");
    const results = $("publicScanResults");

    const target = input.value.trim();

    if(!target){
        alert("Enter a website URL to scan.");
        return;
    }

    btn.disabled = true;
    btn.textContent = "Starting scan…";
    statusChip.textContent = "Queued";
    results.innerHTML = '<p class="muted" style="margin-top:12px">Assessing target…</p>';

    if(publicScanTimer){ clearInterval(publicScanTimer); }

    try{

        const response = await fetch("/api/public-scan", {
            method:"POST",
            headers:{ "Content-Type":"application/json" },
            body: JSON.stringify({ target_url: target })
        });

        const data = await response.json();

        if(!response.ok){
            results.innerHTML = '<p class="muted" style="margin-top:12px">' + escText(data.error || "Unable to start scan.") + '</p>';
            btn.disabled = false;
            btn.textContent = "Scan free →";
            return;
        }

        const scanId = data.scan.scan_id;
        statusChip.textContent = "Scanning";

        publicScanTimer = setInterval(async () => {

            const pollRes = await fetch("/api/public-scan/" + scanId);
            const pollData = await pollRes.json();
            const scan = pollData.scan || {};

            if(scan.status === "completed"){
                clearInterval(publicScanTimer);
                statusChip.textContent = "Completed";
                btn.disabled = false;
                btn.textContent = "Scan another site →";
                renderPublicScanResults(scan.findings || []);
            }
            else if(scan.status === "failed"){
                clearInterval(publicScanTimer);
                statusChip.textContent = "Failed";
                btn.disabled = false;
                btn.textContent = "Scan free →";
                results.innerHTML = '<p class="muted" style="margin-top:12px">' + escText(scan.error || "Scan failed.") + '</p>';
            }

        }, 3000);

    }
    catch(error){
        console.error(error);
        results.innerHTML = '<p class="muted" style="margin-top:12px">Request failed.</p>';
        btn.disabled = false;
        btn.textContent = "Scan free →";
    }

};

function renderPublicScanResults(findings){

    const results = $("publicScanResults");

    const counts = { high:0, med:0, low:0 };
    findings.forEach(f => {
        const s = String(f.severity || "").toLowerCase();
        if(s.includes("high") || s.includes("critical")) counts.high++;
        else if(s.includes("med")) counts.med++;
        else counts.low++;
    });

    const grade = counts.high > 0 ? "C" : (counts.med > 2 ? "B" : (counts.med > 0 ? "B+" : "A"));

    let html = `
        <div class="report-score">
            <span class="num">${grade}</span>
            <span class="muted">Security grade · ${findings.length} findings</span>
        </div>
    `;

    findings.slice(0, 5).forEach(f => {
        html += `
            <div class="finding-row">
                <span class="sev-dot ${severityDotClass(f.severity)}"></span>
                <span class="label">${escText(f.title || f.name || "Finding")}</span>
                <span class="tag">${escText((f.severity || "info").toUpperCase())}</span>
            </div>
        `;
    });

    html += '<button type="button" class="btn-ghost btn-full" style="margin-top:14px" onclick="showAuth()">Sign up to save this report + unlock AI fixes →</button>';

    results.innerHTML = html;

}

async function loadLiveCounter(){

    const el = $("liveCounterNum");
    if(!el){ return; }

    try{
        const response = await fetch("/api/stats");
        const data = await response.json();
        const target = data.total_findings || 0;

        let current = 0;
        const step = Math.max(1, Math.ceil(target / 60));

        const timer = setInterval(() => {
            current = Math.min(target, current + step);
            el.textContent = current.toLocaleString();
            if(current >= target){ clearInterval(timer); }
        }, 20);
    }
    catch(error){
        console.error(error);
    }

}

loadLiveCounter();

async function boot(){

    try{

        const response = await fetch("/config");

        if(!response.ok){
            throw new Error("Unable to load Firebase configuration");
        }

        const config = await response.json();

        A = getAuth(initializeApp(config));

        onAuthStateChanged(A, user => {

            if(user){
                $("landing").classList.add("hidden");
                $("auth").classList.add("hidden");
                $("app").classList.remove("hidden");
                $("who").textContent = user.email || "";
                history();
                loadPlanInfo();
            }
            else{
                $("landing").classList.remove("hidden");
                $("auth").classList.add("hidden");
                $("app").classList.add("hidden");
            }

        });

    }

    catch(error){
        console.error(error);
        $("msg").textContent = "Application configuration failed.";
    }

}

window.showAuth = () => {
    $("landing").classList.add("hidden");
    $("auth").classList.remove("hidden");
};

window.signup = async () => {

    $("msg").textContent = "";

    try{
        const email = $("email").value.trim();
        const password = $("pw").value;

        if(!email || !password){
            $("msg").textContent = "Enter email and password.";
            return;
        }

        await createUserWithEmailAndPassword(A, email, password);
    }
    catch(error){
        $("msg").textContent = error.message;
    }

};

window.login = async () => {

    $("msg").textContent = "";

    try{
        const email = $("email").value.trim();
        const password = $("pw").value;

        if(!email || !password){
            $("msg").textContent = "Enter email and password.";
            return;
        }

        await signInWithEmailAndPassword(A, email, password);
    }
    catch(error){
        $("msg").textContent = error.message;
    }

};

window.googleSignIn = async () => {

    $("msg").textContent = "";

    try{
        await signInWithPopup(A, new GoogleAuthProvider());
    }
    catch(error){
        $("msg").textContent = error.message;
    }

};

window.githubSignIn = async () => {

    $("msg").textContent = "";

    try{
        await signInWithPopup(A, new GithubAuthProvider());
    }
    catch(error){
        $("msg").textContent = error.message;
    }

};

window.logout = async () => {
    try{ await signOut(A); }
    catch(error){ console.error(error); }
};

const promptBox = $("q");
const charCount = $("charCount");

if(promptBox && charCount){
    promptBox.addEventListener("input", () => {
        charCount.textContent = promptBox.value.length + " / 2000";
    });
}

if(promptBox){
    promptBox.addEventListener("keydown", (event) => {
        if(event.ctrlKey && event.key === "Enter"){
            event.preventDefault();
            analyze();
        }
    });
}

window.clearPrompt = function(){
    const box = $("q");
    if(box){ box.value = ""; box.focus(); }
    const count = $("charCount");
    if(count){ count.textContent = "0 / 2000"; }
};

let currentCategory = "web";

let lastAnalyzeAnswer = "";

window.execSummary = async function(btn){

    const content = lastAnalyzeAnswer;
    if(!content){ return; }

    const box = $("execBox");
    btn.disabled = true;
    btn.textContent = "Summarizing…";
    box.innerHTML = "";

    try{
        const user = A.currentUser;
        const token = await user.getIdToken();

        const response = await fetch("/api/summarize", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body:JSON.stringify({ content })
        });

        const data = await response.json();

        if(response.ok){
            box.innerHTML = '<div class="exec-card"><span class="eyebrow">For executives</span>' +
                esc(data.summary || "") + '</div>';
        }
        else{
            box.innerHTML = '<p class="muted">' + esc(data.error || "Unable to summarize.") + '</p>';
        }
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Request failed.</p>';
    }
    finally{
        btn.disabled = false;
        btn.textContent = "📋 Executive summary";
    }

};

const categoryConfig = {
    web:{
        placeholder:"Example: How should I manually test a web app for broken access control in an authorized lab?",
        checks:[
            ["SQL Injection","How should I manually test a web application for SQL Injection in an authorized lab?"],
            ["XSS","How should I manually test a web application for Cross-Site Scripting (XSS) in an authorized lab?"],
            ["Access Control","How should I manually test a web application for Broken Access Control in an authorized lab?"],
            ["Security Headers","How should I review security headers of an authorized web application?"]
        ]
    },
    mobile:{
        placeholder:"Example: How should I check an authorized Android app for insecure local data storage?",
        checks:[
            ["Insecure storage","How should I check an authorized mobile app for insecure local data storage?"],
            ["SSL pinning","How should I verify SSL/certificate pinning is implemented correctly in an authorized mobile app?"],
            ["API security","How should I review an authorized mobile app's backend API communication for security issues?"],
            ["Permissions","How should I review Android/iOS permission usage for an authorized app?"]
        ]
    },
    cloud:{
        placeholder:"Example: How should I check an authorized AWS S3 bucket for public access misconfiguration?",
        checks:[
            ["Storage exposure","How should I check an authorized cloud storage bucket for public access misconfiguration?"],
            ["IAM review","How should I review IAM roles and permissions for excessive privileges in an authorized cloud account?"],
            ["Open ports","How should I check an authorized cloud instance for unnecessarily exposed ports or services?"],
            ["Encryption","How should I verify encryption at rest and in transit for an authorized cloud environment?"]
        ]
    },
    code:{
        placeholder:"Example: What should I look for while manually reviewing authentication code for security issues?",
        checks:[
            ["Hardcoded secrets","How do I find hardcoded credentials or secrets during a source code review?"],
            ["Injection risks","What should I look for to catch injection vulnerabilities during a source code review?"],
            ["Deserialization","How should I review code for insecure deserialization risks?"],
            ["Dependencies","How should I review a codebase's dependencies for known vulnerabilities?"]
        ]
    }
};

window.setCategory = function(cat){

    currentCategory = cat;

    document.querySelectorAll(".cat-tab").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.cat === cat);
    });

    const cfg = categoryConfig[cat];
    if(!cfg){ return; }

    const box = $("q");
    if(box){ box.placeholder = cfg.placeholder; }

    const quickChecks = $("quickChecks");
    if(quickChecks){
        quickChecks.innerHTML = '<span class="muted">Quick checks</span>' +
            cfg.checks.map(([label, text]) =>
                `<button type="button" class="quick-btn" onclick="document.getElementById('q').value=${JSON.stringify(text)}">${label}</button>`
            ).join("");
    }

    const autofixPanel = $("autofixPanel");
    if(autofixPanel){
        autofixPanel.classList.toggle("hidden", cat !== "code");
    }

};

window.generateFix = async function(){

    const code = $("fixCode").value.trim();
    const resultBox = $("fixResult");

    if(!code){
        alert("Paste some code first.");
        return;
    }

    resultBox.innerHTML = '<p class="muted" style="margin-top:10px">Generating secure fix…</p>';

    try{
        const user = A.currentUser;

        if(!user){
            resultBox.innerHTML = '<p class="muted">Please sign in first.</p>';
            return;
        }

        const token = await user.getIdToken();

        const response = await fetch("/api/autofix", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body:JSON.stringify({ code })
        });

        const data = await response.json();

        if(response.ok){
            resultBox.innerHTML = "<pre>" + esc(data.result || "") + "</pre>";
        }
        else if(response.status === 402){
            resultBox.innerHTML = '<p class="muted" style="margin-top:10px">🔒 This is a Pro feature. Upgrade your account to generate AI fixes.</p>';
        }
        else{
            resultBox.innerHTML = '<p class="muted">' + esc(data.error || "Request failed") + '</p>';
        }
    }
    catch(error){
        console.error(error);
        resultBox.innerHTML = '<p class="muted">Request failed.</p>';
    }

};

window.analyze = async () => {

    const user = A.currentUser;
    const question = $("q").value.trim();

    if(!user){
        $("out").innerHTML = "<p>Please sign in first.</p>";
        return;
    }

    if(!question){
        $("out").innerHTML = "<p>Enter a security scenario.</p>";
        return;
    }

    const analyzeBtn = document.querySelector('button[onclick="analyze()"]');

    if(analyzeBtn){
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "Analyzing…";
    }

    try{

        const token = await user.getIdToken();

        $("out").innerHTML = "<p>Gemini is analyzing…</p>";

        const response = await fetch("/api/analyze", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body:JSON.stringify({ prompt:question, category:currentCategory })
        });

        const data = await response.json();

        if(response.ok){
            $("out").innerHTML = "<pre>" + esc(data.answer || "") + "</pre>" +
                '<button type="button" class="btn-ghost btn-sm" style="margin-top:12px" onclick="execSummary(this)">📋 Executive summary</button>' +
                '<div class="exec-summary" id="execBox"></div>';
            lastAnalyzeAnswer = data.answer || "";
            $("q").value = "";
            if(charCount){ charCount.textContent = "0 / 2000"; }
            history();
        }
        else{
            $("out").innerHTML = "<p>" + esc(data.error || "Request failed") + "</p>";
        }

    }
    catch(error){
        console.error(error);
        $("out").innerHTML = "<p>Request failed. Check the server.</p>";
    }
    finally{
        if(analyzeBtn){
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Analyze with Gemini";
        }
    }

};

async function loadPlanInfo(){

    const user = A.currentUser;
    if(!user){ return; }

    try{
        const token = await user.getIdToken();

        const response = await fetch("/api/me", {
            headers:{ "Authorization":"Bearer " + token }
        });

        const data = await response.json();
        const titleEl = $("planTitle");
        const descEl = $("planDesc");

        if(!titleEl || !descEl){ return; }

        if(data.plan === "pro"){
            titleEl.textContent = "⭐ Pro plan";
            descEl.textContent = "Unlimited scans, AI Auto-Fix, PDF reports & public badges unlocked.";
        }
        else{
            titleEl.textContent = "Free plan";
            descEl.textContent = "10 scans & 30 AI requests per hour. Upgrade for Auto-Fix, badges & more.";
        }
    }
    catch(error){
        console.error(error);
    }

}

async function history(){

    const user = A.currentUser;
    if(!user){ return; }

    try{

        const token = await user.getIdToken();

        const response = await fetch("/api/history", {
            headers:{ "Authorization":"Bearer " + token }
        });

        const data = await response.json();

        if(!response.ok){
            $("hist").textContent = data.error || "Unable to load history.";
            return;
        }

        $("hist").innerHTML = data.length
            ? data.map(x => `
                <div class="item">
                    <b>${esc((x.prompt || "").slice(0,90))}</b>
                    <span class="muted">${esc(x.createdAt || "")}</span>
                </div>
            `).join("")
            : "No analyses yet.";

    }
    catch(error){
        console.error(error);
        $("hist").textContent = "Unable to load history.";
    }

}

function esc(value){
    return String(value).replace(/[&<>"']/g, character => ({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[character]));
}

/* ============================================================
   WORKSPACE TABS
   ============================================================ */

const loadedTabs = new Set();

window.setWorkspaceTab = function(tab){

    document.querySelectorAll(".wtab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.wtab === tab);
    });

    document.querySelectorAll(".workspace-panel").forEach(panel => {
        panel.classList.toggle("hidden", panel.id !== "wtab-" + tab);
    });

    if(loadedTabs.has(tab)){ return; }
    loadedTabs.add(tab);

    if(tab === "grc"){ loadReadiness(); loadGrcControls(); loadRisks(); }
    else if(tab === "remediation"){ loadRemediation(); }
    else if(tab === "evidence"){ loadEvidence(); }
    else if(tab === "history"){ history(); }

};

async function authedFetch(path, opts){

    opts = opts || {};
    const user = A && A.currentUser;

    if(!user){ throw new Error("Not signed in"); }

    const token = await user.getIdToken();
    const headers = Object.assign(
        { "Authorization": "Bearer " + token },
        opts.body ? { "Content-Type": "application/json" } : {},
        opts.headers || {}
    );

    const response = await fetch(path, Object.assign({}, opts, { headers }));
    const data = await response.json().catch(() => ({}));

    if(!response.ok){
        throw new Error(data.error || "Request failed");
    }

    return data;

}

/* ---------- GRC readiness ---------- */

async function loadReadiness(){

    const box = $("grcReadiness");

    try{
        const data = await authedFetch("/api/grc/readiness");

        const pct = Math.round(data.control_readiness_pct || 0);

        box.innerHTML = `
            <div class="readiness-grid">
                <div class="readiness-ring" style="--pct:${pct}"><b>${pct}%</b></div>
                <div class="readiness-stats">
                    <div class="rstat"><b>${data.controls_implemented}/${data.controls_total}</b><span>Controls implemented</span></div>
                    <div class="rstat"><b>${data.controls_partial}</b><span>Partially implemented</span></div>
                    <div class="rstat"><b>${data.open_risks}</b><span>Open risks</span></div>
                    <div class="rstat"><b>${data.open_remediation}</b><span>Open remediation tasks</span></div>
                    <div class="rstat"><b>${data.evidence_count}</b><span>Evidence records</span></div>
                    <div class="rstat"><b>${data.avg_risk_score || 0}</b><span>Avg. risk score</span></div>
                </div>
            </div>
        `;
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load readiness right now.</p>';
    }

}

/* ---------- ISO controls ---------- */

function controlStatusClass(status){
    return "st-" + String(status || "not_implemented");
}

async function loadGrcControls(){

    const box = $("grcControls");

    try{
        const data = await authedFetch("/api/grc/controls");
        const controls = data.controls || [];

        if(!controls.length){
            box.innerHTML = '<p class="workspace-empty">No controls found.</p>';
            return;
        }

        const groups = {};
        controls.forEach(c => {
            const g = c.category || "General";
            (groups[g] = groups[g] || []).push(c);
        });

        box.innerHTML = Object.keys(groups).map(group => `
            <div class="control-group-title">${esc(group)}</div>
            ${groups[group].map(c => `
                <div class="control-row">
                    <div class="ctitle">
                        <span class="ccode">${esc(c.code)}</span>
                        ${esc(c.title)}
                    </div>
                    <select class="status-select ${controlStatusClass(c.status)}" onchange="updateControlStatus('${c.id}', this.value, this)">
                        <option value="not_implemented" ${c.status === "not_implemented" ? "selected" : ""}>Not Implemented</option>
                        <option value="partial" ${c.status === "partial" ? "selected" : ""}>Partially Implemented</option>
                        <option value="implemented" ${c.status === "implemented" ? "selected" : ""}>Implemented</option>
                        <option value="na" ${c.status === "na" ? "selected" : ""}>N/A</option>
                    </select>
                </div>
            `).join("")}
        `).join("");
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load controls right now.</p>';
    }

}

window.updateControlStatus = async function(controlId, status, selectEl){

    try{
        await authedFetch("/api/grc/controls/" + encodeURIComponent(controlId), {
            method: "PATCH",
            body: JSON.stringify({ status })
        });

        if(selectEl){
            selectEl.className = "status-select " + controlStatusClass(status);
        }

        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to update control status.");
    }

};

/* ---------- Risk register ---------- */

function riskBadgeClass(score){
    if(score >= 15) return "r-critical";
    if(score >= 9) return "r-high";
    if(score >= 4) return "r-medium";
    return "r-low";
}

async function loadRisks(){

    const box = $("riskList");

    try{
        const data = await authedFetch("/api/grc/risks");
        const risks = data.risks || [];

        box.innerHTML = risks.length
            ? risks.map(r => `
                <div class="risk-item">
                    <div>
                        <b>${esc(r.title)}</b>
                        <p>${esc(r.description || "")}</p>
                        <p class="muted" style="margin-top:2px">Likelihood ${r.likelihood} × Impact ${r.impact}</p>
                    </div>
                    <span class="risk-badge ${riskBadgeClass(r.score)}">${r.score} pts</span>
                    <button type="button" class="icon-del" onclick="deleteRisk('${r.id}')" title="Delete">✕</button>
                </div>
            `).join("")
            : '<p class="workspace-empty">No risks logged yet.</p>';
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load risk register right now.</p>';
    }

}

window.addRisk = async function(){

    const title = $("riskTitle").value.trim();
    const likelihood = parseInt($("riskLikelihood").value, 10);
    const impact = parseInt($("riskImpact").value, 10);
    const description = $("riskDesc").value.trim();

    if(!title){
        alert("Enter a risk title.");
        return;
    }

    try{
        await authedFetch("/api/grc/risks", {
            method: "POST",
            body: JSON.stringify({ title, description, likelihood, impact })
        });

        $("riskTitle").value = "";
        $("riskDesc").value = "";
        loadRisks();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to add risk right now.");
    }

};

window.deleteRisk = async function(id){

    try{
        await authedFetch("/api/grc/risks/" + encodeURIComponent(id), { method: "DELETE" });
        loadRisks();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to delete risk.");
    }

};

/* ---------- Remediation ---------- */

async function loadRemediation(){

    const box = $("taskList");

    try{
        const data = await authedFetch("/api/grc/remediation");
        const tasks = data.tasks || [];

        box.innerHTML = tasks.length
            ? tasks.map(t => `
                <div class="task-item">
                    <div>
                        <b>${esc(t.title)}</b>
                        <p class="meta">${esc(t.description || "")}</p>
                        <p class="meta">${t.due_date ? "Due " + esc(t.due_date) : "No due date"}</p>
                    </div>
                    <div class="task-actions">
                        <span class="priority-chip p-${esc(t.priority)}">${esc(t.priority)}</span>
                        <select class="status-select" onchange="updateTaskStatus('${t.id}', this.value)">
                            <option value="open" ${t.status === "open" ? "selected" : ""}>Open</option>
                            <option value="in_progress" ${t.status === "in_progress" ? "selected" : ""}>In Progress</option>
                            <option value="done" ${t.status === "done" ? "selected" : ""}>Done</option>
                        </select>
                        <button type="button" class="icon-del" onclick="deleteTask('${t.id}')" title="Delete">✕</button>
                    </div>
                </div>
            `).join("")
            : '<p class="workspace-empty">No remediation tasks yet.</p>';
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load tasks right now.</p>';
    }

}

window.addRemediationTask = async function(){

    const title = $("taskTitle").value.trim();
    const priority = $("taskPriority").value;
    const due_date = $("taskDue").value;
    const description = $("taskDesc").value.trim();

    if(!title){
        alert("Enter a task title.");
        return;
    }

    try{
        await authedFetch("/api/grc/remediation", {
            method: "POST",
            body: JSON.stringify({ title, priority, due_date, description })
        });

        $("taskTitle").value = "";
        $("taskDesc").value = "";
        $("taskDue").value = "";
        loadRemediation();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to add task right now.");
    }

};

window.updateTaskStatus = async function(id, status){

    try{
        await authedFetch("/api/grc/remediation/" + encodeURIComponent(id), {
            method: "PATCH",
            body: JSON.stringify({ status })
        });
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to update task.");
    }

};

window.deleteTask = async function(id){

    try{
        await authedFetch("/api/grc/remediation/" + encodeURIComponent(id), { method: "DELETE" });
        loadRemediation();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to delete task.");
    }

};

/* ---------- Evidence ---------- */

async function loadEvidence(){

    const box = $("evidenceList");

    try{
        const data = await authedFetch("/api/grc/evidence");
        const items = data.evidence || [];

        box.innerHTML = items.length
            ? items.map(e => `
                <div class="evidence-item">
                    <div>
                        <b>${esc(e.title)}</b>
                        <p class="meta">${esc(e.description || "")}</p>
                        ${e.link ? `<a href="${esc(e.link)}" target="_blank" rel="noopener">${esc(e.link)}</a>` : ""}
                    </div>
                    <button type="button" class="icon-del" onclick="deleteEvidence('${e.id}')" title="Delete">✕</button>
                </div>
            `).join("")
            : '<p class="workspace-empty">No evidence recorded yet.</p>';
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load evidence right now.</p>';
    }

}

window.addEvidence = async function(){

    const title = $("evTitle").value.trim();
    const link = $("evLink").value.trim();
    const description = $("evDesc").value.trim();

    if(!title){
        alert("Enter an evidence title.");
        return;
    }

    try{
        await authedFetch("/api/grc/evidence", {
            method: "POST",
            body: JSON.stringify({ title, link, description })
        });

        $("evTitle").value = "";
        $("evLink").value = "";
        $("evDesc").value = "";
        loadEvidence();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to save evidence right now.");
    }

};

window.deleteEvidence = async function(id){

    try{
        await authedFetch("/api/grc/evidence/" + encodeURIComponent(id), { method: "DELETE" });
        loadEvidence();
        loadReadiness();
    }
    catch(error){
        console.error(error);
        alert("Unable to delete evidence.");
    }

};

window.openUpiModal = async function(){

    if(!A || !A.currentUser){
        alert("Please sign in first, then tap Upgrade to Pro again.");
        showAuth();
        return;
    }

    $("upiModal").classList.remove("hidden");
    const box = $("upiQrBox");
    box.innerHTML = '<p class="muted">Loading payment details…</p>';

    try{
        const response = await fetch("/api/upi-config");
        const data = await response.json();

        const qrImg = "https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=" + encodeURIComponent(data.upi_uri);

        box.innerHTML = `
            <img src="${qrImg}" alt="UPI QR code" style="border-radius:12px;border:1px solid var(--border);margin-bottom:10px">
            <div style="font-family:'JetBrains Mono';font-size:13px;color:var(--text)">${escText(data.upi_id)}</div>
            <div class="muted" style="font-size:12px;margin-top:2px">Amount: ₹${escText(data.amount)}</div>
        `;
    }
    catch(error){
        console.error(error);
        box.innerHTML = '<p class="muted">Unable to load payment details right now.</p>';
    }

};

window.closeUpiModal = function(){
    $("upiModal").classList.add("hidden");
};

window.submitUpiPayment = async function(){

    const utr = $("upiUtr").value.trim();
    const resultBox = $("upiResult");

    if(!utr){
        resultBox.textContent = "Enter your UPI transaction reference number.";
        return;
    }

    resultBox.textContent = "Submitting…";

    try{
        const user = A.currentUser;
        const token = await user.getIdToken();

        const response = await fetch("/api/upi-payment", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body: JSON.stringify({ utr })
        });

        if(response.ok){
            resultBox.textContent = "✓ Submitted. We'll verify and activate Pro within a few hours.";
            $("upiUtr").value = "";
        }
        else{
            const data = await response.json();
            resultBox.textContent = data.error || "Unable to submit.";
        }
    }
    catch(error){
        console.error(error);
        resultBox.textContent = "Request failed.";
    }

};

boot();

let scanPollTimer = null;

let lastScanId = null;

function severityDot(sev){
    const s = String(sev || "").toLowerCase();
    if(s.includes("high") || s.includes("critical")) return "sev-high";
    if(s.includes("med")) return "sev-med";
    return "sev-low";
}

let lastScanReport = null;

function severityBucket(sev){
    const s = String(sev || "").toLowerCase();
    if(s.includes("high") || s.includes("critical")) return "high";
    if(s.includes("med")) return "med";
    return "low";
}

function renderScanFindings(findings, targetUrl){

    const box = $("scanResults");
    if(!box){ return; }

    const list = Array.isArray(findings) ? findings : [];

    const counts = { high:0, med:0, low:0 };
    list.forEach(f => { counts[severityBucket(f.severity)]++; });

    lastScanReport = { target: targetUrl || "", findings: list, counts, generatedAt: new Date() };

    const total = list.length || 1;
    const pct = k => Math.round((counts[k] / total) * 100);

    const summaryHtml = `
        <div class="findings-summary">
            <div class="fs-bar">
                <span style="width:${pct('high')}%;background:var(--danger)"></span>
                <span style="width:${pct('med')}%;background:var(--warning)"></span>
                <span style="width:${pct('low')}%;background:var(--accent)"></span>
            </div>
            <div class="fs-legend">
                <span><i class="sev-dot sev-high"></i> High · ${counts.high}</span>
                <span><i class="sev-dot sev-med"></i> Medium · ${counts.med}</span>
                <span><i class="sev-dot sev-low"></i> Low · ${counts.low}</span>
            </div>
        </div>
    `;

    if(list.length === 0){
        box.innerHTML = '<p class="muted" style="margin-top:10px">No issues found in this assessment.</p>';
        return;
    }

    const findingsHtml = list.map((f, i) => {
        const title = esc(f.title || f.name || "Finding");
        const desc = esc(f.description || f.detail || f.summary || "");
        return `
            <div class="scan-finding">
                <span class="sev-dot ${severityDot(f.severity)}"></span>
                <div style="flex:1">
                    <b>${title}</b>
                    <p>${desc}</p>
                    <button type="button" class="quick-btn" style="margin-top:6px" onclick="toggleAskFinding(${i})">💬 Ask AI about this</button>
                    <div class="finding-ask hidden" id="askBox${i}">
                        <textarea id="askInput${i}" placeholder="e.g. How urgent is this? What's the safest way to test it?"></textarea>
                        <button type="button" class="btn-ghost btn-sm" onclick="askAboutFinding(${i}, ${JSON.stringify(title)}, ${JSON.stringify(desc)})">Ask</button>
                        <div class="finding-ask-answer hidden" id="askAnswer${i}"></div>
                    </div>
                </div>
            </div>
        `;
    }).join("");

    box.innerHTML = summaryHtml + findingsHtml +
        '<div class="row" style="gap:10px;margin-top:14px">' +
        '<button type="button" class="btn-ghost btn-sm" style="flex:1" onclick="downloadReport()">⬇ Download PDF report</button>' +
        '<button type="button" class="btn-ghost btn-sm" style="flex:1" onclick="publishBadge()">🔒 Publish public badge (Pro)</button>' +
        '</div>' +
        '<div id="badgeResult" class="muted" style="margin-top:8px;font-size:12px"></div>' +
        '<div class="expert-cta">' +
            '<div><b>Not sure how serious this is?</b><p class="muted" style="margin-top:2px">Request a manual review from a real security analyst.</p></div>' +
            '<button type="button" class="btn-ghost btn-sm" onclick="requestExpertReview()">🧑‍💻 Request expert review</button>' +
        '</div>' +
        '<div id="expertResult" class="muted" style="margin-top:8px;font-size:12px"></div>';

}

window.requestExpertReview = async function(){

    const resultBox = $("expertResult");

    if(!lastScanReport){
        resultBox.textContent = "Run a scan first.";
        return;
    }

    const notes = prompt("Anything specific you'd like the analyst to focus on? (optional)") || "";

    resultBox.textContent = "Sending request…";

    try{
        const user = A.currentUser;
        const token = await user.getIdToken();

        const response = await fetch("/api/expert-review", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body: JSON.stringify({
                target_url: lastScanReport.target,
                scan_id: lastScanId || "",
                notes
            })
        });

        if(response.ok){
            resultBox.textContent = "✓ Request sent. We'll reach out within 24–48 hours.";
        }
        else{
            const data = await response.json();
            resultBox.textContent = data.error || "Unable to send request.";
        }
    }
    catch(error){
        console.error(error);
        resultBox.textContent = "Request failed.";
    }

};

window.toggleAskFinding = function(i){
    const box = $("askBox" + i);
    if(box){ box.classList.toggle("hidden"); }
};

window.askAboutFinding = async function(i, title, desc){

    const input = $("askInput" + i);
    const answerBox = $("askAnswer" + i);
    const question = input.value.trim();

    const finalPrompt = "Regarding this security finding — \\"" + title + "\\": " + desc +
        (question ? ("\\n\\nSpecific question: " + question) : "\\n\\nExplain the risk in detail, how to safely verify it, and how to remediate it.");

    answerBox.classList.remove("hidden");
    answerBox.textContent = "Thinking…";

    try{
        const user = A.currentUser;
        const token = await user.getIdToken();

        const response = await fetch("/api/analyze", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body:JSON.stringify({ prompt:finalPrompt, category:"web" })
        });

        const data = await response.json();
        answerBox.textContent = response.ok ? (data.answer || "") : (data.error || "Request failed");
    }
    catch(error){
        console.error(error);
        answerBox.textContent = "Request failed.";
    }

};

window.publishBadge = async function(){

    const resultBox = $("badgeResult");

    if(!lastScanId){
        resultBox.textContent = "Run a scan first.";
        return;
    }

    resultBox.textContent = "Publishing…";

    try{
        const user = A.currentUser;
        const token = await user.getIdToken();

        const response = await fetch("/api/scan/" + lastScanId + "/publish", {
            method:"POST",
            headers:{ "Authorization":"Bearer " + token }
        });

        const data = await response.json();

        if(response.ok){
            const url = location.origin + data.badge_url;
            resultBox.innerHTML = 'Public badge: <a href="' + url + '" target="_blank" style="color:var(--accent)">' + url + '</a>';
        }
        else if(response.status === 402){
            resultBox.textContent = "This is a Pro feature — upgrade to unlock public badges.";
        }
        else{
            resultBox.textContent = data.error || "Unable to publish.";
        }
    }
    catch(error){
        console.error(error);
        resultBox.textContent = "Request failed.";
    }

};

window.downloadReport = function(){

    if(!lastScanReport || typeof window.jspdf === "undefined"){
        alert("No report available yet.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const { target, findings, counts, generatedAt } = lastScanReport;
    const pageW = doc.internal.pageSize.getWidth();
    const marginX = 16;
    const contentW = pageW - marginX * 2;

    const brandBlue = [75, 139, 255];
    const brandInk = [15, 23, 42];
    const muted = [110, 125, 150];
    const sevColors = {
        high:[248,113,113], med:[251,191,36], low:[75,139,255], info:[148,163,184]
    };

    function severityKey(sev){
        const s = String(sev || "info").toLowerCase();
        if(s.includes("high") || s.includes("critical")) return "high";
        if(s.includes("med")) return "med";
        if(s.includes("low")) return "low";
        return "info";
    }

    function drawHeader(){
        doc.setFillColor(...brandInk);
        doc.rect(0, 0, pageW, 34, "F");
        doc.setTextColor(255,255,255);
        doc.setFont(undefined, "bold");
        doc.setFontSize(16);
        doc.text("CyberLens AI", marginX, 15);
        doc.setFont(undefined, "normal");
        doc.setFontSize(9);
        doc.setTextColor(180,195,220);
        doc.text("AI-Powered Security Assessment Report", marginX, 22);
        doc.setFontSize(8);
        doc.text(generatedAt.toLocaleString(), pageW - marginX, 22, { align:"right" });
        return 44;
    }

    function drawFooter(){
        const pages = doc.internal.getNumberOfPages();
        for(let p = 1; p <= pages; p++){
            doc.setPage(p);
            doc.setDrawColor(225,229,235);
            doc.line(marginX, 285, pageW - marginX, 285);
            doc.setFontSize(8);
            doc.setTextColor(...muted);
            doc.text("CyberLens AI · Confidential security report", marginX, 291);
            doc.text("Page " + p + " / " + pages, pageW - marginX, 291, { align:"right" });
        }
    }

    let y = drawHeader();

    doc.setTextColor(...brandInk);
    doc.setFont(undefined, "bold");
    doc.setFontSize(11);
    doc.text("Target", marginX, y);
    doc.setFont(undefined, "normal");
    doc.setTextColor(...muted);
    doc.text(doc.splitTextToSize(target, contentW), marginX, y + 6);
    y += 16;

    const chipW = (contentW - 16) / 3;
    const chipData = [
        ["High", counts.high, sevColors.high],
        ["Medium", counts.med, sevColors.med],
        ["Low", counts.low, sevColors.low],
    ];

    chipData.forEach(([label, count, color], i) => {
        const x = marginX + i * (chipW + 8);
        doc.setFillColor(248, 249, 251);
        doc.roundedRect(x, y, chipW, 22, 3, 3, "F");
        doc.setFillColor(...color);
        doc.circle(x + 10, y + 11, 3, "F");
        doc.setTextColor(...brandInk);
        doc.setFont(undefined, "bold");
        doc.setFontSize(14);
        doc.text(String(count), x + 18, y + 10);
        doc.setFont(undefined, "normal");
        doc.setFontSize(8);
        doc.setTextColor(...muted);
        doc.text(label + " severity", x + 18, y + 16);
    });

    y += 34;

    doc.setFont(undefined, "bold");
    doc.setFontSize(12);
    doc.setTextColor(...brandInk);
    doc.text("Findings (" + findings.length + ")", marginX, y);
    y += 8;

    if(findings.length === 0){
        doc.setFont(undefined, "normal");
        doc.setFontSize(10);
        doc.setTextColor(...muted);
        doc.text("No issues were found in this assessment.", marginX, y);
        y += 8;
    }

    findings.forEach((f, i) => {

        const title = f.title || f.name || "Finding " + (i + 1);
        const desc = f.description || f.detail || f.summary || "";
        const sevKey = severityKey(f.severity);
        const color = sevColors[sevKey];

        doc.setFont(undefined, "bold");
        doc.setFontSize(10.5);
        const titleLines = doc.splitTextToSize(title, contentW - 26);
        doc.setFont(undefined, "normal");
        doc.setFontSize(9);
        const descLines = doc.splitTextToSize(desc, contentW - 4);

        const blockH = 8 + titleLines.length * 5.5 + descLines.length * 4.6 + 8;

        if(y + blockH > 275){
            doc.addPage();
            y = drawHeader();
        }

        doc.setFillColor(250, 250, 252);
        doc.setDrawColor(230, 233, 238);
        doc.roundedRect(marginX, y, contentW, blockH, 3, 3, "FD");

        doc.setFillColor(...color);
        doc.circle(marginX + 8, y + 9, 2.2, "F");

        doc.setTextColor(...brandInk);
        doc.setFont(undefined, "bold");
        doc.setFontSize(10.5);
        doc.text(titleLines, marginX + 16, y + 9);

        doc.setFillColor(...color);
        const tagW = doc.getTextWidth(sevKey.toUpperCase()) + 6;
        doc.roundedRect(pageW - marginX - tagW - 4, y + 4, tagW, 8, 2, 2, "F");
        doc.setTextColor(255,255,255);
        doc.setFontSize(7.5);
        doc.text(sevKey.toUpperCase(), pageW - marginX - tagW/2 - 4, y + 9.3, { align:"center" });

        doc.setFont(undefined, "normal");
        doc.setFontSize(9);
        doc.setTextColor(...muted);
        doc.text(descLines, marginX + 16, y + 8 + titleLines.length * 5.5 + 4);

        y += blockH + 6;

    });

    drawFooter();

    doc.save("cyberlens-report.pdf");

};

async function pollScan(scanId){

    const user = A.currentUser;
    if(!user){ return; }

    const statusText = $("scanStatusText");
    const statusLabel = $("scanStatusLabel");
    const progressFill = $("scanProgressFill");

    try{

        const token = await user.getIdToken();

        const response = await fetch("/api/scan/" + scanId, {
            headers:{ "Authorization":"Bearer " + token }
        });

        const data = await response.json();

        if(!response.ok){
            clearInterval(scanPollTimer);
            statusText.textContent = "Error";
            $("scanIdText").textContent = data.error || "Unable to fetch scan status.";
            return;
        }

        const scan = data.scan || {};

        if(scan.status === "scanning"){
            statusLabel.textContent = "Scanning target";
            statusText.textContent = "In progress";
            progressFill.style.width = "65%";
        }
        else if(scan.status === "completed"){
            clearInterval(scanPollTimer);
            statusLabel.textContent = "Assessment complete";
            statusText.textContent = (scan.findings_count ?? 0) + " findings";
            progressFill.style.width = "100%";
            renderScanFindings(scan.findings, scan.target_url);
        }
        else if(scan.status === "failed"){
            clearInterval(scanPollTimer);
            statusLabel.textContent = "Assessment failed";
            statusText.textContent = "Failed";
            progressFill.style.width = "100%";
            $("scanResults").innerHTML = '<p class="muted" style="margin-top:10px">' + esc(scan.error || "Scan failed.") + '</p>';
        }
        else{
            statusLabel.textContent = "Queued";
            statusText.textContent = "Waiting to start";
            progressFill.style.width = "35%";
        }

    }
    catch(error){
        console.error(error);
    }

}

window.startSecurityScan = async function(){

    const target = $("scanTarget").value.trim();
    const authorized = $("scanAuthorized").checked;
    const profile = $("scanProfile").value;

    const statusBox = $("scanStatus");
    const statusText = $("scanStatusText");
    const statusLabel = $("scanStatusLabel");
    const scanIdText = $("scanIdText");
    const progressFill = $("scanProgressFill");

    if(!target){
        alert("Enter an authorized website URL.");
        return;
    }

    if(!authorized){
        alert("Please confirm that you are authorized to assess this website.");
        return;
    }

    if(scanPollTimer){
        clearInterval(scanPollTimer);
    }

    $("scanResults").innerHTML = "";
    statusBox.hidden = false;
    statusLabel.textContent = "Submitting";
    statusText.textContent = "Queued";
    progressFill.style.width = "20%";

    try{

        const user = A.currentUser;

        if(!user){
            statusText.textContent = "Sign in required";
            return;
        }

        const token = await user.getIdToken();

        const response = await fetch("/api/scan", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Authorization":"Bearer " + token
            },
            body: JSON.stringify({
                target_url: target,
                profile: profile,
                authorized: true
            })
        });

        const data = await response.json();

        if(!response.ok){
            throw new Error(data.error || "Unable to start scan.");
        }

        statusLabel.textContent = "Queued";
        statusText.textContent = "Waiting to start";
        progressFill.style.width = "35%";

        const scanId = data.scan && data.scan.scan_id;

        if(scanId){
            lastScanId = scanId;
            scanIdText.textContent = "Scan ID: " + scanId;
            scanPollTimer = setInterval(() => pollScan(scanId), 3000);
        }

    }
    catch(error){
        console.error(error);
        statusText.textContent = "Failed";
        scanIdText.textContent = error.message;
        progressFill.style.width = "0%";
    }

};

</script>

</body>
</html>"""


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def home():

    return Response(
        HTML,
        mimetype="text/html"
    )


@app.get("/config")
def config():

    return jsonify({
        "apiKey": os.environ.get("FIREBASE_API_KEY", ""),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET", ""),
        "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID", ""),
        "appId": os.environ.get("FIREBASE_APP_ID", "")
    })


# ============================================================
# AUTHENTICATION
# ============================================================

def user_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        header = request.headers.get("Authorization", "")

        try:

            if not header.startswith("Bearer "):
                raise ValueError("Missing bearer token")

            token = header[7:]

            request.user = auth.verify_id_token(token)

            return function(*args, **kwargs)

        except Exception:

            return jsonify(
                error="Authentication required"
            ), 401

    return wrapper


def get_user_plan(uid: str) -> str:
    """Read the user's plan from Firestore. Defaults to 'free'.

    Honors a temporary Pro grant (temp_pro_until, a unix timestamp) set via
    /api/dev/grant-temp-pro for internal testing; auto-reverts once expired.
    """

    try:
        doc = db.collection("users").document(uid).get()
        if not doc.exists:
            return "free"

        data = doc.to_dict()
        plan = str(data.get("plan", "free")).lower()

        temp_until = data.get("temp_pro_until")
        if temp_until is not None:
            if time.time() < float(temp_until):
                return "pro"
            elif plan == "pro":
                # Temporary grant expired — revert to free automatically.
                return "free"

        return plan

    except Exception:
        pass

    return "free"


# Free-plan rate limits: (max_actions, window_seconds). Pro users are unlimited.
RATE_LIMITS = {
    "scan": (10, 3600),
    "analyze": (30, 3600),
}


def check_user_rate_limit(uid: str, action: str) -> bool:
    """Return True if the (free-plan) user is within their rate limit for this action."""

    if get_user_plan(uid) == "pro":
        return True

    limit, window = RATE_LIMITS.get(action, (30, 3600))
    key = (uid, action)
    now = time.time()

    hits = [t for t in _user_action_hits.get(key, []) if now - t < window]

    if len(hits) >= limit:
        _user_action_hits[key] = hits
        return False

    hits.append(now)
    _user_action_hits[key] = hits
    return True


def pro_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        plan = get_user_plan(request.user["uid"])

        if plan != "pro":
            return jsonify(
                error="This is a Pro feature. Upgrade your account to unlock it.",
                upgrade_required=True
            ), 402

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# SECURITY SCAN API
# ============================================================

def bump_global_finding_count(count: int) -> None:
    """Atomically increment the site-wide vulnerability counter."""

    if count <= 0:
        return

    try:
        db.collection("stats").document("global").set(
            {"total_findings": firestore.Increment(count)},
            merge=True,
        )
    except Exception:
        pass


def run_scan_job(scan_id: str, target_url: str, profile: str = "passive") -> None:
    """Run a scan in the background and update its Firestore job."""

    job_ref = db.collection("scan_jobs").document(scan_id)

    try:
        job_ref.update({
            "status": "scanning"
        })

        result = run_assessment(target_url, profile=profile)

        job_ref.update({
            "status": "completed",
            "evidence": result["evidence"],
            "findings": result["findings"],
            "findings_count": result["findings_count"],
            "error": None,
        })

        bump_global_finding_count(result["findings_count"])

    except Exception as exc:
        job_ref.update({
            "status": "failed",
            "error": str(exc),
        })


@app.post("/api/scan")
@user_required
def create_scan():

    if not check_user_rate_limit(request.user["uid"], "scan"):
        return jsonify(
            error="Free plan scan limit reached (10/hour). Upgrade to Pro for higher limits."
        ), 429

    data = request.get_json(silent=True) or {}
    target_url = str(data.get("target_url", "")).strip()
    profile = str(data.get("profile", "passive")).strip().lower()
    authorized = data.get("authorized", False)

    if not authorized:
        return jsonify(
            error="Authorization confirmation is required."
        ), 400

    if profile not in ("passive", "safe_active"):
        return jsonify(
            error="Unknown scan profile."
        ), 400

    valid, result = validate_target_url(target_url)

    if not valid:
        return jsonify(
            error=result
        ), 400

    job = ScanJob(
        target_url=result,
        profile=profile
    )

    job_data = job.to_dict()
    job_data["user_id"] = request.user["uid"]

    db.collection("scan_jobs").document(
        job.scan_id
    ).set(job_data)

    threading.Thread(
        target=run_scan_job,
        args=(job.scan_id, result, profile),
        daemon=True,
    ).start()

    return jsonify({
        "success": True,
        "scan": job_data
    }), 201


@app.get("/api/scan/<scan_id>")
@user_required
def get_scan_status(scan_id):
    doc = db.collection("scan_jobs").document(scan_id).get()

    if not doc.exists:
        return jsonify(
            error="Scan not found."
        ), 404

    scan = doc.to_dict()

    if scan.get("user_id") != request.user["uid"]:
        return jsonify(
            error="Access denied."
        ), 403

    return jsonify({
        "success": True,
        "scan": scan
    }), 200


# ============================================================
# NO-SIGNUP PUBLIC SCAN
# ============================================================

PUBLIC_SCAN_LIMIT = 3          # scans per window, per IP
PUBLIC_SCAN_WINDOW = 3600      # seconds (1 hour)


def _public_scan_allowed(ip: str) -> bool:

    now = time.time()
    hits = [t for t in _public_scan_hits.get(ip, []) if now - t < PUBLIC_SCAN_WINDOW]
    _public_scan_hits[ip] = hits

    if len(hits) >= PUBLIC_SCAN_LIMIT:
        return False

    hits.append(now)
    _public_scan_hits[ip] = hits
    return True


def run_public_scan_job(scan_id: str, target_url: str) -> None:

    job_ref = db.collection("public_scans").document(scan_id)

    try:
        job_ref.update({"status": "scanning"})

        result = run_assessment(target_url, profile="passive")

        job_ref.update({
            "status": "completed",
            "findings": result["findings"],
            "findings_count": result["findings_count"],
            "error": None,
        })

        bump_global_finding_count(result["findings_count"])

    except Exception as exc:
        job_ref.update({
            "status": "failed",
            "error": str(exc),
        })


@app.get("/api/stats")
def get_stats():
    """Public, read-only site-wide vulnerability counter."""

    try:
        doc = db.collection("stats").document("global").get()
        total = doc.to_dict().get("total_findings", 0) if doc.exists else 0
    except Exception:
        total = 0

    return jsonify({"total_findings": total})


@app.post("/api/public-scan")
def create_public_scan():

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

    if not _public_scan_allowed(ip):
        return jsonify(
            error="Free scan limit reached. Please try again later, or sign up for unlimited scans."
        ), 429

    data = request.get_json(silent=True) or {}
    target_url = str(data.get("target_url", "")).strip()

    valid, result = validate_target_url(target_url)

    if not valid:
        return jsonify(error=result), 400

    job = ScanJob(target_url=result, profile="passive")
    job_data = job.to_dict()
    job_data["ip"] = ip

    db.collection("public_scans").document(job.scan_id).set(job_data)

    threading.Thread(
        target=run_public_scan_job,
        args=(job.scan_id, result),
        daemon=True,
    ).start()

    return jsonify({"success": True, "scan": job_data}), 201


@app.get("/api/public-scan/<scan_id>")
def get_public_scan_status(scan_id):

    doc = db.collection("public_scans").document(scan_id).get()

    if not doc.exists:
        return jsonify(error="Scan not found."), 404

    return jsonify({"success": True, "scan": doc.to_dict()}), 200


# ============================================================
# EXPERT HUMAN REVIEW REQUEST
# ============================================================

@app.post("/api/expert-review")
@user_required
def request_expert_review():

    data = request.get_json(silent=True) or {}
    target_url = str(data.get("target_url", "")).strip()
    notes = str(data.get("notes", "")).strip()
    scan_id = str(data.get("scan_id", "")).strip()

    if not target_url:
        return jsonify(error="Missing target website."), 400

    db.collection("expert_requests").document().set({
        "user_id": request.user["uid"],
        "email": request.user.get("email", ""),
        "target_url": target_url,
        "scan_id": scan_id,
        "notes": notes,
        "status": "new",
        "createdAt": firestore.SERVER_TIMESTAMP,
    })

    return jsonify({"success": True}), 201


# ============================================================
# GEMINI ANALYSIS
# ============================================================

@app.post("/api/analyze")
@user_required
def analyze():

    if not gemini:
        return jsonify(
            error="Gemini is not configured"
        ), 503

    if not check_user_rate_limit(request.user["uid"], "analyze"):
        return jsonify(
            error="Free plan AI request limit reached (30/hour). Upgrade to Pro for higher limits."
        ), 429

    data = request.get_json(silent=True) or {}

    prompt = str(data.get("prompt", "")).strip()

    category = str(data.get("category", "web")).strip().lower()

    if category not in CATEGORY_CONTEXT:
        category = "web"

    if not prompt:
        return jsonify(
            error="Enter a scenario"
        ), 400

    system = """
You are CyberLens AI, a defensive cybersecurity assistant.

""" + CATEGORY_CONTEXT[category] + """

Give safe, authorized guidance focused on:

- vulnerability understanding
- manual testing methodology
- evidence collection
- risk assessment
- remediation

Do not provide:

- credential theft
- malware
- persistence
- evasion
- destructive actions
- unauthorized access

Structure useful answers with:

Summary
What to Check
Safe Test Steps
Evidence
Risk
Remediation
"""

    try:

        result = gemini.models.generate_content(
            model=MODEL,
            contents=system + "\n\nScenario:\n" + prompt
        )

        answer = result.text or "No response."

        reference = (
            db
            .collection("users")
            .document(request.user["uid"])
            .collection("analyses")
            .document()
        )

        reference.set({
            "prompt": prompt,
            "answer": answer,
            "createdAt": firestore.SERVER_TIMESTAMP
        })

        return jsonify(
            id=reference.id,
            answer=answer
        )

    except Exception as error:

        app.logger.exception(
            "Gemini/Firestore request failed: %s",
            error
        )

        return jsonify(
            error=(
                "AI request failed; "
                "check server configuration."
            )
        ), 500


# ============================================================
# HISTORY
# ============================================================

@app.get("/api/history")
@user_required
def get_history():

    try:

        documents = (
            db
            .collection("users")
            .document(request.user["uid"])
            .collection("analyses")
            .order_by(
                "createdAt",
                direction=firestore.Query.DESCENDING
            )
            .limit(20)
            .stream()
        )

        output = []

        for document in documents:

            data = document.to_dict()
            timestamp = data.get("createdAt")

            output.append({
                "id": document.id,
                "prompt": data.get("prompt", ""),
                "answer": data.get("answer", ""),
                "createdAt": (
                    timestamp.isoformat()
                    if timestamp
                    else None
                )
            })

        return jsonify(output)

    except Exception as error:

        app.logger.exception(
            "History request failed: %s",
            error
        )

        return jsonify(
            error="Unable to load history."
        ), 500


# ============================================================
# ACCOUNT / PLAN
# ============================================================

@app.get("/api/me")
@user_required
def get_me():

    return jsonify({
        "email": request.user.get("email", ""),
        "plan": get_user_plan(request.user["uid"])
    })


@app.get("/api/upi-config")
def get_upi_config():
    """Public UPI payment details for the Pro plan (no secrets involved)."""

    upi_uri = (
        "upi://pay?pa=" + UPI_ID +
        "&pn=" + UPI_PAYEE_NAME.replace(" ", "%20") +
        "&am=" + PRO_PLAN_AMOUNT +
        "&cu=INR&tn=CyberLens%20Pro"
    )

    return jsonify({
        "upi_id": UPI_ID,
        "payee_name": UPI_PAYEE_NAME,
        "amount": PRO_PLAN_AMOUNT,
        "upi_uri": upi_uri,
    })


@app.post("/api/upi-payment")
@user_required
def submit_upi_payment():
    """Record a user's claimed UPI payment for manual verification."""

    data = request.get_json(silent=True) or {}
    utr = str(data.get("utr", "")).strip()

    if not utr:
        return jsonify(error="Enter the UPI transaction reference (UTR) number."), 400

    db.collection("payment_requests").document().set({
        "user_id": request.user["uid"],
        "email": request.user.get("email", ""),
        "utr": utr,
        "amount": PRO_PLAN_AMOUNT,
        "status": "pending",
        "createdAt": firestore.SERVER_TIMESTAMP,
    })

    return jsonify({"success": True}), 201


# ============================================================
# EXECUTIVE SUMMARY (free)
# ============================================================

@app.post("/api/summarize")
@user_required
def summarize():

    if not gemini:
        return jsonify(error="Gemini is not configured"), 503

    data = request.get_json(silent=True) or {}
    content = str(data.get("content", "")).strip()

    if not content:
        return jsonify(error="Nothing to summarize"), 400

    prompt = (
        "Rewrite the following technical security finding for a "
        "non-technical business executive. Explain the business risk, "
        "potential impact in plain language, and the recommended "
        "priority (low/medium/high/urgent). Avoid technical jargon. "
        "Keep it under 150 words.\n\n" + content
    )

    try:
        result = gemini.models.generate_content(
            model=MODEL,
            contents=prompt
        )
        return jsonify(summary=result.text or "")

    except Exception as error:
        app.logger.exception("Summarize failed: %s", error)
        return jsonify(
            error="Unable to generate summary right now."
        ), 500


# ============================================================
# AI AUTO-FIX (Pro)
# ============================================================

@app.post("/api/autofix")
@user_required
@pro_required
def autofix():

    if not gemini:
        return jsonify(error="Gemini is not configured"), 503

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()

    if not code:
        return jsonify(error="Paste some code to fix"), 400

    if len(code) > 6000:
        return jsonify(error="Code is too long (max 6000 characters)."), 400

    prompt = """
You are a secure coding assistant. Review the following code, identify
security issues, and return a corrected, more secure version.

Respond in this exact structure:

### Issues Found
- bullet list of issues

### Fixed Code
```
<corrected code here>
```

### What Changed
- bullet list explaining each fix

Code to review:
""" + code

    try:
        result = gemini.models.generate_content(
            model=MODEL,
            contents=prompt
        )
        return jsonify(result=result.text or "")

    except Exception as error:
        app.logger.exception("Autofix failed: %s", error)
        return jsonify(
            error="Unable to generate a fix right now."
        ), 500


# ============================================================
# PUBLIC SECURITY BADGE (Pro)
# ============================================================

def compute_grade(counts: dict) -> str:

    high = counts.get("high", 0)
    med = counts.get("med", 0)

    if high > 0:
        return "C"
    if med > 2:
        return "B"
    if med > 0:
        return "B+"
    return "A"


@app.post("/api/scan/<scan_id>/publish")
@user_required
@pro_required
def publish_scan(scan_id):

    doc_ref = db.collection("scan_jobs").document(scan_id)
    doc = doc_ref.get()

    if not doc.exists:
        return jsonify(error="Scan not found."), 404

    scan = doc.to_dict()

    if scan.get("user_id") != request.user["uid"]:
        return jsonify(error="Access denied."), 403

    if scan.get("status") != "completed":
        return jsonify(error="Only completed scans can be published."), 400

    doc_ref.update({"public": True})

    return jsonify({
        "success": True,
        "badge_url": "/badge/" + scan_id
    })


@app.get("/badge/<scan_id>")
def public_badge(scan_id):

    doc = db.collection("scan_jobs").document(scan_id).get()

    if not doc.exists or not doc.to_dict().get("public"):
        return Response("Badge not found or not public.", status=404)

    scan = doc.to_dict()
    findings = scan.get("findings") or []

    counts = {"high": 0, "med": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if "high" in sev or "critical" in sev:
            counts["high"] += 1
        elif "med" in sev:
            counts["med"] += 1
        else:
            counts["low"] += 1

    grade = compute_grade(counts)
    target = scan.get("target_url", "")

    page = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberLens AI — Verified Security Badge</title>
<style>
body{margin:0;font-family:system-ui,sans-serif;background:#050a13;color:#eef4ff;
display:grid;place-items:center;min-height:100vh}
.card{background:#0b1523;border:1px solid #1c2f48;border-radius:24px;
padding:40px;text-align:center;max-width:380px;box-shadow:0 24px 60px -12px rgba(0,0,0,.55)}
.grade{font-size:64px;font-weight:800;background:linear-gradient(90deg,#4b8bff,#8b5cf6);
-webkit-background-clip:text;color:transparent;margin:10px 0}
.target{color:#8ea0bd;font-size:13px;word-break:break-all}
.badge-tag{display:inline-block;margin-top:16px;font-size:11px;font-weight:700;
color:#8ea0bd;border:1px solid #1c2f48;border-radius:99px;padding:6px 14px}
</style></head>
<body>
<div class="card">
<div style="font-weight:700">🛡️ CyberLens AI</div>
<div class="grade">GRADE""" + " " + grade + """</div>
<div class="target">""" + target + """</div>
<div class="badge-tag">Verified security assessment</div>
</div>
</body></html>"""

    return Response(page, mimetype="text/html")


# ============================================================
# GRC WORKSPACE — ISO CONTROLS, RISK REGISTER, REMEDIATION, EVIDENCE
# ============================================================

DEFAULT_ISO_CONTROLS = [
    # Organizational controls (ISO/IEC 27001:2022 Annex A.5)
    ("A.5.1", "Policies for information security", "Organizational"),
    ("A.5.2", "Information security roles and responsibilities", "Organizational"),
    ("A.5.7", "Threat intelligence", "Organizational"),
    ("A.5.9", "Inventory of information and other associated assets", "Organizational"),
    ("A.5.12", "Classification of information", "Organizational"),
    ("A.5.15", "Access control", "Organizational"),
    ("A.5.23", "Information security for use of cloud services", "Organizational"),
    ("A.5.24", "Information security incident management planning", "Organizational"),
    ("A.5.30", "ICT readiness for business continuity", "Organizational"),
    ("A.5.31", "Legal, statutory, regulatory and contractual requirements", "Organizational"),
    # People controls (Annex A.6)
    ("A.6.1", "Screening", "People"),
    ("A.6.3", "Information security awareness, education and training", "People"),
    ("A.6.5", "Responsibilities after termination or change of employment", "People"),
    ("A.6.7", "Remote working", "People"),
    ("A.6.8", "Information security event reporting", "People"),
    # Physical controls (Annex A.7)
    ("A.7.1", "Physical security perimeters", "Physical"),
    ("A.7.4", "Physical security monitoring", "Physical"),
    ("A.7.9", "Security of assets off-premises", "Physical"),
    ("A.7.10", "Storage media", "Physical"),
    ("A.7.14", "Secure disposal or re-use of equipment", "Physical"),
    # Technological controls (Annex A.8)
    ("A.8.2", "Privileged access rights", "Technological"),
    ("A.8.5", "Secure authentication", "Technological"),
    ("A.8.7", "Protection against malware", "Technological"),
    ("A.8.8", "Management of technical vulnerabilities", "Technological"),
    ("A.8.9", "Configuration management", "Technological"),
    ("A.8.12", "Data leakage prevention", "Technological"),
    ("A.8.16", "Monitoring activities", "Technological"),
    ("A.8.20", "Networks security", "Technological"),
    ("A.8.23", "Web filtering", "Technological"),
    ("A.8.24", "Use of cryptography", "Technological"),
    ("A.8.25", "Secure development life cycle", "Technological"),
    ("A.8.28", "Secure coding", "Technological"),
]

VALID_CONTROL_STATUSES = {"implemented", "partial", "not_implemented", "na"}
VALID_TASK_STATUSES = {"open", "in_progress", "done"}
VALID_PRIORITIES = {"low", "medium", "high"}


def _controls_collection(uid: str):
    return db.collection("users").document(uid).collection("iso_controls")


def _ensure_controls_seeded(uid: str):
    """Seed the user's ISO control set on first access."""

    collection = _controls_collection(uid)

    if next(iter(collection.limit(1).stream()), None) is not None:
        return

    batch = db.batch()
    for code, title, category in DEFAULT_ISO_CONTROLS:
        doc_ref = collection.document()
        batch.set(doc_ref, {
            "code": code,
            "title": title,
            "category": category,
            "status": "not_implemented",
            "notes": "",
            "createdAt": firestore.SERVER_TIMESTAMP,
        })
    batch.commit()


@app.get("/api/grc/controls")
@user_required
def get_grc_controls():

    try:
        uid = request.user["uid"]
        _ensure_controls_seeded(uid)

        docs = _controls_collection(uid).order_by("code").stream()

        controls = [dict(id=d.id, **{k: v for k, v in d.to_dict().items() if k != "createdAt"}) for d in docs]

        return jsonify(controls=controls)

    except Exception as error:
        app.logger.exception("Loading GRC controls failed: %s", error)
        return jsonify(error="Unable to load controls."), 500


@app.patch("/api/grc/controls/<control_id>")
@user_required
def update_grc_control(control_id):

    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()

    if status not in VALID_CONTROL_STATUSES:
        return jsonify(error="Invalid status."), 400

    try:
        uid = request.user["uid"]
        doc_ref = _controls_collection(uid).document(control_id)

        if not doc_ref.get().exists:
            return jsonify(error="Control not found."), 404

        update = {"status": status}
        if "notes" in data:
            update["notes"] = str(data.get("notes", ""))[:2000]

        doc_ref.update(update)

        return jsonify(success=True)

    except Exception as error:
        app.logger.exception("Updating GRC control failed: %s", error)
        return jsonify(error="Unable to update control."), 500


def _risks_collection(uid: str):
    return db.collection("users").document(uid).collection("risks")


@app.get("/api/grc/risks")
@user_required
def get_risks():

    try:
        uid = request.user["uid"]
        docs = (
            _risks_collection(uid)
            .order_by("createdAt", direction=firestore.Query.DESCENDING)
            .stream()
        )

        risks = [dict(id=d.id, **{k: v for k, v in d.to_dict().items() if k != "createdAt"}) for d in docs]

        return jsonify(risks=risks)

    except Exception as error:
        app.logger.exception("Loading risk register failed: %s", error)
        return jsonify(error="Unable to load risk register."), 500


@app.post("/api/grc/risks")
@user_required
def create_risk():

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:200]

    if not title:
        return jsonify(error="Enter a risk title."), 400

    try:
        likelihood = max(1, min(5, int(data.get("likelihood", 3))))
    except (TypeError, ValueError):
        likelihood = 3

    try:
        impact = max(1, min(5, int(data.get("impact", 3))))
    except (TypeError, ValueError):
        impact = 3

    description = str(data.get("description", "")).strip()[:1000]

    try:
        uid = request.user["uid"]
        doc_ref = _risks_collection(uid).document()
        doc_ref.set({
            "title": title,
            "description": description,
            "likelihood": likelihood,
            "impact": impact,
            "score": likelihood * impact,
            "status": "open",
            "createdAt": firestore.SERVER_TIMESTAMP,
        })

        return jsonify(id=doc_ref.id, success=True), 201

    except Exception as error:
        app.logger.exception("Creating risk failed: %s", error)
        return jsonify(error="Unable to add risk."), 500


@app.delete("/api/grc/risks/<risk_id>")
@user_required
def delete_risk(risk_id):

    try:
        uid = request.user["uid"]
        _risks_collection(uid).document(risk_id).delete()
        return jsonify(success=True)

    except Exception as error:
        app.logger.exception("Deleting risk failed: %s", error)
        return jsonify(error="Unable to delete risk."), 500


def _remediation_collection(uid: str):
    return db.collection("users").document(uid).collection("remediation")


@app.get("/api/grc/remediation")
@user_required
def get_remediation():

    try:
        uid = request.user["uid"]
        docs = (
            _remediation_collection(uid)
            .order_by("createdAt", direction=firestore.Query.DESCENDING)
            .stream()
        )

        tasks = [dict(id=d.id, **{k: v for k, v in d.to_dict().items() if k != "createdAt"}) for d in docs]

        return jsonify(tasks=tasks)

    except Exception as error:
        app.logger.exception("Loading remediation tasks failed: %s", error)
        return jsonify(error="Unable to load remediation tasks."), 500


@app.post("/api/grc/remediation")
@user_required
def create_remediation_task():

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:200]

    if not title:
        return jsonify(error="Enter a task title."), 400

    priority = str(data.get("priority", "medium")).strip().lower()
    if priority not in VALID_PRIORITIES:
        priority = "medium"

    try:
        uid = request.user["uid"]
        doc_ref = _remediation_collection(uid).document()
        doc_ref.set({
            "title": title,
            "description": str(data.get("description", "")).strip()[:1000],
            "priority": priority,
            "status": "open",
            "due_date": str(data.get("due_date", "")).strip()[:20],
            "createdAt": firestore.SERVER_TIMESTAMP,
        })

        return jsonify(id=doc_ref.id, success=True), 201

    except Exception as error:
        app.logger.exception("Creating remediation task failed: %s", error)
        return jsonify(error="Unable to add task."), 500


@app.patch("/api/grc/remediation/<task_id>")
@user_required
def update_remediation_task(task_id):

    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().lower()

    if status not in VALID_TASK_STATUSES:
        return jsonify(error="Invalid status."), 400

    try:
        uid = request.user["uid"]
        doc_ref = _remediation_collection(uid).document(task_id)

        if not doc_ref.get().exists:
            return jsonify(error="Task not found."), 404

        doc_ref.update({"status": status})

        return jsonify(success=True)

    except Exception as error:
        app.logger.exception("Updating remediation task failed: %s", error)
        return jsonify(error="Unable to update task."), 500


@app.delete("/api/grc/remediation/<task_id>")
@user_required
def delete_remediation_task(task_id):

    try:
        uid = request.user["uid"]
        _remediation_collection(uid).document(task_id).delete()
        return jsonify(success=True)

    except Exception as error:
        app.logger.exception("Deleting remediation task failed: %s", error)
        return jsonify(error="Unable to delete task."), 500


def _evidence_collection(uid: str):
    return db.collection("users").document(uid).collection("evidence")


@app.get("/api/grc/evidence")
@user_required
def get_evidence():

    try:
        uid = request.user["uid"]
        docs = (
            _evidence_collection(uid)
            .order_by("createdAt", direction=firestore.Query.DESCENDING)
            .stream()
        )

        items = [dict(id=d.id, **{k: v for k, v in d.to_dict().items() if k != "createdAt"}) for d in docs]

        return jsonify(evidence=items)

    except Exception as error:
        app.logger.exception("Loading evidence failed: %s", error)
        return jsonify(error="Unable to load evidence."), 500


@app.post("/api/grc/evidence")
@user_required
def create_evidence():

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:200]

    if not title:
        return jsonify(error="Enter an evidence title."), 400

    try:
        uid = request.user["uid"]
        doc_ref = _evidence_collection(uid).document()
        doc_ref.set({
            "title": title,
            "description": str(data.get("description", "")).strip()[:1000],
            "link": str(data.get("link", "")).strip()[:500],
            "createdAt": firestore.SERVER_TIMESTAMP,
        })

        return jsonify(id=doc_ref.id, success=True), 201

    except Exception as error:
        app.logger.exception("Creating evidence record failed: %s", error)
        return jsonify(error="Unable to save evidence."), 500


@app.delete("/api/grc/evidence/<evidence_id>")
@user_required
def delete_evidence(evidence_id):

    try:
        uid = request.user["uid"]
        _evidence_collection(uid).document(evidence_id).delete()
        return jsonify(success=True)

    except Exception as error:
        app.logger.exception("Deleting evidence failed: %s", error)
        return jsonify(error="Unable to delete evidence."), 500


@app.get("/api/grc/readiness")
@user_required
def get_grc_readiness():
    """Aggregate dashboard: control coverage, risk register and remediation stats."""

    try:
        uid = request.user["uid"]
        _ensure_controls_seeded(uid)

        controls = [d.to_dict() for d in _controls_collection(uid).stream()]
        applicable = [c for c in controls if c.get("status") != "na"]

        implemented = sum(1 for c in applicable if c.get("status") == "implemented")
        partial = sum(1 for c in applicable if c.get("status") == "partial")
        total_applicable = len(applicable) or 1

        readiness_pct = ((implemented + (partial * 0.5)) / total_applicable) * 100

        risks = [d.to_dict() for d in _risks_collection(uid).stream()]
        open_risks = [r for r in risks if r.get("status", "open") == "open"]
        avg_score = (
            round(sum(r.get("score", 0) for r in open_risks) / len(open_risks), 1)
            if open_risks else 0
        )

        tasks = [d.to_dict() for d in _remediation_collection(uid).stream()]
        open_tasks = sum(1 for t in tasks if t.get("status") != "done")

        evidence_count = len(list(_evidence_collection(uid).stream()))

        return jsonify({
            "control_readiness_pct": round(readiness_pct, 1),
            "controls_total": len(controls),
            "controls_implemented": implemented,
            "controls_partial": partial,
            "open_risks": len(open_risks),
            "avg_risk_score": avg_score,
            "open_remediation": open_tasks,
            "evidence_count": evidence_count,
        })

    except Exception as error:
        app.logger.exception("Computing GRC readiness failed: %s", error)
        return jsonify(error="Unable to compute readiness."), 500


# ============================================================
# TEMPORARY PRO ACCESS (internal testing only)
# ============================================================

DEV_TEST_SECRET = os.environ.get("DEV_TEST_SECRET", "")
TEMP_PRO_HOURS = 24


@app.post("/api/dev/grant-temp-pro")
@user_required
def grant_temp_pro():
    """Grants the calling user temporary Pro access, for internal testing.

    Requires DEV_TEST_SECRET to be set on the server and sent back in the
    X-Dev-Secret header. Access auto-expires after TEMP_PRO_HOURS.
    """

    if not DEV_TEST_SECRET:
        return jsonify(error="Temporary Pro access is not enabled on this server."), 404

    if request.headers.get("X-Dev-Secret", "") != DEV_TEST_SECRET:
        return jsonify(error="Invalid dev secret."), 403

    try:
        uid = request.user["uid"]
        expires_at = time.time() + (TEMP_PRO_HOURS * 3600)

        db.collection("users").document(uid).set({
            "plan": "pro",
            "temp_pro_until": expires_at,
        }, merge=True)

        return jsonify(success=True, expires_at=expires_at, hours=TEMP_PRO_HOURS)

    except Exception as error:
        app.logger.exception("Granting temp pro access failed: %s", error)
        return jsonify(error="Unable to grant temporary access."), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
