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

.history-list .item b{font-weight:600;color:var(--text);display:block;margin-bottom:3px;font-size:13.5px}

::-webkit-scrollbar{width:9px}

::-webkit-scrollbar-thumb{background:var(--border);border-radius:99px}

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
            <button class="btn-primary btn-full" onclick="showAuth()">Upgrade to Pro</button>
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
                        <span class="eyebrow">Activity</span>
                        <h3>Recent analyses</h3>
                    </div>
                </div>
                <div id="hist" class="history-list muted">No analyses yet.</div>
            </div>
        </div>

    </div>
</div>
</section>


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
    """Read the user's plan from Firestore. Defaults to 'free'."""

    try:
        doc = db.collection("users").document(uid).get()
        if doc.exists:
            return str(doc.to_dict().get("plan", "free")).lower()
    except Exception:
        pass

    return "free"


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

def run_scan_job(scan_id: str, target_url: str) -> None:
    """Run a scan in the background and update its Firestore job."""

    job_ref = db.collection("scan_jobs").document(scan_id)

    try:
        job_ref.update({
            "status": "scanning"
        })

        result = run_assessment(target_url)

        job_ref.update({
            "status": "completed",
            "evidence": result["evidence"],
            "findings": result["findings"],
            "findings_count": result["findings_count"],
            "error": None,
        })

    except Exception as exc:
        job_ref.update({
            "status": "failed",
            "error": str(exc),
        })


@app.post("/api/scan")
@user_required
def create_scan():
    data = request.get_json(silent=True) or {}
    target_url = str(data.get("target_url", "")).strip()
    profile = str(data.get("profile", "passive")).strip().lower()
    authorized = data.get("authorized", False)

    if not authorized:
        return jsonify(
            error="Authorization confirmation is required."
        ), 400

    if profile != "passive":
        return jsonify(
            error="Safe Active Assessment is not available yet."
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
        args=(job.scan_id, result),
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

        result = run_assessment(target_url)

        job_ref.update({
            "status": "completed",
            "findings": result["findings"],
            "findings_count": result["findings_count"],
            "error": None,
        })

    except Exception as exc:
        job_ref.update({
            "status": "failed",
            "error": str(exc),
        })


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
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
