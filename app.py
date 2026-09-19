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

app = Flask(__name__)


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
    display:flex;align-items:center;justify-content:space-between;
    padding:16px 24px;max-width:1180px;margin:0 auto;
}

.brand{display:flex;align-items:center;gap:10px;font-family:'Sora';font-weight:700;font-size:19px}

.brand svg{flex-shrink:0}

.brand span.hl{background:linear-gradient(90deg,var(--accent),var(--accent-2));-webkit-background-clip:text;color:transparent}

.nav-links{display:flex;gap:32px;align-items:center}

.nav-links a{color:var(--text-muted);text-decoration:none;font-size:14px;font-weight:500}

.nav-links a:hover{color:var(--text)}

.nav-cta{display:flex;gap:10px;align-items:center}

@media(max-width:820px){.nav-links{display:none}}

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

.scan-finding{
    display:flex;gap:12px;padding:13px 0;
    border-top:1px solid var(--border-soft);font-size:13.5px;
}

.scan-finding:first-child{border-top:none}

.scan-finding .sev-dot{margin-top:5px}

.scan-finding b{display:block;color:var(--text);margin-bottom:2px;font-size:13.5px}

.scan-finding p{font-size:12.5px;margin:0}

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
            <a href="#trust">Why teams use it</a>
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

    <div class="report-card">
        <div class="report-head">
            <span class="url">scan · your-company.com</span>
            <span class="status-chip">Completed</span>
        </div>
        <div class="report-score">
            <span class="num">B+</span>
            <span class="muted">Security grade</span>
        </div>
        <div class="finding-row">
            <span class="sev-dot sev-high"></span>
            <span class="label">Missing Content-Security-Policy header</span>
            <span class="tag">HIGH</span>
        </div>
        <div class="finding-row">
            <span class="sev-dot sev-med"></span>
            <span class="label">Outdated TLS cipher suite in use</span>
            <span class="tag">MEDIUM</span>
        </div>
        <div class="finding-row">
            <span class="sev-dot sev-low"></span>
            <span class="label">Verbose server banner exposed</span>
            <span class="tag">LOW</span>
        </div>
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

<div class="wrap" id="trust">
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

                <textarea id="q" rows="6" placeholder="Example: How should I manually test a web app for broken access control in an authorized lab?"></textarea>

                <div class="quick-checks">
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
    onAuthStateChanged
}
from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";

let A;

const $ = x => document.getElementById(x);

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
            body:JSON.stringify({ prompt:question })
        });

        const data = await response.json();

        if(response.ok){
            $("out").innerHTML = "<pre>" + esc(data.answer || "") + "</pre>";
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

function severityDot(sev){
    const s = String(sev || "").toLowerCase();
    if(s.includes("high") || s.includes("critical")) return "sev-high";
    if(s.includes("med")) return "sev-med";
    return "sev-low";
}

function renderScanFindings(findings){

    const box = $("scanResults");
    if(!box){ return; }

    if(!Array.isArray(findings) || findings.length === 0){
        box.innerHTML = '<p class="muted" style="margin-top:10px">No issues found in this assessment.</p>';
        return;
    }

    box.innerHTML = findings.map(f => {
        const title = esc(f.title || f.name || "Finding");
        const desc = esc(f.description || f.detail || f.summary || "");
        const sev = esc(f.severity || "info");
        return `
            <div class="scan-finding">
                <span class="sev-dot ${severityDot(f.severity)}"></span>
                <div>
                    <b>${title}</b>
                    <p>${desc}</p>
                </div>
            </div>
        `;
    }).join("");

}

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
            renderScanFindings(scan.findings);
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

    if not prompt:
        return jsonify(
            error="Enter a scenario"
        ), 400

    system = """
You are CyberLens AI, a defensive cybersecurity assistant.

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
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
