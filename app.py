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
# ==========================================================hoctype html>
HTML = """
<html>
<head>

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>CyberLens AI</title>

<style>

*{
    box-sizing:border-box
}

body{
    margin:0;
    font-family:Inter,system-ui;
    background:#07111f;
    color:#eaf1ff
}

.wrap{
    max-width:1100px;
    margin:auto;
    padding:28px 18px
}

.nav{
    display:flex;
    justify-content:space-between;
    align-items:center
}

.logo{
    font-size:22px;
    font-weight:800
}

.badge{
    font-size:12px;
    padding:7px 11px;
    border:1px solid #2d4060;
    border-radius:20px;
    color:#9bb4d9
}

.hero{
    display:grid;
    grid-template-columns:1.15fr .85fr;
    gap:24px;
    align-items:center;
    padding:60px 0
}

h1{
    font-size:50px;
    line-height:1.02;
    margin:12px 0
}

.grad{
    background:linear-gradient(
        90deg,
        #52b8ff,
        #8b5cff
    );
    -webkit-background-clip:text;
    color:transparent
}

p{
    color:#9eb0c9;
    line-height:1.6
}

.card{
    background:#0d1a2b;
    border:1px solid #203451;
    border-radius:22px;
    padding:24px;
    box-shadow:0 20px 60px #0004
}

.shield{
    height:290px;
    display:grid;
    place-items:center;
    background:radial-gradient(
        circle,
        #243c70,
        #0d1a2b 60%
    );
    font-size:110px
}

input,
textarea{
    width:100%;
    background:#081522;
    border:1px solid #2a405e;
    border-radius:12px;
    color:white;
    padding:14px;
    margin:7px 0;
    font:inherit
}

button{
    background:linear-gradient(
        90deg,
        #5a54ff,
        #874dff
    );
    color:white;
    border:0;
    border-radius:11px;
    padding:13px 18px;
    font-weight:800;
    cursor:pointer
}

button.alt{
    background:#182940
}

.row{
    display:flex;
    gap:10px;
    flex-wrap:wrap
}

.hidden{
    display:none
}

.muted{
    color:#8195b2;
    font-size:13px
}

pre{
    white-space:pre-wrap;
    line-height:1.6;
    background:#081522;
    border-radius:14px;
    padding:16px;
    color:#d9e7ff
}

.history{
    margin-top:15px
}

.item{
    padding:12px;
    border-bottom:1px solid #203451;
    color:#cbd8ea;
    font-size:13px
}

@media(max-width:800px){

    .hero{
        grid-template-columns:1fr;
        padding:35px 0
    }

    h1{
        font-size:39px
    }

    .shield{
        height:180px;
        font-size:70px
    }

}
.quick-checks{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
    margin:10px 0 14px;
}

.quick-btn{
    width:auto;
    background:rgba(82,184,255,.08);
    border:1px solid rgba(82,184,255,.22);
    color:#a9d9ff;
    border-radius:999px;
    padding:8px 12px;
    font-size:12px;
    font-weight:700;
    cursor:pointer;
    transition:.2s ease;
}

.quick-btn:hover{
    background:rgba(82,184,255,.16);
    border-color:rgba(82,184,255,.45);
    transform:translateY(-1px);
.input-meta{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:12px;
    margin:8px 2px 14px;
    color:#7f93aa;
    font-size:12px;
}

.input-hint{
    opacity:.8;
}

.input-actions{
    display:flex;
    align-items:center;
    gap:10px;
}

#charCount{
    font-variant-numeric:tabular-nums;
    white-space:nowrap;
}

.clear-btn{
    width:auto;
    padding:6px 10px;
    border:1px solid rgba(255,255,255,.12);
    border-radius:8px;
    background:rgba(255,255,255,.04);
    color:#aebed0;
    font-size:11px;
    font-weight:700;
    cursor:pointer;
    transition:.2s ease;
}

.clear-btn:hover{
    background:rgba(82,184,255,.10);
    border-color:rgba(82,184,255,.30);
    color:#d9efff;
    transform:translateY(-1px);
}
.analyze-loading{
    opacity:.7;
    cursor:wait !important;
    transform:scale(.98);
}
.scan-card{
    margin:18px 0 16px;
    padding:22px;
    border:1px solid rgba(82,184,255,.20);
    border-radius:22px;
    background:
        linear-gradient(135deg,rgba(17,31,58,.92),rgba(8,17,36,.96));
    box-shadow:
        0 18px 45px rgba(0,0,0,.28),
        inset 0 1px 0 rgba(255,255,255,.05);
}

.scan-card-header{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:18px;
    margin-bottom:20px;
}

.scan-eyebrow{
    display:inline-block;
    margin-bottom:7px;
    color:#72c8ff;
    font-size:11px;
    font-weight:800;
    letter-spacing:1.2px;
}

.scan-card h3{
    margin:0 0 7px;
    font-size:21px;
}

.scan-card p{
    margin:0;
    color:#91a8c4;
    font-size:13px;
    line-height:1.5;
}

.scan-status{
    padding:6px 10px;
    border:1px solid rgba(82,184,255,.25);
    border-radius:999px;
    color:#72c8ff;
    font-size:10px;
    font-weight:800;
    letter-spacing:.8px;
}

.scan-label{
    display:block;
    margin-bottom:7px;
    color:#b8c9dc;
    font-size:12px;
    font-weight:700;
}

#scanTarget,
#scanProfile{
    width:100%;
    box-sizing:border-box;
    border:1px solid rgba(82,184,255,.18);
    border-radius:12px;
    background:rgba(4,12,27,.72);
    color:#eaf5ff;
    padding:13px 14px;
    outline:none;
}

#scanTarget:focus,
#scanProfile:focus{
    border-color:rgba(82,184,255,.65);
    box-shadow:0 0 0 3px rgba(82,184,255,.08);
}

.scan-authorization{
    display:flex;
    align-items:center;
    gap:9px;
    margin:15px 0 18px;
    color:#9db1c8;
    font-size:12px;
}

.scan-authorization input{
    width:16px;
    height:16px;
}

.scan-controls{
    display:grid;
    grid-template-columns:1fr auto;
    gap:14px;
    align-items:end;
}

.scan-start-btn{
    width:auto;
    min-width:190px;
    padding:13px 18px;
    border:1px solid rgba(82,184,255,.35);
    border-radius:12px;
    background:linear-gradient(135deg,#258cff,#46c8ff);
    color:#fff;
    font-weight:800;
    cursor:pointer;
    transition:.2s ease;
}

.scan-start-btn:hover{
    transform:translateY(-2px);
    box-shadow:0 10px 25px rgba(37,140,255,.22);
}

.scan-progress{
    margin-top:18px;
    padding:14px;
    border-radius:14px;
    background:rgba(82,184,255,.05);
    border:1px solid rgba(82,184,255,.12);
}

.scan-progress-top{
    display:flex;
    justify-content:space-between;
    gap:12px;
    margin-bottom:9px;
    color:#a9bdd3;
    font-size:12px;
}

.scan-progress-bar{
    height:5px;
    overflow:hidden;
    border-radius:999px;
    background:rgba(255,255,255,.08);
}

#scanProgressFill{
    display:block;
    width:8%;
    height:100%;
    border-radius:inherit;
    background:linear-gradient(90deg,#258cff,#72d8ff);
    transition:width .4s ease;
}

#scanIdText{
    display:block;
    margin-top:9px;
    color:#71869f;
    font-size:11px;
}

@media (max-width:700px){
    .scan-card-header,
    .scan-controls{
        grid-template-columns:1fr;
        flex-direction:column;
    }

    .scan-start-btn{
        width:100%;
    }
}
</style>

</head>

<body>

<div class="wrap">


<div class="nav">

    <div class="logo">
        🛡️ Cyber<span class="grad">Lens</span> AI
    </div>

    <span class="badge">
        Powered by Gemini
    </span>

</div>


<section id="landing" class="hero">

<div>

    <span class="badge">
        DEFENSIVE SECURITY COPILOT
    </span>

    <h1>
        Your AI-powered
        <span class="grad">
            Security Assistant
        </span>
    </h1>

    <p>
        Analyze web-security scenarios,
        understand risk, structure manual testing,
        and get practical remediation guidance.
    </p>

    <button onclick="showAuth()">
        Get Started →
    </button>

</div>


<div class="card shield">
    🛡️
</div>

</section>


<section
    id="auth"
    class="card hidden"
    style="max-width:520px;margin:40px auto"
>

    <h2>
        Welcome to CyberLens AI
    </h2>

    <p>
        Sign in to keep your private security analysis history.
    </p>

    <input
        id="email"
        type="email"
        placeholder="Email address"
    >

    <input
        id="pw"
        type="password"
        placeholder="Password (6+ characters)"
    >

    <div class="row">

        <button onclick="signup()">
            Create account
        </button>

        <button
            class="alt"
            onclick="login()"
        >
            Sign in
        </button>

    </div>

    <p id="msg"></p>

</section>


<section id="app" class="hidden">


<div
    class="row"
    style="justify-content:space-between;align-items:center"
>

    <div>

        <h2>
            AI Security Assistant
        </h2>

        <span
            class="muted"
            id="who"
        ></span>

    </div>

    <button
        class="alt"
        onclick="logout()"
    >
        Sign out
    </button>

</div>


<div
    class="card"
    style="margin-top:15px"
>

    <textarea
        id="q"
        rows="7"
        placeholder="Example: How should I manually test a web app for broken access control in an authorized lab?"
    ></textarea>
    <div class="scan-card">
    <div class="scan-card-header">
        <div>
            <span class="scan-eyebrow">SECURITY ASSESSMENT</span>
            <h3>Scan an Authorized Website</h3>
            <p>Assess your website for security weaknesses and configuration risks.</p>
        </div>
        <span class="scan-status">READY</span>
    </div>

    <label class="scan-label" for="scanTarget">Target Website</label>

    <input
        id="scanTarget"
        type="url"
        placeholder="https://your-authorized-website.com"
        autocomplete="url"
    >

    <label class="scan-authorization">
        <input type="checkbox" id="scanAuthorized">
        <span>I confirm that I am authorized to assess this website.</span>
    </label>

    <div class="scan-controls">
        <div>
            <label class="scan-label" for="scanProfile">Scan Profile</label>
            <select id="scanProfile">
                <option value="passive">Passive Assessment</option>
                <option value="safe_active">Safe Active Assessment</option>
            </select>
        </div>

        <button
            type="button"
            class="scan-start-btn"
            onclick="startSecurityScan()"
        >
            Start Security Scan →
        </button>
    </div>

    <div id="scanStatus" class="scan-progress" hidden>
        <div class="scan-progress-top">
            <span>Initializing assessment</span>
            <span id="scanStatusText">Queued</span>
        </div>
        <div class="scan-progress-bar">
            <span id="scanProgressFill"></span>
        </div>
        <small id="scanIdText"></small>
    </div>
</div>
<div class="quick-checks">
    <span class="muted">Quick security checks</span>
    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for SQL Injection in an authorized lab?'">SQL Injection</button>
    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for Cross-Site Scripting (XSS) in an authorized lab?'">XSS</button>
    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I manually test a web application for Broken Access Control in an authorized lab?'">Access Control</button>
    <button type="button" class="quick-btn" onclick="document.getElementById('q').value='How should I review security headers of an authorized web application?'">Security Headers</button>
    
</div>
<div class="input-meta">
    <span class="input-hint">
        Ctrl + Enter to analyze
    </span>

    <div class="input-actions">
        <span id="charCount">0 / 2000</span>
        <button
            type="button"
            class="clear-btn"
            onclick="clearPrompt()"
        >
            Clear
        </button>
    </div>
</div>
    <div
        class="row"
        style="justify-content:space-between;align-items:center"
    >

        <span class="muted">
            Authorized / defensive testing only
        </span>

        <button onclick="analyze()">
            Analyze with Gemini
        </button>

    </div>


    <div id="out"></div>

</div>


<div class="card history">

    <h3>
        Recent analyses
    </h3>

    <div
        id="hist"
        class="muted"
    >
        No analyses yet.
    </div>

</div>


</section>


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
    onAuthStateChanged
}
from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";


let A;


const $ = x =>
    document.getElementById(x);


async function boot(){

    try{

        const response =
            await fetch("/config");


        if(!response.ok){

            throw new Error(
                "Unable to load Firebase configuration"
            );

        }


        const config =
            await response.json();


        A = getAuth(
            initializeApp(config)
        );


        onAuthStateChanged(
            A,
            user => {

                if(user){

                    $("landing")
                        .classList
                        .add("hidden");

                    $("auth")
                        .classList
                        .add("hidden");

                    $("app")
                        .classList
                        .remove("hidden");

                    $("who")
                        .textContent =
                        user.email || "";

                    history();

                }

                else{

                    $("landing")
                        .classList
                        .remove("hidden");

                    $("auth")
                        .classList
                        .add("hidden");

                    $("app")
                        .classList
                        .add("hidden");

                }

            }
        );


    }

    catch(error){

        console.error(error);

        $("msg").textContent =
            "Application configuration failed.";

    }

}


window.showAuth = () => {

    $("landing")
        .classList
        .add("hidden");

    $("auth")
        .classList
        .remove("hidden");

};


window.signup = async () => {

    $("msg").textContent = "";

    try{

        const email =
            $("email").value.trim();

        const password =
            $("pw").value;


        if(!email || !password){

            $("msg").textContent =
                "Enter email and password.";

            return;

        }


        await createUserWithEmailAndPassword(
            A,
            email,
            password
        );

    }

    catch(error){

        $("msg").textContent =
            error.message;

    }

};


window.login = async () => {

    $("msg").textContent = "";

    try{

        const email =
            $("email").value.trim();

        const password =
            $("pw").value;


        if(!email || !password){

            $("msg").textContent =
                "Enter email and password.";

            return;

        }


        await signInWithEmailAndPassword(
            A,
            email,
            password
        );

    }

    catch(error){

        $("msg").textContent =
            error.message;

    }

};


window.logout = async () => {

    try{

        await signOut(A);

    }

    catch(error){

        console.error(error);

    }

};

const promptBox = $("q");
const charCount = $("charCount");

if(promptBox && charCount){
    promptBox.addEventListener("input", () => {
        charCount.textContent =
            promptBox.value.length + " / 2000";
    });
}if(promptBox){
    promptBox.addEventListener("keydown", (event) => {
        if(event.ctrlKey && event.key === "Enter"){
            event.preventDefault();
            analyze();
        }
    });
}
function clearPrompt(){
    const promptBox = $("q");

    if(promptBox){
        promptBox.value = "";
        promptBox.focus();
    }

    const charCount = $("charCount");

    if(charCount){
        charCount.textContent = "0 / 2000";
    }
}

window.analyze = async () => {
window.analyze = async () => {

    const user =
        A.currentUser;

    const question =
        $("q").value.trim();


    if(!user){

        $("out").innerHTML =
            "<p>Please sign in first.</p>";

        return;

    }


    if(!question){

        $("out").innerHTML =
            "<p>Enter a security scenario.</p>";

        return;

    }

const analyzeBtn =
    document.querySelector('button[onclick="analyze()"]');

if(analyzeBtn){
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing…";
}
    try{

        const token =
            await user.getIdToken();


        $("out").innerHTML =
            "<p>Gemini is analyzing…</p>";


        const response =
            await fetch(
                "/api/analyze",
                {
                    method:"POST",

                    headers:{
                        "Content-Type":
                            "application/json",

                        "Authorization":
                            "Bearer " + token
                    },

                    body:JSON.stringify({
                        prompt:question
                    })
                }
            );


        const data =
            await response.json();


        if(response.ok){

            $("out").innerHTML =
                "<pre>" +
                esc(data.answer || "") +
                "</pre>";


            $("q").value = "";


            history();
if(analyzeBtn){
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze with Gemini";
}
        }

        else{

            $("out").innerHTML =
                "<p>" +
                esc(
                    data.error ||
                    "Request failed"
                ) +
                "</p>";

        }

    }

    catch(error){
if(analyzeBtn){
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze with Gemini";
}
        console.error(error);

        $("out").innerHTML =
            "<p>Request failed. Check the server.</p>";

    }

};


async function history(){

    const user =
        A.currentUser;


    if(!user){

        return;

    }


    try{

        const token =
            await user.getIdToken();


        const response =
            await fetch(
                "/api/history",
                {
                    headers:{
                        "Authorization":
                            "Bearer " + token
                    }
                }
            );


        const data =
            await response.json();


        if(!response.ok){

            $("hist").textContent =
                data.error ||
                "Unable to load history.";

            return;

        }


        $("hist").innerHTML =
            data.length

            ? data.map(
                x => `
                    <div class="item">

                        <b>
                            ${esc(
                                (x.prompt || "")
                                .slice(0,90)
                            )}
                        </b>

                        <br>

                        <span class="muted">
                            ${esc(
                                x.createdAt || ""
                            )}
                        </span>

                    </div>
                `
            ).join("")

            : "No analyses yet.";

    }

    catch(error){

        console.error(error);

        $("hist").textContent =
            "Unable to load history.";

    }

}


function esc(value){

    return String(value).replace(
        /[&<>"']/g,

        character => ({
            "&":"&amp;",
            "<":"&lt;",
            ">":"&gt;",
            '"':"&quot;",
            "'":"&#039;"
        }[character])
    );

}


boot();
async function startSecurityScan(){
    const target = document.getElementById("scanTarget").value.trim();
    const authorized = document.getElementById("scanAuthorized").checked;
    const profile = document.getElementById("scanProfile").value;

    const statusBox = document.getElementById("scanStatus");
    const statusText = document.getElementById("scanStatusText");
    const scanIdText = document.getElementById("scanIdText");
    const progressFill = document.getElementById("scanProgressFill");

    if(!target){
        alert("Enter an authorized website URL.");
        return;
    }

    if(!authorized){
        alert("Please confirm that you are authorized to assess this website.");
        return;
    }

    statusBox.hidden = false;
    statusText.textContent = "Submitting...";
    progressFill.style.width = "20%";

    try{
        const user = A.currentUser;

        if(!user){
            statusText.textContent = "Sign in required";
            return;
        }

        const token = await user.getIdToken();

        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
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

        statusText.textContent = "Queued";
        progressFill.style.width = "35%";

        if(data.scan && data.scan.scan_id){
            scanIdText.textContent = "Scan ID: " + data.scan.scan_id;
        }

    }catch(error){
        console.error(error);
        statusText.textContent = "Failed";
        scanIdText.textContent = error.message;
        progressFill.style.width = "0%";
    }
}
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

    keys = [
        "FIREBASE_API_KEY",
        "FIREBASE_AUTH_DOMAIN",
        "FIREBASE_PROJECT_ID",
        "FIREBASE_STORAGE_BUCKET",
        "FIREBASE_MESSAGING_SENDER_ID",
        "FIREBASE_APP_ID"
    ]

    return jsonify({
        key: os.environ.get(key, "")
        for key in keys
    })


# ============================================================
# AUTHENTICATION
# ============================================================

def user_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        header = request.headers.get("Authorization", "")

        try:

            if not header.startswith(
                "Bearer "
            ):

                raise ValueError(
                    "Missing bearer token"
                )


            token = header[7:]


            request.user = auth.verify_id_token(token)


            return function(
                *args,
                **kwargs
            )


        except Exception:

            return jsonify(
                error="Authentication required"
            ), 401


    return wrapper
# ============================================================
# SECURITY SCAN API
# ============================================================

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

    if profile not in {"passive", "safe_active"}:
        return jsonify(
            error="Invalid scan profile."
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
                contents=
                    system +
                    "\n\nScenario:\n" +
                    prompt
            )


        answer = result.text or "No response."


        reference = (
            db
            .collection("users")
            .document(
                request.user["uid"]
            )
            .collection("analyses")
            .document()
        )


        reference.set({

            "prompt": prompt,

            "answer": answer,

            "createdAt":
                firestore.SERVER_TIMESTAMP

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
            error=
                "AI request failed; "
                "check server configuration."
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
            .document(
                request.user["uid"]
            )
            .collection("analyses")
            .order_by(
                "createdAt",
                direction=
                    firestore.Query.DESCENDING
            )
            .limit(20)
            .stream()
        )


        output = []


        for document in documents:

            data = document.to_dict()


            timestamp = data.get("createdAt")


            output.append({

                "id":
                    document.id,

                "prompt":
                    data.get(
                        "prompt",
                        ""
                    ),

                "answer":
                    data.get(
                        "answer",
                        ""
                    ),

                "createdAt":
                    (
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
        port=int(
            os.environ.get(
                "PORT",
                8080
            )
        )
          )
