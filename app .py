import os
from functools import wraps
from flask import Flask, request, jsonify, Response
import firebase_admin
from firebase_admin import auth, firestore
from google import genai

app = Flask(__name__)

if not firebase_admin._apps:
    firebase_admin.initialize_app()

db = firestore.client()
gemini = genai.Client(api_key=os.environ["GEMINI_API_KEY"]) if os.environ.get("GEMINI_API_KEY") else None
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

HTML = r"""<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberLens AI</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui;background:#07111f;color:#eaf1ff}
.wrap{max-width:1100px;margin:auto;padding:28px 18px}.nav{display:flex;justify-content:space-between;align-items:center}
.logo{font-size:22px;font-weight:800}.logo b{color:#6c63ff}.badge{font-size:12px;padding:7px 11px;border:1px solid #2d4060;border-radius:20px;color:#9bb4d9}
.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:24px;align-items:center;padding:60px 0}
h1{font-size:50px;line-height:1.02;margin:12px 0}.grad{background:linear-gradient(90deg,#52b8ff,#8b5cff);-webkit-background-clip:text;color:transparent}
p{color:#9eb0c9;line-height:1.6}.card{background:#0d1a2b;border:1px solid #203451;border-radius:22px;padding:24px;box-shadow:0 20px 60px #0004}
.shield{height:290px;display:grid;place-items:center;background:radial-gradient(circle,#243c70,#0d1a2b 60%);font-size:110px}
input,textarea{width:100%;background:#081522;border:1px solid #2a405e;border-radius:12px;color:white;padding:14px;margin:7px 0;font:inherit}
button{background:linear-gradient(90deg,#5a54ff,#874dff);color:white;border:0;border-radius:11px;padding:13px 18px;font-weight:800;cursor:pointer}
button.alt{background:#182940}.row{display:flex;gap:10px;flex-wrap:wrap}.hidden{display:none}.muted{color:#8195b2;font-size:13px}
pre{white-space:pre-wrap;line-height:1.6;background:#081522;border-radius:14px;padding:16px;color:#d9e7ff}.history{margin-top:15px}
.item{padding:12px;border-bottom:1px solid #203451;color:#cbd8ea;font-size:13px}
@media(max-width:800px){.hero{grid-template-columns:1fr;padding:35px 0}h1{font-size:39px}.shield{height:180px;font-size:70px}}
</style></head><body><div class="wrap">
<div class="nav"><div class="logo">🛡️ Cyber<span class="grad">Lens</span> AI</div><span class="badge">Powered by Gemini</span></div>
<section id="landing" class="hero"><div><span class="badge">DEFENSIVE SECURITY COPILOT</span><h1>Your AI-powered <span class="grad">Security Assistant</span></h1>
<p>Analyze web-security scenarios, understand risk, structure manual testing, and get practical remediation guidance.</p>
<button onclick="showAuth()">Get Started →</button></div><div class="card shield">🛡️</div></section>
<section id="auth" class="card hidden" style="max-width:520px;margin:40px auto"><h2>Welcome to CyberLens AI</h2><p>Sign in to keep your private security analysis history.</p>
<input id="email" type="email" placeholder="Email address"><input id="pw" type="password" placeholder="Password (6+ characters)">
<div class="row"><button onclick="signup()">Create account</button><button class="alt" onclick="login()">Sign in</button></div><p id="msg"></p></section>
<section id="app" class="hidden"><div class="row" style="justify-content:space-between;align-items:center"><div><h2>AI Security Assistant</h2><span class="muted" id="who"></span></div><button class="alt" onclick="logout()">Sign out</button></div>
<div class="card" style="margin-top:15px"><textarea id="q" rows="7" placeholder="Example: How should I manually test a web app for broken access control in an authorized lab?"></textarea>
<div class="row" style="justify-content:space-between;align-items:center"><span class="muted">Authorized / defensive testing only</span><button onclick="analyze()">Analyze with Gemini</button></div>
<div id="out"></div></div><div class="card history"><h3>Recent analyses</h3><div id="hist" class="muted">No analyses yet.</div></div></section>
</div>
<script type="module">
import{initializeApp}from"https://www.gstatic.com/firebasejs/12.0.0/firebase-app.js";
import{getAuth,createUserWithEmailAndPassword,signInWithEmailAndPassword,signOut,onAuthStateChanged}from"https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";
let A;
const $=x=>document.getElementById(x);
async function boot(){let c=await fetch("/config").then(r=>r.json());A=getAuth(initializeApp(c));onAuthStateChanged(A,u=>{if(u){$("landing").classList.add("hidden");$("auth").classList.add("hidden");$("app").classList.remove("hidden");$("who").textContent=u.email;history()}else{$("landing").classList.remove("hidden");$("app").classList.add("hidden")}})}
window.showAuth=()=>{$("landing").classList.add("hidden");$("auth").classList.remove("hidden")}
window.signup=async()=>{try{await createUserWithEmailAndPassword(A,$("email").value,$("pw").value)}catch(e){$("msg").textContent=e.message}}
window.login=async()=>{try{await signInWithEmailAndPassword(A,$("email").value,$("pw").value)}catch(e){$("msg").textContent=e.message}}
window.logout=()=>signOut(A)
window.analyze=async()=>{let u=A.currentUser,q=$("q").value.trim();if(!q)return;let t=await u.getIdToken();$("out").innerHTML="<p>Gemini is analyzing…</p>";let r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+t},body:JSON.stringify({prompt:q})});let d=await r.json();$("out").innerHTML=r.ok?"<pre>"+esc(d.answer)+"</pre>":"<p>"+esc(d.error)+"</p>";if(r.ok){$("q").value="";history()}}
async function history(){let u=A.currentUser;if(!u)return;let t=await u.getIdToken(),r=await fetch("/api/history",{headers:{Authorization:"Bearer "+t}}),d=await r.json();$("hist").innerHTML=d.length?d.map(x=>'<div class="item"><b>'+esc(x.prompt.slice(0,90))+'</b><br><span class="muted">'+(x.createdAt||"")+'</span></div>').join(""):"No analyses yet."}
function esc(s){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}boot()
</script></body></html>"""

@app.get("/")
def home(): return Response(HTML, mimetype="text/html")

@app.get("/config")
def config():
    return jsonify({k:os.environ.get(k,"") for k in ["FIREBASE_API_KEY","FIREBASE_AUTH_DOMAIN","FIREBASE_PROJECT_ID","FIREBASE_STORAGE_BUCKET","FIREBASE_MESSAGING_SENDER_ID","FIREBASE_APP_ID"]})

def user_required(f):
    @wraps(f)
    def w(*a,**kw):
        h=request.headers.get("Authorization","")
        try:
            if not h.startswith("Bearer "): raise ValueError()
            request.user=auth.verify_id_token(h[7:])
            return f(*a,**kw)
        except Exception:return jsonify(error="Authentication required"),401
    return w

@app.post("/api/analyze")
@user_required
def analyze():
    if not gemini:return jsonify(error="Gemini is not configured"),503
    p=(request.json or {}).get("prompt","").strip()
    if not p:return jsonify(error="Enter a scenario"),400
    system="""You are CyberLens AI, a defensive cybersecurity assistant. Give safe, authorized guidance focused on vulnerability understanding, manual testing methodology, evidence, risk and remediation. Do not provide credential theft, malware, persistence, evasion, destructive actions or unauthorized access. Structure useful answers with Summary, What to Check, Safe Test Steps, Evidence, Risk and Remediation."""
    try:
        ans=gemini.models.generate_content(model=MODEL,contents=system+"\n\nScenario:\n"+p).text or "No response."
        ref=db.collection("users").document(request.user["uid"]).collection("analyses").document()
        ref.set({"prompt":p,"answer":ans,"createdAt":firestore.SERVER_TIMESTAMP})
        return jsonify(id=ref.id,answer=ans)
    except Exception:
        return jsonify(error="AI request failed; check server configuration."),500

@app.get("/api/history")
@user_required
def get_history():
    docs=db.collection("users").document(request.user["uid"]).collection("analyses").order_by("createdAt",direction=firestore.Query.DESCENDING).limit(20).stream()
    out=[]
    for d in docs:
        x=d.to_dict();ts=x.get("createdAt")
        out.append({"id":d.id,"prompt":x.get("prompt",""),"answer":x.get("answer",""),"createdAt":ts.isoformat() if ts else None})
    return jsonify(out)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",8080)))