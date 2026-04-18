import threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO

# ──────────────────────────────────────────────
#  Flask / SocketIO
# ──────────────────────────────────────────────
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

stats       = {"total": 0, "attacks": 0, "normal": 0}
blocked_ips = set()
MAX_ALERTS  = 30

ATTACK_SEVERITY = {
    "BENIGN":            0,
    "SSH-Patator":      85,
    "FTP-Patator":      87,
    "PortScan":         88,
    "Bot":              82,
    "DoS Hulk":         92,
    "DoS slowloris":    80,
    "DoS Slowhttptest": 83,
    "Infiltration":     90,
    "Heartbleed":       98,
    "DDoS":             95,
    "Web Attack":       78,
}

BLOCK_THRESHOLD = 82

# ──────────────────────────────────────────────
#  API reçoit les alertes de ids_realtime.py
# ──────────────────────────────────────────────
@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data       = request.json
    attack     = data.get("type", "BENIGN")
    score      = data.get("score", 0)
    packets    = data.get("packets", 0)
    ips        = data.get("ips", [])
    src_ip     = ips[0] if ips else ""
    timestamp  = datetime.now().strftime("%H:%M:%S")

    stats["total"] += 1

    if attack != "BENIGN":
        stats["attacks"] += 1
        print(f"[ALERT] {attack:20s}  score={score}/100  ip={src_ip}  flux={packets}")

        socketio.emit("new_alert", {
            "timestamp": timestamp,
            "type":      attack,
            "score":     score,
            "packets":   packets,
            "ip":        src_ip,
        })

        if src_ip and src_ip not in blocked_ips and score >= BLOCK_THRESHOLD:
            blocked_ips.add(src_ip)
            print(f"[BLOCK] {src_ip}")
            socketio.emit("new_block", {
                "timestamp": timestamp,
                "ip":        src_ip,
                "attack":    attack,
                "score":     score,
            })
    else:
        stats["normal"] += 1
        print(f"[OK]    {packets} flux normaux")

    socketio.emit("update_stats", {
        "total":   stats["total"],
        "attacks": stats["attacks"],
        "normal":  stats["normal"],
        "blocked": len(blocked_ips),
    })

    return jsonify({"status": "ok"})


# ──────────────────────────────────────────────
#  Dashboard HTML
# ──────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS · Network Watch</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Space+Grotesk:wght@300;500;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<style>
  :root {
    --bg:#0a0c10; --surface:#111520; --border:#1e2535;
    --accent:#00e5ff; --red:#ff3b5c; --orange:#ff8c42;
    --yellow:#ffd166; --green:#06d6a0; --text:#c9d1e0; --muted:#4a5568;
    --mono:'IBM Plex Mono',monospace; --ui:'Space Grotesk',sans-serif;
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--ui);min-height:100vh;display:flex;flex-direction:column}
  header{display:flex;align-items:center;justify-content:space-between;padding:18px 32px;border-bottom:1px solid var(--border);background:var(--surface);position:sticky;top:0;z-index:10}
  .logo{display:flex;align-items:center;gap:12px}
  .logo-icon{width:36px;height:36px;border:2px solid var(--accent);border-radius:8px;display:grid;place-items:center;font-family:var(--mono);font-size:14px;color:var(--accent);font-weight:600}
  .logo-text{font-size:15px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
  .logo-sub{font-size:11px;color:var(--muted);font-family:var(--mono)}
  .live{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;color:var(--green);border:1px solid var(--green);border-radius:20px;padding:4px 12px}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink 1.4s ease-in-out infinite}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
  .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
  .stat-card{background:var(--surface);padding:24px 28px;display:flex;flex-direction:column;gap:6px}
  .stat-label{font-size:10px;font-weight:500;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
  .stat-value{font-family:var(--mono);font-size:38px;font-weight:600;line-height:1;transition:color .3s}
  .stat-card:nth-child(1) .stat-value{color:var(--accent)}
  .stat-card:nth-child(2) .stat-value{color:var(--red)}
  .stat-card:nth-child(3) .stat-value{color:var(--green)}
  .stat-card:nth-child(4) .stat-value{color:var(--orange)}
  main{display:grid;grid-template-columns:1fr 340px;gap:1px;background:var(--border);flex:1}
  .panel{background:var(--surface);padding:24px;display:flex;flex-direction:column;gap:16px;overflow:hidden}
  .panel-title{font-size:10px;font-weight:600;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);padding-bottom:12px;border-bottom:1px solid var(--border);flex-shrink:0}
  .scroll-list{overflow-y:auto;flex:1;display:flex;flex-direction:column;gap:10px}
  .scroll-list::-webkit-scrollbar{width:4px}
  .scroll-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
  .alert-card{border:1px solid var(--border);border-radius:8px;padding:14px 16px;background:var(--bg);display:grid;grid-template-columns:1fr auto;gap:6px;animation:slideIn .3s ease;flex-shrink:0}
  @keyframes slideIn{from{opacity:0;transform:translateY(-6px)}}
  .alert-card.sev-critical{border-color:#ff3b5c44}
  .alert-card.sev-high{border-color:#ff8c4244}
  .alert-card.sev-medium{border-color:#ffd16644}
  .alert-type{font-family:var(--mono);font-size:13px;font-weight:600;grid-column:1;align-self:center}
  .alert-time{font-family:var(--mono);font-size:10px;color:var(--muted);grid-column:2;align-self:center;white-space:nowrap}
  .alert-meta{grid-column:1/-1;font-size:11px;color:var(--muted);font-family:var(--mono);display:flex;gap:14px;flex-wrap:wrap}
  .alert-meta span b{color:var(--text)}
  .score-bar{grid-column:1/-1;height:3px;background:var(--border);border-radius:2px;overflow:hidden;margin-top:4px}
  .score-fill{height:100%;border-radius:2px;transition:width .4s}
  .block-card{border:1px solid #ff8c4222;border-radius:8px;padding:12px 14px;background:var(--bg);animation:slideIn .3s ease;flex-shrink:0}
  .block-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
  .block-ip{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--orange)}
  .block-time{font-family:var(--mono);font-size:10px;color:var(--muted)}
  .block-detail{font-size:11px;color:var(--muted);font-family:var(--mono)}
  .empty{color:var(--muted);font-size:12px;font-family:var(--mono);text-align:center;padding:32px 0}
  footer{text-align:center;padding:12px;font-family:var(--mono);font-size:10px;color:var(--muted);border-top:1px solid var(--border);background:var(--surface)}
  .model-badge{display:inline-flex;align-items:center;gap:6px;background:#00e5ff11;border:1px solid #00e5ff33;border-radius:4px;padding:2px 8px;font-size:10px;color:var(--accent);font-family:var(--mono)}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">IDS</div>
    <div>
      <div class="logo-text">Network Intrusion Detection</div>
      <div class="logo-sub">Random Forest · CICIDS2017 · 99.79% &nbsp;<span class="model-badge">✓ CICFlowMeter + RF</span></div>
    </div>
  </div>
  <div class="live"><span class="dot"></span>LIVE</div>
</header>
<div class="stats-row">
  <div class="stat-card"><div class="stat-label">Flux Analysés</div><div class="stat-value" id="total">0</div></div>
  <div class="stat-card"><div class="stat-label">Attaques Détectées</div><div class="stat-value" id="attacks">0</div></div>
  <div class="stat-card"><div class="stat-label">Trafic Normal</div><div class="stat-value" id="normal">0</div></div>
  <div class="stat-card"><div class="stat-label">IPs Bloquées</div><div class="stat-value" id="blocked">0</div></div>
</div>
<main>
  <div class="panel">
    <div class="panel-title">Alertes en Temps Réel</div>
    <div class="scroll-list" id="alerts"><p class="empty">En attente d'activité réseau …</p></div>
  </div>
  <div class="panel">
    <div class="panel-title">IPs Bloquées</div>
    <div class="scroll-list" id="blocked-list"><p class="empty">Aucune IP bloquée</p></div>
  </div>
</main>
<footer>IDS · tcpdump → CICFlowMeter → Random Forest → Dashboard</footer>
<script>
const MAX_ALERTS = """ + str(MAX_ALERTS) + """;
const socket = io();
function sevClass(s){return s>=90?'sev-critical':s>=75?'sev-high':'sev-medium'}
function sevColor(s){return s>=90?'var(--red)':s>=75?'var(--orange)':'var(--yellow)'}
socket.on('new_alert',function(d){
  const list=document.getElementById('alerts');
  if(list.querySelector('.empty'))list.innerHTML='';
  const c=sevColor(d.score),card=document.createElement('div');
  card.className='alert-card '+sevClass(d.score);
  card.innerHTML=`<span class="alert-type" style="color:${c}">${d.type}</span>
    <span class="alert-time">${d.timestamp}</span>
    <div class="alert-meta">
      <span>score <b style="color:${c}">${d.score}/100</b></span>
      <span>flux <b>${d.packets}</b></span>
      <span>src <b>${d.ip||'—'}</b></span>
    </div>
    <div class="score-bar"><div class="score-fill" style="width:${d.score}%;background:${c}"></div></div>`;
  list.insertBefore(card,list.firstChild);
  while(list.children.length>MAX_ALERTS)list.removeChild(list.lastChild);
});
socket.on('new_block',function(d){
  const list=document.getElementById('blocked-list');
  if(list.querySelector('.empty'))list.innerHTML='';
  const card=document.createElement('div');
  card.className='block-card';
  card.innerHTML=`<div class="block-header"><span class="block-ip">${d.ip}</span><span class="block-time">${d.timestamp}</span></div>
    <div class="block-detail">${d.attack} · score ${d.score}/100</div>`;
  list.insertBefore(card,list.firstChild);
});
socket.on('update_stats',function(d){
  document.getElementById('total').textContent=d.total;
  document.getElementById('attacks').textContent=d.attacks;
  document.getElementById('normal').textContent=d.normal;
  document.getElementById('blocked').textContent=d.blocked;
});
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════╗")
    print("║  IDS Dashboard  →  http://localhost:5000       ║")
    print("║  Pipeline : tcpdump → CICFlowMeter → RF       ║")
    print("╚════════════════════════════════════════════════╝")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
