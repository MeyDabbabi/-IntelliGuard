from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import os
import sqlite3
import zipfile
import io
import glob

app = Flask(__name__)
app.secret_key = 'une_cle_secrete_unique_et_longue_pour_les_sessions'
socketio = SocketIO(app, cors_allowed_origins="*")

VALID_USERNAME = "admin"
VALID_PASSWORD = "G7!tR3$mK9#pLx2@qW5z"

# ------------------ BASE DE DONNÉES SQLITE ------------------
DB_PATH = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  type TEXT,
                  score INTEGER,
                  ips TEXT,
                  machine TEXT,
                  packets INTEGER)''')
    conn.commit()
    conn.close()

def save_alert(alert):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, type, score, ips, machine, packets) VALUES (?, ?, ?, ?, ?, ?)",
              (alert['timestamp'], alert['type'], alert['score'], ','.join(alert['ips']), alert['machine'], alert['packets']))
    conn.commit()
    conn.close()

def get_alerts(filters=None, limit=5000):
    query = "SELECT timestamp, type, score, ips, machine, packets FROM alerts WHERE 1=1"
    params = []
    if filters:
        if filters.get('ip'):
            query += " AND ips LIKE ?"
            params.append(f"%{filters['ip']}%")
        if filters.get('year'):
            query += " AND strftime('%Y', timestamp) = ?"
            params.append(filters['year'])
        if filters.get('month'):
            query += " AND strftime('%m', timestamp) = ?"
            params.append(f"{int(filters['month']):02d}")
        if filters.get('day'):
            query += " AND strftime('%d', timestamp) = ?"
            params.append(f"{int(filters['day']):02d}")
        if filters.get('hour'):
            query += " AND strftime('%H', timestamp) = ?"
            params.append(f"{int(filters['hour']):02d}")
        if filters.get('type'):
            query += " AND type = ?"
            params.append(filters['type'])
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return [{"timestamp": r[0], "type": r[1], "score": r[2], "ips": r[3].split(','), "machine": r[4], "packets": r[5]} for r in rows]

init_db()

# ------------------ AUTHENTIFICATION (inchangée, avec vidéo) ------------------
def is_logged_in():
    return session.get('logged_in', False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        # Mauvais identifiants
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>IntelliGuard IDS - Sign in</title>
        <style>
            *{margin:0;padding:0;box-sizing:border-box;}
            body{
                font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
                height:100vh;overflow:hidden;position:relative;
                background:#000;
            }
            #bg-video{
                position:fixed;top:50%;left:50%;
                transform:translate(-50%,-50%) scale(0.98);
                min-width:100%;min-height:100%;width:auto;height:auto;
                z-index:-2;object-fit:cover;
            }
            .login-container{
                position:absolute;top:50%;left:50%;
                transform:translate(-50%,-50%);
                text-align:center;width:360px;
                background:transparent;
                padding:20px;
            }
            .login-container input{
                width:100%;padding:12px;margin:10px 0;
                border:1px solid rgba(255,255,255,0.5);
                border-radius:40px;
                background:rgba(0,0,0,0.4);
                font-size:16px;color:white;
                outline:none;
            }
            .login-container input:focus{
                border-color:#00e5ff;
                background:rgba(0,0,0,0.6);
            }
            .login-container input::placeholder{
                color:rgba(255,255,255,0.7);
            }
            .login-container button{
                width:100%;padding:12px;margin-top:20px;
                border:none;border-radius:40px;
                background:#1a73e8;
                color:white;
                font-weight:bold;
                cursor:pointer;
            }
            .login-container button:hover{background:#0d5bba;}
            .error{color:#ff8888;margin-top:15px;}
        </style>
        </head>
        <body>
            <video autoplay muted loop id="bg-video">
                <source src="/static/background.mp4" type="video/mp4">
            </video>
            <div class="login-container">
                <form method="post">
                    <input type="text" name="username" placeholder="Login" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Sign in</button>
                </form>
                <div class="error">Invalid credentials</div>
            </div>
        </body>
        </html>
        '''
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>IntelliGuard IDS - Sign in</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{
            font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
            height:100vh;overflow:hidden;position:relative;
            background:#000;
        }
        #bg-video{
            position:fixed;top:50%;left:50%;
            transform:translate(-50%,-50%) scale(0.98);
            min-width:100%;min-height:100%;width:auto;height:auto;
            z-index:-2;object-fit:cover;
        }
        .login-container{
            position:absolute;top:50%;left:50%;
            transform:translate(-50%,-50%);
            text-align:center;width:360px;
            background:transparent;
            padding:20px;
        }
        .login-container input{
            width:100%;padding:12px;margin:10px 0;
            border:1px solid rgba(255,255,255,0.5);
            border-radius:40px;
            background:rgba(0,0,0,0.4);
            font-size:16px;color:white;
            outline:none;
        }
        .login-container input:focus{
            border-color:#00e5ff;
            background:rgba(0,0,0,0.6);
        }
        .login-container input::placeholder{
            color:rgba(255,255,255,0.7);
        }
        .login-container button{
            width:100%;padding:12px;margin-top:20px;
            border:none;border-radius:40px;
            background:#1a73e8;
            color:white;
            font-weight:bold;
            cursor:pointer;
        }
        .login-container button:hover{background:#0d5bba;}
    </style>
    </head>
    <body>
        <video autoplay muted loop id="bg-video">
            <source src="/static/background.mp4" type="video/mp4">
        </video>
        <div class="login-container">
            <form method="post">
                <input type="text" name="username" placeholder="Login" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# ------------------ DASHBOARD ------------------
@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('index.html')

# ------------------ API ALERTES TEMPS REEL ------------------
stats = {"total": 0, "attacks": 0, "normal": 0}
blocked_ips = set()

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    data = request.json
    label = data.get('type', 'BENIGN')
    score = data.get('score', 10)
    packets = data.get('packets', 0)
    ips = data.get('ips', [])
    machine = data.get('machine', 'unknown')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stats["total"] += 1
    if label != "BENIGN":
        stats["attacks"] += 1
    else:
        stats["normal"] += 1

    alert = {
        'timestamp': timestamp,
        'type': label,
        'score': score,
        'ips': ips,
        'machine': machine,
        'packets': packets
    }
    save_alert(alert)

    if label == "BENIGN":
        socketio.emit('normal_traffic', {"timestamp": timestamp, "packets": packets, "machine": machine})
    else:
        socketio.emit('new_alert', {
            "timestamp": timestamp,
            "type": label,
            "score": score,
            "packets": packets,
            "ips": ips,
            "machine": machine
        })
        for ip in ips:
            if ip not in blocked_ips and score >= 85:
                blocked_ips.add(ip)
                socketio.emit('new_block', {
                    "timestamp": timestamp,
                    "ip": ip,
                    "attaque": label,
                    "score": score
                })

    socketio.emit('update_stats', {
        "total": stats["total"],
        "attacks": stats["attacks"],
        "normal": stats["normal"],
        "blocked": len(blocked_ips)
    })
    return jsonify({"status": "ok"})

# ------------------ API RECHERCHE ------------------
@app.route('/api/search', methods=['POST'])
def search_alerts():
    data = request.json
    filters = {
        'ip': data.get('ip'),
        'year': data.get('year'),
        'month': data.get('month'),
        'day': data.get('day'),
        'hour': data.get('hour'),
        'type': data.get('type')
    }
    filters = {k: v for k, v in filters.items() if v and v != ''}
    alerts = get_alerts(filters, limit=5000)
    return jsonify(alerts)

# ------------------ EXPORT PCAP SIMPLE (conservé pour compatibilité) ------------------
@app.route('/download_pcap')
def download_pcap():
    pcap_path = "/tmp/capture_rt.pcap"
    if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
        return send_file(pcap_path, as_attachment=True, download_name='intelliguard_capture.pcap')
    else:
        return "No PCAP file available", 404

# ------------------ EXPORT PCAPS PAR PÉRIODE (ZIP) ------------------
@app.route('/download_pcaps')
def download_pcaps():
    start_str = request.args.get('start')
    end_str = request.args.get('end')
    if not start_str or not end_str:
        return "Missing start or end", 400
    try:
        start = datetime.strptime(start_str, '%Y-%m-%d %H:%M:%S')
        end = datetime.strptime(end_str, '%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid date format", 400

    pcap_dir = "/home/mayousha/Downloads/MachineLearningCVE/pcaps"
    if not os.path.exists(pcap_dir):
        return "No PCAP directory", 404

    selected = []
    for f in os.listdir(pcap_dir):
        if f.startswith('capture_') and f.endswith('.pcap'):
            try:
                # extraire date du nom "capture_YYYY-MM-DD_HH-MM-SS.pcap"
                date_str = f[8:27]  # "YYYY-MM-DD_HH-MM-SS"
                file_time = datetime.strptime(date_str, '%Y-%m-%d_%H-%M-%S')
                if start <= file_time <= end:
                    selected.append(os.path.join(pcap_dir, f))
            except:
                continue

    if not selected:
        return "No PCAP files for this period", 404

    # Créer l'archive ZIP en mémoire
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in selected:
            arcname = os.path.basename(file_path)
            zf.write(file_path, arcname)
    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f'pcaps_{start_str[:10]}_{end_str[:10]}.zip',
        mimetype='application/zip'
    )

if __name__ == '__main__':
    print("IntelliGuard IDS started on http://localhost:5000")
    print("Credentials: admin / G7!tR3$mK9#pLx2@qW5z")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
