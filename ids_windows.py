import time
import requests
import os
import socket
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# ==================== CONFIGURATION ====================
DASHBOARD_URL = "http://192.168.1.49:5000/api/alert"
CAPTURE_DURATION = 30
MACHINE_NAME = socket.gethostname()

# Dossier logs Windows
LOG_DIR = os.path.join(os.environ.get("APPDATA", "C:\\"), "IntelliGuard", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "ids.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info(f"Démarrage IDS sur {MACHINE_NAME}")

# ==================== SEUILS PAR DEFAUT ====================
THRESHOLDS = {
    'syn_flood': 10000,
    'udp_flood': 10000,
    'icmp_flood': 2000,
    'portscan': 500,
    'ssh_brute': 50,
    'ftp_brute': 50,
    'bot_unusual': 20000
}

# ==================== STATS SCAPY ====================
stats = {
    "syn": 0, "udp": 0, "icmp": 0,
    "ssh": 0, "ftp": 0,
    "dst_ports": set(),
    "unusual_ports": 0,
    "top_src": "",
    "src_counter": Counter()
}

def packet_callback(pkt):
    try:
        if IP in pkt:
            src = pkt[IP].src
            # Ignorer les IPs locales
            if src.startswith("127.") or src.startswith("192.168.1.49"):
                return
            stats["src_counter"][src] += 1
            stats["top_src"] = stats["src_counter"].most_common(1)[0][0]

        if TCP in pkt:
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            stats["dst_ports"].add(dport)
            if dport == 22:
                stats["ssh"] += 1
            elif dport == 21:
                stats["ftp"] += 1
            if flags & 0x02:
                stats["syn"] += 1
            if dport not in [80, 443, 22, 21, 25, 53, 8080, 3306, 5432, 3389]:
                stats["unusual_ports"] += 1
        elif UDP in pkt:
            stats["udp"] += 1
        elif ICMP in pkt:
            stats["icmp"] += 1
    except:
        pass

def reset_stats():
    stats.update({
        "syn": 0, "udp": 0, "icmp": 0,
        "ssh": 0, "ftp": 0,
        "dst_ports": set(),
        "unusual_ports": 0,
        "top_src": "",
        "src_counter": Counter()
    })

def rule_based_detection():
    alerts = []
    if stats["syn"] > THRESHOLDS['syn_flood']:
        alerts.append(("DDoS", 95, stats["syn"]))
        return alerts
    if stats["udp"] > THRESHOLDS['udp_flood']:
        alerts.append(("DDoS", 95, stats["udp"]))
        return alerts
    if stats["icmp"] > THRESHOLDS['icmp_flood']:
        alerts.append(("DDoS", 95, stats["icmp"]))
        return alerts
    if len(stats["dst_ports"]) > THRESHOLDS['portscan']:
        alerts.append(("PortScan", 88, len(stats["dst_ports"])))
        return alerts
    if stats["ssh"] > THRESHOLDS['ssh_brute']:
        alerts.append(("SSH-Patator", 85, stats["ssh"]))
        return alerts
    if stats["ftp"] > THRESHOLDS['ftp_brute']:
        alerts.append(("FTP-Patator", 87, stats["ftp"]))
        return alerts
    if stats["unusual_ports"] > THRESHOLDS['bot_unusual']:
        alerts.append(("Bot", 82, stats["unusual_ports"]))
        return alerts
    return alerts

def send_alert(atype, score, count, src_ip):
    try:
        requests.post(DASHBOARD_URL, json={
            "type": atype,
            "score": score,
            "packets": count,
            "ips": [src_ip],
            "machine": MACHINE_NAME
        }, timeout=3)
        logging.info(f"Alerte envoyée: {atype} (score {score}) IP: {src_ip}")
    except Exception as e:
        logging.error(f"Erreur envoi alerte: {e}")

# ==================== BOUCLE PRINCIPALE ====================
print("=" * 60)
print(f"IntelliGuard IDS Agent - Machine: {MACHINE_NAME}")
print(f"Serveur: {DASHBOARD_URL}")
print("=" * 60)

try:
    while True:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] Capture {CAPTURE_DURATION}s...")
        reset_stats()

        # Capture Scapy (utilise Npcap sur Windows)
        sniff(prn=packet_callback, timeout=CAPTURE_DURATION, store=0)

        # Détection par règles
        alerts = rule_based_detection()
        src_ip = stats["top_src"] if stats["top_src"] else "0.0.0.0"

        if alerts:
            for atype, score, count in alerts:
                print(f"  ALERTE: {atype} (score {score}/100) - {count} paquets - IP: {src_ip}")
                send_alert(atype, score, count, src_ip)
        else:
            print("  Trafic normal")
            logging.info("Trafic normal")

        print("-" * 60)
        time.sleep(1)

except KeyboardInterrupt:
    print("\nIDS arrete.")
    logging.info("IDS arrete")
except Exception as e:
    logging.critical(f"Erreur fatale: {e}")
    print(f"Erreur fatale: {e}")
