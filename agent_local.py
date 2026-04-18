import time
import requests
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket

# ==================== CONFIGURATION ====================
# À modifier : adresse IP du serveur qui héberge le dashboard
SERVER_IP = "127.0.0.1"   # ou "192.168.1.49" selon votre réseau
DASHBOARD_URL = f"http://{SERVER_IP}:5000/api/alert"
INTERFACE = None          # Laissez None pour auto-détection, ou fixez "wlp0s20f3"
CAPTURE_DURATION = 30
MACHINE_NAME = socket.gethostname()   # Nom de votre PC

# ==================== CAPTURE SCAPY ====================
stats = {
    "syn": 0, "udp": 0, "icmp": 0,
    "ssh": 0, "ftp": 0,
    "dst_ports": set(),
    "unusual_ports": 0,
    "top_src": ""
}

def packet_callback(pkt):
    if IP in pkt and pkt[IP].src == "127.0.0.1":
        return
    try:
        if IP in pkt:
            stats["top_src"] = pkt[IP].src
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
        "top_src": ""
    })

def capture():
    reset_stats()
    sniff(iface=INTERFACE, prn=packet_callback, timeout=CAPTURE_DURATION, store=0)

def detect():
    alerts = []
    if stats["syn"] > 10000:
        alerts.append(("DDoS", 95, stats["syn"]))
        return alerts
    if stats["udp"] > 10000:
        alerts.append(("DDoS", 95, stats["udp"]))
        return alerts
    if stats["icmp"] > 2000:
        alerts.append(("DDoS", 95, stats["icmp"]))
        return alerts
    if len(stats["dst_ports"]) > 500:
        alerts.append(("PortScan", 88, len(stats["dst_ports"])))
        return alerts
    if stats["ssh"] > 50:
        alerts.append(("SSH-Patator", 85, stats["ssh"]))
        return alerts
    if stats["ftp"] > 50:
        alerts.append(("FTP-Patator", 87, stats["ftp"]))
        return alerts
    if stats["unusual_ports"] > 20000:
        alerts.append(("Bot", 82, stats["unusual_ports"]))
        return alerts
    return alerts

print(f"Agent IDS démarré sur {MACHINE_NAME}")
print(f"Envoi des alertes vers {DASHBOARD_URL}")
print("Ctrl+C pour arrêter\n")

try:
    while True:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] Capture locale...")
        capture()
        alerts = detect()
        src_ip = stats["top_src"] if stats["top_src"] else "inconnue"
        if alerts:
            for atype, score, count in alerts:
                print(f"  🔴 ALERTE locale {atype} (score {score}/100) - {count} paquets")
                try:
                    requests.post(DASHBOARD_URL, json={
                        "type": atype,
                        "score": score,
                        "packets": count,
                        "ips": [src_ip],
                        "machine": MACHINE_NAME
                    }, timeout=2)
                    print("     ✓ Alerte envoyée au serveur")
                except Exception as e:
                    print(f"     ⚠️ Échec envoi: {e}")
        else:
            print("  ✅ Trafic normal")
        print("-" * 50)
        time.sleep(1)

except KeyboardInterrupt:
    print("\nAgent arrêté.")
