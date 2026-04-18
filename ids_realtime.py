import time
import requests
import os
import shutil
import subprocess
import pandas as pd
import numpy as np
import joblib
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# ==================== CONFIGURATION ====================
INTERFACE = "wlp0s20f3"
CAPTURE_DURATION = 30
DASHBOARD_URL = "http://localhost:5000/api/alert"
PCAP_DIR = "/home/mayousha/Downloads/MachineLearningCVE/pcaps"
LOG_DIR = "/var/log/intelliguard"
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Configuration des logs
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "ids.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info("Démarrage IDS entreprise")

# ==================== CHARGEMENT MODELE ML ====================
try:
    model = joblib.load("intrusion_detection_FINAL.pkl")
    encoder = joblib.load("label_encoder_FINAL.pkl")
    logging.info("Modèle ML chargé avec succès")
    ML_AVAILABLE = True
except Exception as e:
    logging.error(f"Erreur chargement modèle ML: {e}")
    ML_AVAILABLE = False

# ==================== EXTRACTION FEATURES AVEC TSHARK (compatible modèle) ====================
def extract_features_tshark(pcap_file):
    """Extrait les features nécessaires pour le modèle Random Forest"""
    cmd = f"tshark -r {pcap_file} -T fields -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len -e tcp.flags.syn -e ip.proto -E separator=,"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        lines = result.stdout.strip().split('\n')
        if len(lines) < 5:
            return None
        syn_count = 0
        total_bytes = 0
        durations = []
        dst_ports = []
        for line in lines:
            if not line:
                continue
            parts = line.split(',')
            if len(parts) < 8:
                continue
            try:
                if parts[0]:
                    durations.append(float(parts[0]))
                if len(parts) > 8 and parts[8] == '1':
                    syn_count += 1
                if len(parts) > 7 and parts[7]:
                    total_bytes += int(parts[7])
                if len(parts) > 4 and parts[4] and parts[4] != '-':
                    dst_ports.append(int(parts[4]))
                elif len(parts) > 6 and parts[6] and parts[6] != '-':
                    dst_ports.append(int(parts[6]))
            except:
                pass
        if len(durations) < 2:
            return None
        flow_duration = (max(durations) - min(durations)) * 1_000_000  # microsecondes
        if flow_duration <= 0:
            flow_duration = 1
        # Construction des features (uniquement celles utilisées par le modèle)
        # Le modèle attend 78 colonnes. On va créer un dictionnaire avec les colonnes nécessaires.
        # Pour les colonnes manquantes, on met 0.
        features = {
            'Destination Port': dst_ports[0] if dst_ports else 0,
            'Flow Duration': flow_duration,
            'Total Fwd Packets': len(lines),
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': total_bytes,
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Length Max': 0,
            'Fwd Packet Length Min': 0,
            'Fwd Packet Length Mean': 0,
            'Fwd Packet Length Std': 0,
            'Bwd Packet Length Max': 0,
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': 0,
            'Bwd Packet Length Std': 0,
            'Flow Bytes/s': total_bytes / (flow_duration / 1_000_000 + 0.001),
            'Flow Packets/s': len(lines) / (flow_duration / 1_000_000 + 0.001),
            'Flow IAT Mean': 0,
            'Flow IAT Std': 0,
            'Flow IAT Max': 0,
            'Flow IAT Min': 0,
            'Fwd IAT Total': 0,
            'Fwd IAT Mean': 0,
            'Fwd IAT Std': 0,
            'Fwd IAT Max': 0,
            'Fwd IAT Min': 0,
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': 0,
            'Bwd IAT Min': 0,
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': 0,
            'Bwd Header Length': 0,
            'Fwd Packets/s': len(lines) / (flow_duration / 1_000_000 + 0.001),
            'Bwd Packets/s': 0,
            'Min Packet Length': 0,
            'Max Packet Length': 0,
            'Packet Length Mean': total_bytes / max(len(lines), 1),
            'Packet Length Std': 0,
            'Packet Length Variance': 0,
            'FIN Flag Count': 0,
            'SYN Flag Count': syn_count,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': 0,
            'Average Packet Size': total_bytes / max(len(lines), 1),
            'Avg Fwd Segment Size': 0,
            'Avg Bwd Segment Size': 0,
            'Fwd Header Length.1': 0,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': len(lines),
            'Subflow Fwd Bytes': total_bytes,
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0,
            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': 0,
            'min_seg_size_forward': 0,
            'Active Mean': 0,
            'Active Std': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
        }
        # Ajouter les colonnes manquantes (le modèle a 78 features)
        for col in model.feature_names_in_:
            if col not in features:
                features[col] = 0
        return features
    except Exception as e:
        logging.error(f"Erreur extraction tshark: {e}")
        return None

# ==================== SCAPY POUR REGLES (secours) ====================
stats = {
    "syn": 0, "udp": 0, "icmp": 0,
    "ssh": 0, "ftp": 0,
    "dst_ports": set(),
    "unusual_ports": 0,
    "top_src": ""
}

def packet_callback(pkt):
    if IP in pkt and pkt[IP].src == "192.168.1.49":
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

def capture_scapy():
    reset_stats()
    sniff(iface=INTERFACE, prn=packet_callback, timeout=CAPTURE_DURATION, store=0)

def rule_based_detection():
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

# ==================== BOUCLE PRINCIPALE ====================
print("=" * 60)
print("IntelliGuard IDS - Mode Entreprise (ML + règles secours)")
print("=" * 60)
print(f"Interface : {INTERFACE}")
print("Logs dans :", LOG_DIR)
print("Ctrl+C pour arrêter\n")
logging.info("Démarrage de la boucle principale")

try:
    while True:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] Capture {CAPTURE_DURATION}s...")
        pcap_file = "/tmp/capture_rt.pcap"
        os.system(f"sudo timeout {CAPTURE_DURATION} tcpdump -i {INTERFACE} -w {pcap_file} 2>/dev/null")

        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            dated_pcap = os.path.join(PCAP_DIR, f"capture_{timestamp}.pcap")
            shutil.copy2(pcap_file, dated_pcap)
            print(f"  📁 PCAP sauvegardé : {dated_pcap}")
            logging.info(f"PCAP sauvegardé : {dated_pcap}")

        # 1. Tentative d'analyse ML
        alert_sent = False
        if ML_AVAILABLE:
            features = extract_features_tshark(pcap_file)
            if features:
                df = pd.DataFrame([features])
                # Alignement avec les colonnes du modèle
                for col in model.feature_names_in_:
                    if col not in df.columns:
                        df[col] = 0
                df = df[model.feature_names_in_]
                df = df.fillna(0).replace([np.inf, -np.inf], 0)
                pred = model.predict(df)
                label = encoder.inverse_transform(pred)[0]
                if label != "BENIGN":
                    score = 95 if "DDoS" in label else (88 if "PortScan" in label else 85)
                    print(f"  🔬 [ML] {label} (score {score})")
                    logging.info(f"ML détection: {label} (score {score})")
                    try:
                        requests.post(DASHBOARD_URL, json={
                            "type": label,
                            "score": score,
                            "packets": 1,
                            "ips": ["192.168.1.49"],
                            "machine": "IDS_Enterprise"
                        }, timeout=2)
                    except Exception as e:
                        logging.error(f"Erreur envoi dashboard: {e}")
                    alert_sent = True

        # 2. Si ML n'a rien détecté, utiliser les règles Scapy (secours)
        if not alert_sent:
            capture_scapy()
            alerts = rule_based_detection()
            src_ip = stats["top_src"] if stats["top_src"] else "192.168.1.49"
            if alerts:
                for atype, score, count in alerts:
                    print(f"  🔴 [REGLE] {atype} (score {score}/100) - {count} paquets")
                    logging.info(f"Règle détection: {atype} (score {score})")
                    try:
                        requests.post(DASHBOARD_URL, json={
                            "type": atype,
                            "score": score,
                            "packets": count,
                            "ips": [src_ip],
                            "machine": "IDS_Enterprise"
                        }, timeout=2)
                    except Exception as e:
                        logging.error(f"Erreur envoi dashboard: {e}")
                    alert_sent = True

        if not alert_sent:
            print("  ✅ Trafic normal")
            logging.info("Trafic normal")

        print("-" * 60)
        time.sleep(1)

except KeyboardInterrupt:
    print("\n🛑 IDS arrêté.")
    logging.info("IDS arrêté par utilisateur")
except Exception as e:
    logging.critical(f"Erreur fatale: {e}")
    print(f"Erreur fatale: {e}")
