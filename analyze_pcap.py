import pandas as pd
import numpy as np
import joblib
import subprocess
import os
import sys

# ==================== CONFIGURATION ====================
MODEL_PATH = "intrusion_detection_FINAL.pkl"
ENCODER_PATH = "label_encoder_FINAL.pkl"
CICFLOWMETER = "/home/mayousha/cicflowmeter/venv/bin/cicflowmeter"

# Mapping des colonnes (identique à celui utilisé dans ids_realtime.py)
COL_MAP = {
    'dst_port': 'Destination Port', 'flow_duration': 'Flow Duration',
    'tot_fwd_pkts': 'Total Fwd Packets', 'tot_bwd_pkts': 'Total Backward Packets',
    'totlen_fwd_pkts': 'Total Length of Fwd Packets', 'totlen_bwd_pkts': 'Total Length of Bwd Packets',
    'fwd_pkt_len_max': 'Fwd Packet Length Max', 'fwd_pkt_len_min': 'Fwd Packet Length Min',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean', 'fwd_pkt_len_std': 'Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max', 'bwd_pkt_len_min': 'Bwd Packet Length Min',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean', 'bwd_pkt_len_std': 'Bwd Packet Length Std',
    'flow_byts_s': 'Flow Bytes/s', 'flow_pkts_s': 'Flow Packets/s',
    'flow_iat_mean': 'Flow IAT Mean', 'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max', 'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total', 'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std', 'fwd_iat_max': 'Fwd IAT Max', 'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_tot': 'Bwd IAT Total', 'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std', 'bwd_iat_max': 'Bwd IAT Max', 'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags', 'bwd_psh_flags': 'Bwd PSH Flags',
    'fwd_urg_flags': 'Fwd URG Flags', 'bwd_urg_flags': 'Bwd URG Flags',
    'fwd_header_len': 'Fwd Header Length', 'bwd_header_len': 'Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s', 'bwd_pkts_s': 'Bwd Packets/s',
    'pkt_len_min': 'Min Packet Length', 'pkt_len_max': 'Max Packet Length',
    'pkt_len_mean': 'Packet Length Mean', 'pkt_len_std': 'Packet Length Std',
    'pkt_len_var': 'Packet Length Variance', 'fin_flag_cnt': 'FIN Flag Count',
    'syn_flag_cnt': 'SYN Flag Count', 'rst_flag_cnt': 'RST Flag Count',
    'psh_flag_cnt': 'PSH Flag Count', 'ack_flag_cnt': 'ACK Flag Count',
    'urg_flag_cnt': 'URG Flag Count', 'cwr_flag_count': 'CWE Flag Count',
    'ece_flag_cnt': 'ECE Flag Count', 'down_up_ratio': 'Down/Up Ratio',
    'pkt_size_avg': 'Average Packet Size', 'fwd_seg_size_avg': 'Avg Fwd Segment Size',
    'bwd_seg_size_avg': 'Avg Bwd Segment Size', 'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
    'fwd_pkts_b_avg': 'Fwd Avg Packets/Bulk', 'fwd_blk_rate_avg': 'Fwd Avg Bulk Rate',
    'bwd_byts_b_avg': 'Bwd Avg Bytes/Bulk', 'bwd_pkts_b_avg': 'Bwd Avg Packets/Bulk',
    'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate', 'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_fwd_byts': 'Subflow Fwd Bytes', 'subflow_bwd_pkts': 'Subflow Bwd Packets',
    'subflow_bwd_byts': 'Subflow Bwd Bytes', 'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'init_bwd_win_byts': 'Init_Win_bytes_backward', 'fwd_act_data_pkts': 'act_data_pkt_fwd',
    'fwd_seg_size_min': 'min_seg_size_forward', 'active_mean': 'Active Mean',
    'active_std': 'Active Std', 'active_max': 'Active Max', 'active_min': 'Active Min',
    'idle_mean': 'Idle Mean', 'idle_std': 'Idle Std', 'idle_max': 'Idle Max', 'idle_min': 'Idle Min',
}

def analyze_pcap(pcap_file):
    """Analyse un fichier PCAP avec le modèle Random Forest"""
    if not os.path.exists(pcap_file):
        print(f"Fichier {pcap_file} introuvable")
        return

    print(f"📁 Analyse de {pcap_file}...")
    csv_file = pcap_file.replace('.pcap', '.csv')
    # Conversion PCAP -> CSV avec CICFlowMeter
    try:
        subprocess.run([CICFLOWMETER, "-f", pcap_file, "-c", csv_file],
                       check=True, timeout=60, capture_output=True)
    except Exception as e:
        print(f"❌ Erreur CICFlowMeter: {e}")
        return

    if not os.path.exists(csv_file):
        print("❌ Fichier CSV non généré")
        return

    # Charger le modèle
    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)

    # Lire le CSV
    df = pd.read_csv(csv_file)
    df.columns = df.columns.str.strip()
    df_renamed = df.rename(columns=COL_MAP)
    # Supprimer les doublons
    df_renamed = df_renamed.loc[:, ~df_renamed.columns.duplicated()]

    # Aligner les colonnes avec celles du modèle
    for col in model.feature_names_in_:
        if col not in df_renamed.columns:
            df_renamed[col] = 0
    df_model = df_renamed[model.feature_names_in_]
    df_model = df_model.fillna(0).replace([np.inf, -np.inf], 0)

    # Prédire
    preds = model.predict(df_model)
    labels = encoder.inverse_transform(preds)

    # Résultats
    from collections import Counter
    results = Counter(labels)
    print("\n📊 Résultats de l'analyse ML:")
    for label, count in results.items():
        if label == "BENIGN":
            print(f"  ✅ {label}: {count} flux")
        else:
            print(f"  🔴 {label}: {count} flux")
    print(f"   Précision du modèle sur dataset: 99.79%")
    # Nettoyer
    os.remove(csv_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_pcap.py <fichier.pcap>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
