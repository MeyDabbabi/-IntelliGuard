# IntelliGuard – Network Intrusion Detection System

**IntelliGuard** est un système de détection d'intrusion réseau (IDS) basé sur du machine learning (Random Forest) et des règles comportementales. Il permet une surveillance en temps réel du trafic, une centralisation des alertes via un tableau de bord web, et un déploiement en architecture agent / serveur.

## ✨ Fonctionnalités

- **Détection temps réel** : analyse du trafic réseau avec des règles Scapy (DDoS, PortScan, SSH/FTP brute force, Bot) et intégration d’un modèle Random Forest.
- **Modèle ML** : Random Forest entraîné sur le dataset CICIDS2017 avec une **précision de 99,79 %** (fichier `.pkl` fourni).
- **Tableau de bord web** : interface Flask avec authentification, statistiques en temps réel, historique des alertes (SQLite), recherche multicritères, export PCAP.
- **Architecture centralisée** : un serveur central héberge le dashboard, des agents légers peuvent être déployés sur les autres postes.
- **Sauvegarde automatique des captures** : les fichiers PCAP sont horodatés et stockés localement.

## 🏗️ Architecture
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ PC Agent 1 │ │ PC Agent 2 │ │ PC Agent N │
│ (agent_local.py)│─────▶│ (agent_local.py)│─────▶│ (agent_local.py)│
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
│ │ │
└────────────────────────┼────────────────────────┘
▼
┌─────────────────────────┐
│ Serveur Central │
│ Dashboard + IDS temps réel
│ (agent.py + ids_realtime.py)
└─────────────────────────┘

text

## 🚀 Installation

### Sur le serveur central (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install python3 python3-pip tcpdump tshark -y
git clone https://github.com/MeyDabbabi/-IntelliGuard.git
cd -IntelliGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Sur un poste client (agent local)
bash
# Installer Python, tcpdump, puis copier agent_local.py
# Modifier SERVER_IP dans agent_local.py
🧪 Utilisation
Démarrer le tableau de bord
bash
cd ids_agent
source ../venv/bin/activate
python3 agent.py
Accès : http://<IP_SERVEUR>:5000
Identifiants par défaut : admin / G7!tR3$mK9#pLx2@qW5z

⚠️ Changez ce mot de passe en production.

Démarrer l’IDS temps réel
bash
cd ..
sudo venv/bin/python3 ids_realtime.py
Lancer un agent local
bash
python3 agent_local.py
📦 Contenu du dépôt
Fichier / Dossier	Description
ids_realtime.py	Moteur principal (règles Scapy + ML optionnel)
ids_agent/	Dashboard Flask, templates, base de données
agent_local.py	Agent pour postes distants
analyze_pcap.py	Analyse hors ligne avec le modèle ML
intrusion_detection_FINAL.pkl	Modèle Random Forest
label_encoder_FINAL.pkl	Encodeur des labels
requirements.txt	Dépendances Python
LICENSE	Licence MIT
🛠️ Personnalisation
Seuils de détection : modifiez rule_based_detection() dans ids_realtime.py.

HTTPS : placez le dashboard derrière Nginx avec Let’s Encrypt.

📄 Licence
Ce projet est distribué sous la licence MIT. 

🙏 Remerciements
Dataset CICIDS2017 (Canadian Institute for Cybersecurity)

Bibliothèques : Scapy, Scikit‑learn, Flask, SocketIO, etc.
