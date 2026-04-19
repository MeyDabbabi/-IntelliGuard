# IntelliGuard – Network Intrusion Detection System

**IntelliGuard** est un système de détection d'intrusion réseau (IDS) basé sur du machine learning (Random Forest) et des règles comportementales. Il permet une surveillance en temps réel du trafic, une centralisation des alertes via un tableau de bord web, et un déploiement en architecture agent / serveur.

## ✨ Fonctionnalités

- **Détection temps réel** : analyse du trafic réseau avec des règles Scapy (DDoS, PortScan, SSH/FTP brute force, Bot) et possibilité d’intégrer un modèle Random Forest.
- **Modèle ML** : Random Forest entraîné sur le dataset CICIDS2017 avec une **précision de 99,79 %** (fichier `.pkl` fourni).
- **Tableau de bord web** : interface Flask avec authentification, statistiques en temps réel, historique des alertes (SQLite), recherche multicritères, export PCAP (format Wireshark).
- **Architecture centralisée** : un serveur central héberge le dashboard, des agents légers peuvent être déployés sur les autres postes pour remonter leurs alertes.
- **Alertes** : notifications sur le dashboard, emails, et possibilité d’extension vers Telegram/WhatsApp.
- **Sauvegarde automatique des captures** : les fichiers PCAP sont horodatés et stockés localement.

## 🏗️ Architecture
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ PC Agent 1 │ │ PC Agent 2 │ │ PC Agent N │
│ (agent_local.py)│─────▶│ (agent_local.py)│─────▶│ (agent_local.py)│
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
│ │ │
└────────────────────────┼────────────────────────┘
│
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
# Mise à jour et installation des paquets système
sudo apt update
sudo apt install python3 python3-pip tcpdump tshark -y

# Téléchargement du projet
git clone https://github.com/MeyDabbabi/-IntelliGuard.git
cd -IntelliGuard

# Installation des dépendances Python (de préférence dans un venv)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Sur un poste client (agent local)
bash
# Même principe : installer Python, tcpdump, puis le script agent_local.py
# Modifier la variable SERVER_IP dans agent_local.py pour pointer vers l’IP du serveur central
🧪 Utilisation
Démarrer le tableau de bord
bash
cd ids_agent
source ../venv/bin/activate   # si vous utilisez un environnement virtuel
python3 agent.py
Le dashboard est alors accessible sur http://<IP_SERVEUR>:5000.
Identifiants par défaut :

Login : admin

Mot de passe : G7!tR3$mK9#pLx2@qW5z

⚠️ Sécurité : changez ce mot de passe lors du premier déploiement en production (modifiez VALID_PASSWORD dans agent.py).

Démarrer l’IDS temps réel (sur le serveur)
bash
cd ..
sudo venv/bin/python3 ids_realtime.py
Lancer un agent local (sur un autre PC)
bash
python3 agent_local.py
📦 Contenu du dépôt
Fichier / Dossier	Description
ids_realtime.py	Moteur principal de détection (règles Scapy + modèle ML optionnel)
ids_agent/	Dossier contenant le dashboard (Flask), les templates, les fichiers statiques et la base de données
agent_local.py	Script pour les postes distants (capture locale et envoi des alertes)
analyze_pcap.py	Analyse hors ligne de fichiers PCAP avec le modèle Random Forest
intrusion_detection_FINAL.pkl	Modèle Random Forest pré‑entraîné
label_encoder_FINAL.pkl	Encodeur des labels associés
requirements.txt	Dépendances Python
LICENSE	Licence MIT
🛠️ Personnalisation
Seuils de détection : modifiez les valeurs dans la fonction rule_based_detection() de ids_realtime.py.

Ajout d’un certificat HTTPS : pour la production, placez le dashboard derrière Nginx avec Let’s Encrypt.

Notifications supplémentaires : intégrez un bot Telegram (voir la documentation en ligne).

📄 Licence
Ce projet est distribué sous la licence MIT. Voir le fichier LICENSE pour plus de détails.

🙏 Remerciements
Dataset CICIDS2017 (Canadian Institute for Cybersecurity)

Bibliothèques : Scapy, Scikit‑learn, Flask, SocketIO, etc.
