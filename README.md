# IntelliGuard – Système de Détection d'Intrusion

## Composants
- `ids_realtime.py` : IDS temps réel avec modèle Random Forest (99.79%)
- `ids_agent/` : Dashboard web
- `agent_local.py` : Agent pour postes distants
- `analyze_pcap.py` : Analyse hors ligne sur fichiers PCAP

## Installation
```bash
sudo apt install python3 python3-pip tcpdump tshark -y
pip3 install -r requirements.txt
```

## Lancement
- Dashboard : `cd ids_agent && python3 agent.py`
- IDS : `sudo python3 ids_realtime.py`

## Accès Dashboard
- URL : `http://IP_SERVEUR:5000`
