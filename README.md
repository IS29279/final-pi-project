# Pi Intrusion Testing Appliance (PITA)
## ITP 258 — Team 3 — Sprint 2

---

### File Structure

```
final-pi-project/
├── FinalApp.py         # Flask application factory and routes
├── models.py           # SQLAlchemy database models
├── orchestrator.py     # Nmap + tshark orchestration layer
├── requirements.txt
├── reports/            # Generated .txt report files (auto-created)
└── templates/
    ├── main.html
    ├── scan_detail.html
    └── report.html
```

The database file `final-pi-project.db` is created automatically on first run inside the `final-pi-project/` directory.

---

### Pi Setup (one-time)

```bash
# System dependencies
sudo apt update
sudo apt install nmap tshark python3-pip python3-venv -y

# Allow tshark to capture without sudo (add your user to wireshark group)
sudo usermod -aG wireshark $USER
# Log out and back in for this to take effect

# Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Running the App

```bash
source venv/bin/activate
python FinalApp.py
```

The app will be available at `http://<pi-ip>:5000` from any device on the same network.

---

### Running a Scan from the CLI (testing without the browser)

```bash
source venv/bin/activate
python orchestrator.py --target 192.168.1.0/24 --duration 30 --interface wlan0
```

---

### Sprint 2 Demo Checklist

- [ ] Pi accessible over SSH
- [ ] `python FinalApp.py` starts without errors
- [ ] Dashboard loads at `http://<pi-ip>:5000`
- [ ] `final-pi-project.db` exists and tables are visible (`sqlite3 instance/final-pi-project.db .tables`  — run from inside `final-pi-project/`)
- [ ] Submitting the scan form creates a Scan record
- [ ] After scan completes, hosts and ports appear on the detail page
- [ ] Report page displays generated text

---

### Updating the Target Subnet

Edit `DEFAULT_TARGET` at the top of `orchestrator.py` to match the actual network being assessed, or pass it at runtime via the web form or `--target` CLI flag.
