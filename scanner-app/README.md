# Discovery Scanner App

TypeScript + React full stack applicatie bovenop de bestaande Python scans.

## Wat zit erin

- React dashboard voor handmatige scans per module
- Express API die scan-aanvragen verwerkt
- Python bridge die de bestaande scripts en `complete.py` hergebruikt
- Overzicht van bestaande runs in `results/`
- Directe links naar CSV-output en `dashboard.html`

## Scope van de volledige scan

De `Volledige scan` blijft passief en defensief:

- DNS/CT/WHOIS discovery
- web- en SSL observatie
- Shadow IT en risk scoring
- email security checks (SPF/DMARC/MTA-STS/TLS-RPT)
- passieve subdomain takeover signalen
- passieve cloud misconfiguration signalen
- passieve vulnerability indicators

Niet inbegrepen in de full-scan (bewust gescheiden):

- actieve port/vulnerability scans (Nmap)
- credential exposure (IntelX)
- screenshots (optionele handmatige module)

## Structuur

- `client/`: React + Vite frontend
- `server/`: Express + TypeScript backend
- `../scan_bridge.py`: Python bridge naar de huidige scanlogica

## Starten

1. Installeer dependencies:
   - `npm install`
2. Start backend + frontend:
   - `npm run dev`
3. Open daarna:
   - `http://localhost:5173`

## Productie build

- `npm run build`
- `npm run start`

De backend draait standaard op poort `4000` en serveert in productie automatisch de gebouwde React client.

## Python omgeving

De server zoekt standaard eerst naar:

- Windows: `../.venv/Scripts/python.exe`
- Linux/macOS: `../.venv/bin/python`

Je kunt dit overschrijven via environment variable `PYTHON_EXECUTABLE`.

## Nmap voor Port Scan

Voor de `Port Scanning (Active)` module moet Nmap beschikbaar zijn.

- Installeer Nmap via https://nmap.org/download.html (of package manager)
- Of zet in `.env` (project root):
   - `NMAP_PATH=C:\\Program Files\\Nmap\\nmap.exe`

De bridge probeert automatisch:

- `NMAP_PATH` / `NMAP_EXECUTABLE`
- `nmap` op PATH
- bekende Windows install-paden

## Screenshots (optioneel)

De `Screenshots (Manual/Optional)` scan gebruikt Playwright en is bewust apart gehouden van de full-scan.

- `pip install playwright`
- `python -m playwright install chromium`
