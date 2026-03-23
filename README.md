# Exposure Monitoring Toolkit

Compacte toolkit voor externe exposure monitoring van domeinen.

## Wat dit project doet

Dit project verzamelt en rapporteert extern zichtbare assets en risico-signalen.

- Passieve discovery en correlatie (WHOIS, CT, DNS, web, SSL, ASN)
- Shadow IT detectie en risicoscore
- Extra passieve checks:
  - email security (SPF/DMARC/MTA-STS/TLS-RPT)
  - subdomain takeover signalen
  - cloud misconfiguration signalen
  - passieve vulnerability indicators
- HTML dashboard + CSV outputs per scan-run

## Scanmodellen

### 1) Volledige scan (aanbevolen)
Passief en low-noise. Geen actieve poortscan of exploitpogingen.

### 2) Handmatige modules (los)
Alleen indien nodig:

- Port/Vulnerability scan (actief) via Nmap
- Credential exposure via IntelX
- Screenshots via Playwright

## Vereisten

Minimaal (voor passieve volledige scan):

- Python 3.10+
- Python packages: `requests`, `dnspython`

Optioneel:

- `IPINFO_TOKEN` voor betere ASN/provider-data
- `subfinder`, `amass` voor extra subdomain enumeration

Handmatig/gescheiden:

- Nmap (actieve scans)
- IntelX API key (`INTELX_API_KEY`)
- Playwright + Chromium (screenshots)

## IntelX API key instellen

Lokaal:

1. Kopieer `.env.example` naar `.env` in de projectroot.
2. Vul `INTELX_API_KEY` in (en optioneel `INTELX_BASE_URL` / `INTELX_DELAY`).

Azure Container Apps:

1. Zet de key als secret `intelxapikey` op de Container App.
2. Controleer dat environment variable `INTELX_API_KEY` verwijst naar die secret.

## Installatie (Python)

```powershell
# in projectroot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Als er geen `requirements.txt` is, installeer minimaal:

```powershell
pip install requests dnspython
```

Voor screenshots (optioneel):

```powershell
pip install playwright
python -m playwright install chromium
```

## Gebruik via CLI

Volledige scan starten:

```powershell
python complete.py --domain example.com
```

Optionele parameters:

```powershell
python complete.py --domain example.com --official-domains-file official_domains.txt --ipinfo-token <TOKEN> --max-related-domains 10
```

Output staat in `results/<domain>_<timestamp>/`.

## Gebruik via scanner-app (UI)

De webapp staat in `scanner-app/`.

```powershell
cd scanner-app
npm install
npm run dev
```

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:4000`

Meer details: zie `scanner-app/README.md`.

## Deployment op Azure (Container Apps)

Voor de goedkoopste managed cloud-optie met persistente scanresultaten:

- Gebruik de handleiding in `deploy/README.md`
- Start automatische deployment met `deploy/azure-container-app.ps1`

Dit pad gebruikt:

- Azure Container Apps (Consumption)
- Azure Container Registry (ACR)
- Azure Files mount op `/app/results`

## Belangrijkste outputbestanden per run

- `summary.json`
- `dashboard.html`
- `whois_related.csv`
- `ct_log_discovery.csv`, `ct_source_status.csv`
- `dns_scan_*.csv`
- `reverse_ip_clusters.csv`
- `asn_lookup.csv`
- `web_scan_assets.csv`
- `ssl_scan.csv`
- `fingerprinting.csv`
- `shadow_it.csv`
- `risk_scores.csv`
- `email_security.csv`
- `subdomain_takeover_candidates.csv`
- `cloud_misconfigurations.csv`
- `vulnerability_passive.csv`
- optioneel: `screenshots.csv`, `port_scan_results.csv`, `intelx_results.csv`

## Veiligheid en legal

- Gebruik actieve scans alleen met expliciete toestemming.
- Volledige scan is bedoeld als passieve baseline-monitoring.
- Behandel scanresultaten als vertrouwelijke securitydata.
