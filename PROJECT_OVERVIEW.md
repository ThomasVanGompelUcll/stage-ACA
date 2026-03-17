# Projectoverzicht – Exposure Monitoring Toolkit

## 1. Waarom dit project nuttig is

Organisaties hebben vaak onvoldoende zicht op wat extern zichtbaar is op internet. Dit project helpt om dat overzicht gestructureerd op te bouwen en periodiek te herhalen.

Concrete waarde:

- Vroegtijdig detecteren van onbedoelde blootstelling (assets, headers, certificaten, DNS)
- Sneller prioriteren van risico’s via een uniforme risicoscore
- Inzicht in Shadow IT en onofficiële assets
- Betere basis voor rapportage naar IT, security en management
- Reproduceerbare runs met duidelijke output (CSV + dashboard)

Kort: het project maakt exposure-monitoring praktisch, meetbaar en herhaalbaar.

---

## 2. Doel en afbakening

### Doel
Een betrouwbare baseline-scan leveren die veilig en consistent draait op een standaard laptopomgeving.

### Afbakening
De **volledige scan** is bewust vooral passief en low-noise:

- wel: discovery, correlatie, posture checks, risicoschatting
- niet: actieve exploitatie of agressieve netwerkprobes

Actieve onderdelen bestaan wel, maar blijven gescheiden als handmatige modules.

---

## 3. Belangrijkste ontwerpkeuzes

### Keuze 1 – Passieve full scan als standaard
Waarom:

- veiliger operationeel
- minder kans op SIEM/SOC-alerts
- juridisch eenvoudiger verdedigbaar

Gevolg:

- geschikt voor frequente monitoring
- diepgaande validatie gebeurt daarna handmatig waar nodig

### Keuze 2 – Modulaire opbouw
Waarom:

- elke scanstap is afzonderlijk bruikbaar
- eenvoudiger onderhoud en uitbreiding
- UI en CLI kunnen dezelfde logica hergebruiken

Gevolg:

- zowel complete runs als gerichte deel-scans zijn mogelijk

### Keuze 3 – Tooling met minimale verplichtingen
Waarom:

- lage instap voor gebruikers
- minder afhankelijkheden op endpoints

Gevolg:

- baseline draait op Python + packages
- externe binaries (zoals Nmap) zijn optioneel en gescheiden

### Keuze 4 – Resultaatgericht rapporteren
Waarom:

- gebruikers willen niet alleen ruwe data, maar ook context

Gevolg:

- per run: CSV-bestanden, summary en dashboard
- prioritering via risiconiveaus

---

## 4. Welke delen het project bevat

## 4.1 Core scan pipeline
Bestand: `complete.py`

Verantwoordelijk voor de volledige end-to-end scan:

1. WHOIS + related domains
2. CT/subdomain discovery
3. DNS-resolutie
4. Reverse IP + ASN
5. Web + SSL observatie
6. Fingerprinting
7. Shadow IT
8. Risk scoring
9. Email security checks
10. Subdomain takeover signalen (passief)
11. Cloud misconfig signalen (passief)
12. Passive vulnerability indicators
13. Rapportage

## 4.2 API/bridge-laag
Bestand: `scan_bridge.py`

Verbindt de scanlogica met de scanner-app backend en biedt acties per scanmodule.

## 4.3 Webapp
Map: `scanner-app/`

- frontend: scan starten en resultaten bekijken
- backend: scanacties aanroepen, runs ophalen, bestanden aanbieden

## 4.4 Gescheiden handmatige modules
Voor acties met hogere impact of extra afhankelijkheden:

- `port_scan.py` (actief, Nmap)
- IntelX credential exposure (API-key vereist)
- screenshots (Playwright + Chromium)

---

## 5. Proces op hoofdlijnen

1. Input: domein + optionele parameters
2. Dataverzameling: DNS/WHOIS/CT/Web/SSL/ASN
3. Verrijking: fingerprinting, shadow IT, posture checks
4. Scoring: risico per asset
5. Output: dashboard + CSV + summary
6. Beslissing: wel/geen handmatige vervolgscan

Dit ondersteunt een vast werkmodel: **passieve baseline eerst, actieve validatie alleen waar nodig**.

---

## 6. Waarom deze architectuur werkt

- **Praktisch inzetbaar:** weinig setup voor de basis
- **Schaalbaar in gebruik:** van kleine checks tot volledige runs
- **Beheersbaar risico:** actieve scans staan niet in het standaardpad
- **Herhaalbaarheid:** outputstructuur per run is consistent
- **Uitbreidbaar:** nieuwe modules kunnen toegevoegd worden zonder de kern te breken

---

## 7. Bekende trade-offs

- Passieve checks geven signalen, geen volledige exploit-validatie
- Sommige externe bronnen hebben rate-limits of variabele kwaliteit
- Tooling zoals subfinder/amass verhoogt dekking, maar is niet altijd beschikbaar

Daarom blijft menselijke validatie belangrijk voor high/critical bevindingen.

---

## 8. Wanneer welke scan gebruiken

### Gebruik volledige scan
Als je periodiek overzicht, trends en prioritering wil zonder onnodige ruis.

### Gebruik handmatige actieve modules
Als er expliciete autorisatie is en je technische bevestiging wil van specifieke risico’s.

---

## 9. Samenvatting

Dit project is ontworpen om exposure monitoring betrouwbaar en werkbaar te maken:

- standaard: passieve, legale baseline
- aanvullend: gerichte handmatige validatie
- resultaat: duidelijke inzichten en concrete opvolging
