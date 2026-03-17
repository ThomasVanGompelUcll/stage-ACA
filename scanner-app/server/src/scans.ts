export type ScanField = {
  name: string;
  label: string;
  type: 'text' | 'textarea' | 'number' | 'password' | 'run-select' | 'select';
  placeholder?: string;
  required?: boolean;
  description?: string;
  defaultValue?: string | number;
  options?: Array<{
    value: string;
    label: string;
    description?: string;
  }>;
  helpItems?: string[];
};

export type ScanDefinition = {
  id: string;
  title: string;
  description: string;
  fields: ScanField[];
};

export const scanDefinitions: ScanDefinition[] = [
  {
    id: 'full-scan',
    title: 'Volledige scan',
    description: 'Voert de complete PASSIEVE discovery pipeline uit (zonder actieve exploit/port probing) en genereert alle CSV-rapporten plus het HTML-dashboard.',
    fields: [
      { name: 'domain', label: 'Root domain', type: 'text', placeholder: 'example.com', required: true },
      { name: 'officialDomainsText', label: 'Officiële domeinen', type: 'textarea', placeholder: 'example.com\nexample.org', description: 'Eén domein per regel voor Shadow IT matching.' },
      { name: 'ipinfoToken', label: 'IPInfo token', type: 'password', placeholder: 'Optioneel token voor ASN lookup' },
      { name: 'maxRelatedDomains', label: 'Max related domains', type: 'number', defaultValue: 10 },
    ],
  },
  {
    id: 'whois',
    title: 'WHOIS lookup',
    description: 'Haalt WHOIS-informatie op en zoekt gerelateerde domeinen.',
    fields: [
      { name: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com', required: true },
    ],
  },
  {
    id: 'ct-discovery',
    title: 'CT discovery',
    description: 'Zoekt subdomeinen via crt.sh en fallbacks op basis van het opgegeven domein.',
    fields: [
      { name: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com', required: true },
      { name: 'relatedDomainsText', label: 'Gerelateerde domeinen', type: 'textarea', placeholder: 'brand-example.com\nexample.org', description: 'Optioneel. Laat leeg om WHOIS reverse discovery te gebruiken.' },
      { name: 'maxRelatedDomains', label: 'Max related domains', type: 'number', defaultValue: 10 },
    ],
  },
  {
    id: 'subdomain-enumeration',
    title: 'Subdomain enumeration',
    description: 'Voert externe discovery tools uit zoals `subfinder` en `amass`.',
    fields: [
      { name: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com', required: true },
      { name: 'additionalSubdomainsText', label: 'Extra subdomeinen', type: 'textarea', placeholder: 'mail.example.com\nportal.example.com', description: 'Wordt samengevoegd met de tool-output.' },
    ],
  },
  {
    id: 'dns-resolution',
    title: 'DNS scan',
    description: 'Resolveert A, AAAA, CNAME en TXT records voor een handmatige lijst of een bestaande run.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Gebruik een bestaande run met een subdomain-bestand.' },
      { name: 'domain', label: 'Domain label', type: 'text', placeholder: 'example.com', description: 'Alleen gebruikt voor de bestandsnaam als er een nieuwe run wordt gemaakt.' },
      { name: 'subdomainsText', label: 'Subdomeinen', type: 'textarea', placeholder: 'www.example.com\napi.example.com', description: 'Laat leeg om hosts uit de gekozen run te gebruiken.' },
    ],
  },
  {
    id: 'reverse-ip',
    title: 'Reverse IP',
    description: 'Bouwt IP-clusters op basis van DNS-resultaten uit een run of een handmatige DNS CSV.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel als je een DNS CSV plakt.' },
      { name: 'dnsCsvText', label: 'DNS CSV inhoud', type: 'textarea', placeholder: 'source_file,scan_timestamp,domain,record_type,value', description: 'Volledige CSV inclusief header.' },
    ],
  },
  {
    id: 'asn-lookup',
    title: 'ASN lookup',
    description: 'Zoekt ASN- en provider-informatie op voor IP-adressen.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haalt IPs uit de DNS-resultaten van de run.' },
      { name: 'ipsText', label: 'IP adressen', type: 'textarea', placeholder: '1.1.1.1\n8.8.8.8', description: 'Laat leeg om IPs uit de gekozen run te gebruiken.' },
      { name: 'ipinfoToken', label: 'IPInfo token', type: 'password', placeholder: 'Optioneel token' },
    ],
  },
  {
    id: 'web-scan',
    title: 'Web scan',
    description: 'Scant HTTP en HTTPS op status, headers, titles en redirects.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haalt hosts uit de run.' },
      { name: 'domain', label: 'Domain label', type: 'text', placeholder: 'example.com' },
      { name: 'hostsText', label: 'Hosts', type: 'textarea', placeholder: 'www.example.com\nportal.example.com', description: 'Laat leeg om hosts uit de gekozen run te gebruiken.' },
    ],
  },
  {
    id: 'ssl-scan',
    title: 'SSL scan',
    description: 'Controleert certificaten, geldigheid en issuer per host.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haalt hosts uit de run.' },
      { name: 'domain', label: 'Domain label', type: 'text', placeholder: 'example.com' },
      { name: 'hostsText', label: 'Hosts', type: 'textarea', placeholder: 'www.example.com\nportal.example.com' },
    ],
  },
  {
    id: 'fingerprint',
    title: 'Fingerprinting',
    description: 'Combineert web-, DNS-, ASN- en SSL-data tot fingerprinting inzichten.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', required: true, description: 'De run moet DNS-, web-, ASN- en SSL-bestanden bevatten.' },
    ],
  },
  {
    id: 'shadow-it',
    title: 'Shadow IT',
    description: 'Markeert assets die buiten de lijst van officiële domeinen vallen.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haalt hosts uit de run.' },
      { name: 'domain', label: 'Root domain', type: 'text', placeholder: 'example.com', description: 'Verplicht als de run geen samenvatting bevat.' },
      { name: 'hostsText', label: 'Hosts', type: 'textarea', placeholder: 'www.example.com\napp.shadow-example.net' },
      { name: 'officialDomainsText', label: 'Officiële domeinen', type: 'textarea', placeholder: 'example.com\nexample.org', description: 'Eén domein per regel.' },
    ],
  },
  {
    id: 'risk-score',
    title: 'Risk scoring',
    description: 'Berekent risicoscores op basis van web-, SSL- en Shadow IT-data.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', required: true, description: 'De run moet web_scan_assets.csv, ssl_scan.csv en shadow_it.csv bevatten.' },
    ],
  },
  {
    id: 'screenshots',
    title: 'Screenshots (Manual/Optional)',
    description: 'Maakt webscreenshots van hosts. Optioneel en gescheiden van de full-scan. Vereist Playwright + Chromium.',
    fields: [
      { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haalt hosts uit de run.' },
      { name: 'domain', label: 'Domain label', type: 'text', placeholder: 'example.com' },
      { name: 'hostsText', label: 'Hosts', type: 'textarea', placeholder: 'www.example.com\nportal.example.com', description: 'Laat leeg om hosts uit de gekozen run te gebruiken.' },
    ],
  },
  {
    id: 'intelx-search',
    title: 'IntelX Credential Exposure',
    description: 'Zoekt op het darkweb naar gelekte credentials en data voor een domein of e-mailadres via Intelligence X. Vereist INTELX_API_KEY in .env.',
    fields: [
      { name: 'term', label: 'Domein of e-mail', type: 'text', placeholder: 'example.com of user@example.com', required: true },
      { name: 'days', label: 'Lookback (dagen)', type: 'number', defaultValue: 7, description: 'Resultaten ouder dan dit aantal dagen worden gefilterd.' },
      { name: 'limit', label: 'Max resultaten', type: 'number', defaultValue: 100, description: 'Maximaal aantal resultaten per zoekopdracht.' },
    ],
  },
  {
    id: 'port-scan',
    title: 'Port Scanning (Active)',
    description: '⚠️ WAARSCHUWING: Dit is een actieve scan die SIEM/firewall alerts kan triggeren. Alleen gebruiken met expliciete autorisatie. Nmap is vereist.',
    fields: [
      {
        name: 'target',
        label: 'Doel (hostname of IP)',
        type: 'text',
        placeholder: 'example.com of 192.168.1.1',
        required: true,
        description: 'Het systeem of domein dat je actief wilt scannen.',
      },
      {
        name: 'scanType',
        label: 'Scan type',
        type: 'select',
        defaultValue: 'sS',
        description: 'Kies hoe Nmap de poorten controleert.',
        options: [
          { value: 'sS', label: 'SYN stealth scan', description: 'Snel en gebruikelijk; valt vaak op in logging, maar maakt geen volledige TCP-verbinding.' },
          { value: 'sT', label: 'TCP connect scan', description: 'Volledige TCP-verbinding; werkt vaker zonder extra rechten, maar is luidruchtiger.' },
          { value: 'sU', label: 'UDP scan', description: 'Controleert UDP-diensten zoals DNS of SNMP; meestal trager en minder volledig.' },
          { value: 'sA', label: 'ACK scan', description: 'Handig om firewall-filtering te beoordelen; toont niet direct welke poorten open zijn.' },
        ],
      },
      {
        name: 'portsSpec',
        label: 'Port range',
        type: 'select',
        defaultValue: '--top-ports 1000',
        description: 'Kies welke poorten je wilt meenemen.',
        options: [
          { value: '--top-ports 100', label: 'Top 100 poorten', description: 'Snelle baseline voor veelgebruikte services.' },
          { value: '--top-ports 1000', label: 'Top 1000 poorten', description: 'Gebalanceerde standaardscan met goede dekking.' },
          { value: '-p 21,22,25,53,80,110,143,443,445,3389', label: 'Veelgebruikte infra-poorten', description: 'Richt zich op bekende beheer-, mail-, web- en Windows-poorten.' },
          { value: '-p 1-1024', label: 'Well-known ports (1-1024)', description: 'Alle standaard systeem- en infrastructuurpoorten.' },
          { value: '-p 1-65535', label: 'Alle TCP-poorten', description: 'Volledige poortscan; grondig maar trager en opvallender.' },
        ],
      },
      {
        name: 'extraArgs',
        label: 'Extra opties (optioneel)',
        type: 'textarea',
        placeholder: '-sV -Pn --reason',
        description: 'Extra Nmap-flags voor meer detail of aangepast gedrag.',
        helpItems: [
          '-sV → detecteert service- en versiedata op gevonden poorten.',
          '-O → probeert het besturingssysteem van het doel te herkennen.',
          '-Pn → slaat host discovery over; handig als ping wordt geblokkeerd.',
          '-T3 → rustiger tempo met minder kans op ruis of throttling.',
          '-T4 → sneller tempo, maar opvallender in monitoring.',
          '--reason → toont waarom Nmap een poort als open, filtered of closed markeert.',
        ],
      },
    ],
  },
];

export const scanDefinitionMap = new Map(scanDefinitions.map((scan) => [scan.id, scan]));
