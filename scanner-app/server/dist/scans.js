export const scanDefinitions = [
    {
        id: 'full-scan',
        title: 'Volledige scan',
        description: 'Voert de complete passieve discovery pipeline uit en genereert CSV-rapporten plus het HTML-dashboard.',
        fields: [
            { name: 'domain', label: 'Root domain', type: 'text', placeholder: 'example.com', required: true },
            { name: 'officialDomainsText', label: 'Officiele domeinen', type: 'textarea', placeholder: 'example.com\nexample.org', description: 'Een domein per regel voor Shadow IT matching.' },
            { name: 'ipinfoToken', label: 'IPInfo token', type: 'password', placeholder: 'Optioneel token voor ASN lookup' },
            { name: 'maxRelatedDomains', label: 'Max related domains', type: 'number', defaultValue: 10 },
        ],
    },
    {
        id: 'port-scan',
        title: 'Port Scanning (Active)',
        description: 'Actieve Nmap scan. Alleen gebruiken met expliciete autorisatie.',
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
                    { value: 'sS', label: 'SYN stealth scan', description: 'Snel en gebruikelijk; maakt geen volledige TCP-verbinding.' },
                    { value: 'sT', label: 'TCP connect scan', description: 'Volledige TCP-verbinding; werkt vaak zonder extra rechten.' },
                    { value: 'sU', label: 'UDP scan', description: 'Controleert UDP-diensten zoals DNS of SNMP; vaak trager.' },
                    { value: 'sA', label: 'ACK scan', description: 'Nuttig om firewall-filtering te beoordelen.' },
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
                    { value: '-p 1-65535', label: 'Alle TCP-poorten', description: 'Volledige poortscan; grondig maar trager.' },
                ],
            },
            {
                name: 'extraArgs',
                label: 'Extra opties (optioneel)',
                type: 'textarea',
                placeholder: '-sV -Pn --reason',
                description: 'Extra Nmap-flags voor meer detail of aangepast gedrag.',
                helpItems: [
                    '-sV -> detecteert service- en versiedata op gevonden poorten.',
                    '-O -> probeert het besturingssysteem van het doel te herkennen.',
                    '-Pn -> slaat host discovery over; handig als ping wordt geblokkeerd.',
                    '-T3 -> rustiger tempo met minder kans op ruis of throttling.',
                    '-T4 -> sneller tempo, maar opvallender in monitoring.',
                    '--reason -> toont waarom Nmap een poort als open, filtered of closed markeert.',
                ],
            },
        ],
    },
    {
        id: 'screenshots',
        title: 'Screenshots',
        description: 'Maakt webscreenshots van hosts. Vereist Playwright + Chromium.',
        fields: [
            { name: 'runId', label: 'Bestaande run', type: 'run-select', description: 'Optioneel. Haal hosts uit een bestaande run.' },
            { name: 'domain', label: 'Domain label', type: 'text', placeholder: 'example.com' },
            { name: 'hostsText', label: 'Hosts', type: 'textarea', placeholder: 'www.example.com\nportal.example.com', description: 'Laat leeg om hosts uit de gekozen run te gebruiken.' },
        ],
    },
];
export const scanDefinitionMap = new Map(scanDefinitions.map((scan) => [scan.id, scan]));
