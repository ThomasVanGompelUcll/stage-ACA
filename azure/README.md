# Azure Discovery (Separated Workspace)

Deze map is bewust los gehouden van de scanner-tooling.
Hier staat een startpunt voor Azure environment discovery / audit inventory.

## Doel

Automatisch inzicht geven in:

- welke resources bestaan in een subscription
- welke workload types aanwezig zijn
- welke App Services/Functions een identity gebruiken
- welke webapps een GitHub deployment source hebben
- welke app setting keys op connecties kunnen wijzen (optioneel, zonder secret values te exporteren)

## Vereisten

- Azure CLI (`az`) geinstalleerd
- Ingelogd via `az login`
- Toegang tot de gewenste subscription

## Gebruik

Vanuit project root:

```powershell
python azure/discovery_tool.py
```

Specifieke subscription:

```powershell
python azure/discovery_tool.py --subscription "<subscription-id-of-name>"
```

Inclusief analyse van app setting key names:

```powershell
python azure/discovery_tool.py --include-app-settings
```

Aangepaste output map:

```powershell
python azure/discovery_tool.py --output-dir azure/output
```

## Output

Het script schrijft timestamped rapporten naar `azure/output/`:

- `azure_inventory_*.json`
- `azure_resources_*.csv`
- `azure_relationships_*.csv`
- `azure_summary_*.md`

## Veiligheid

- Secret values worden niet naar output geschreven.
- Bij `--include-app-settings` worden alleen key names geanalyseerd.
- Voor productie: combineer dit met Entra ID auth + RBAC + gecentraliseerde storage.

## Volgende stappen

- Entra ID/JWT authenticatie toevoegen aan een API-laag
- Resource Graph queries toevoegen voor schaal
- Netwerkrelaties (VNet/Subnet/NSG) uitbreiden
- Key Vault policy / role assignment mapping toevoegen
- Visuele graph-export (bijv. Mermaid/Neo4j input) toevoegen
