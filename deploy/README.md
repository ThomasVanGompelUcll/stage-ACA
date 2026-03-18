# Azure setup voor Scanner App (Container Apps)

Deze map bevat een geautomatiseerde deployment voor Azure Container Apps met persistente opslag voor scanresultaten.

## Wat het script doet

1. Maakt een resource group
2. Maakt Azure Container Registry (ACR)
3. Maakt Storage Account + File Share (results)
4. Maakt Container Apps environment
5. Koppelt Azure Files aan die environment
6. Bouwt je Docker image in ACR (zonder lokale Docker)
7. Deployt de Container App
8. Mount de results share op /app/results

## Vereisten

- Azure CLI
- Toegang tot een Azure subscription met rechten om resources te maken
- Ingelogd met az login

Optioneel:
- PowerShell 7+

## Belangrijk

De Docker image verwacht dat scanresultaten in /app/results terechtkomen.
De deployment mount daarom een Azure File Share op dat pad.

## Snelle start

Vanuit de projectroot:

~~~powershell
az login
pwsh ./deploy/azure-container-app.ps1
~~~

## Met eigen namen/locatie

~~~powershell
pwsh ./deploy/azure-container-app.ps1 \
  -Location westeurope \
  -ResourceGroup rg-aca-scanner-prod \
  -AcrName acascanneracrprod \
  -ContainerEnvName aca-scanner-env-prod \
  -ContainerAppName aca-scanner-prod \
  -StorageAccountName acascannerfilesprod \
  -FileShareName results \
  -ImageTag v1
~~~

## Na deployment

1. Open de app URL uit de script-output
2. Check health endpoint:

~~~text
https://<jouw-fqdn>/api/health
~~~

3. Start een full scan in de UI
4. Controleer dat outputs verschijnen in /app/results (via Azure portal of storage explorer)

## GitHub Actions pipeline (automatisch deployen)

Workflowbestand:

- `.github/workflows/deploy-container-app.yml`

Benodigde GitHub secret:

- `AZURE_CREDENTIALS`

Maak een service principal en gebruik de JSON-output als waarde voor `AZURE_CREDENTIALS`:

~~~bash
az ad sp create-for-rbac \
  --name "github-actions-scanner-app" \
  --role Contributor \
  --scopes /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP> \
  --sdk-auth
~~~

Optionele GitHub repository variables (anders gebruikt de workflow defaults):

- `AZURE_RESOURCE_GROUP` (default: `stage-scanner-app`)
- `AZURE_CONTAINER_APP_NAME` (default: `aca-scanner-app`)
- `AZURE_ACR_NAME` (default: `acaScannerApp`)

Trigger:

- Automatisch op push naar `main`
- Handmatig via `workflow_dispatch`

## Kostenrichting

Container Apps op Consumption met min-replicas 0 is meestal de goedkoopste optie bij lage activiteit.
Houd rekening met:

- Container Apps usage
- ACR Basic
- Storage account + file share

## Troubleshooting

- Fout: az not recognized
  - Installeer Azure CLI en herstart terminal
- Fout bij container build
  - Controleer of Dockerfile in projectroot staat
- Fout met storage account naam
  - Naam moet wereldwijd uniek zijn, alleen kleine letters en cijfers
- Scanresultaten verdwijnen na restart
  - Verifieer of de mount naar /app/results actief is
