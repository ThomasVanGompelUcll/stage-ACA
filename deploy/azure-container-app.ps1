param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = "",

    [Parameter(Mandatory = $false)]
    [string]$Location = "westeurope",

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = "rg-scanner-app",

    [Parameter(Mandatory = $false)]
    [string]$AcrName = "acascanneracr",

    [Parameter(Mandatory = $false)]
    [string]$ContainerEnvName = "aca-scanner-env",

    [Parameter(Mandatory = $false)]
    [string]$ContainerAppName = "aca-scanner-app",

    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName = "acascannerfiles",

    [Parameter(Mandatory = $false)]
    [string]$FileShareName = "results",

    [Parameter(Mandatory = $false)]
    [string]$ImageName = "scanner-app",

    [Parameter(Mandatory = $false)]
    [string]$ImageTag = "latest"
)

$ErrorActionPreference = "Stop"

function Assert-CliPresent {
    param(
        [string]$CliName,
        [string]$InstallHint
    )

    if (-not (Get-Command $CliName -ErrorAction SilentlyContinue)) {
        throw "$CliName is niet gevonden. $InstallHint"
    }
}

function Invoke-Az {
    param([string]$Command)

    Write-Host "-> $Command" -ForegroundColor Cyan
    Invoke-Expression $Command
}

Write-Host "\n=== Azure Container Apps deployment voor Scanner App ===" -ForegroundColor Green

Assert-CliPresent -CliName "az" -InstallHint "Installeer Azure CLI via: https://learn.microsoft.com/cli/azure/install-azure-cli"

Invoke-Az "az extension add --name containerapp --upgrade --yes"
Invoke-Az "az provider register --namespace Microsoft.App"
Invoke-Az "az provider register --namespace Microsoft.OperationalInsights"

$CurrentSubscription = az account show --query id -o tsv
if ([string]::IsNullOrWhiteSpace($CurrentSubscription)) {
    throw "Geen actieve Azure login gevonden. Voer eerst 'az login' uit."
}

if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Invoke-Az "az account set --subscription $SubscriptionId"
    $CurrentSubscription = az account show --query id -o tsv
}

Write-Host "Actieve subscription: $CurrentSubscription" -ForegroundColor Yellow

# 1) Resource group
Invoke-Az "az group create --name $ResourceGroup --location $Location"

# 2) ACR (image registry)
Invoke-Az "az acr create --name $AcrName --resource-group $ResourceGroup --location $Location --sku Basic --admin-enabled true"

# 3) Storage + file share voor persistente results
Invoke-Az "az storage account create --name $StorageAccountName --resource-group $ResourceGroup --location $Location --sku Standard_LRS --kind StorageV2"
Invoke-Az "az storage share-rm create --resource-group $ResourceGroup --storage-account $StorageAccountName --name $FileShareName --quota 100"

$StorageKey = az storage account keys list --resource-group $ResourceGroup --account-name $StorageAccountName --query "[0].value" -o tsv
if ([string]::IsNullOrWhiteSpace($StorageKey)) {
    throw "Kon storage account key niet ophalen."
}

# 4) Container Apps environment
Invoke-Az "az containerapp env create --name $ContainerEnvName --resource-group $ResourceGroup --location $Location"

# Koppel Azure Files aan de Container Apps environment
$EnvStorageName = "resultsstorage"
Invoke-Az "az containerapp env storage set --name $ContainerEnvName --resource-group $ResourceGroup --storage-name $EnvStorageName --azure-file-account-name $StorageAccountName --azure-file-account-key $StorageKey --azure-file-share-name $FileShareName --access-mode ReadWrite"

# 5) Build image in ACR (geen lokale Docker nodig)
$ImageRef = "$AcrName.azurecr.io/$ImageName`:$ImageTag"
Invoke-Az "az acr build --registry $AcrName --image $ImageName`:$ImageTag --file Dockerfile ."

# 6) Registry credentials
$AcrServer = "$AcrName.azurecr.io"
$AcrUser = az acr credential show --name $AcrName --query username -o tsv
$AcrPass = az acr credential show --name $AcrName --query "passwords[0].value" -o tsv
if ([string]::IsNullOrWhiteSpace($AcrUser) -or [string]::IsNullOrWhiteSpace($AcrPass)) {
    throw "Kon ACR credentials niet ophalen."
}

# 7) Eerste create
Invoke-Az "az containerapp create --name $ContainerAppName --resource-group $ResourceGroup --environment $ContainerEnvName --image $ImageRef --target-port 8080 --ingress external --cpu 1.0 --memory 2.0Gi --min-replicas 0 --max-replicas 1 --registry-server $AcrServer --registry-username $AcrUser --registry-password $AcrPass --env-vars PORT=8080 PYTHON_EXECUTABLE=python3"

# 8) Volume mount naar /app/results configureren
$VolumesJson = "[{\"name\":\"results-volume\",\"storageType\":\"AzureFile\",\"storageName\":\"$EnvStorageName\"}]"
$VolumeMountsJson = "[{\"volumeName\":\"results-volume\",\"mountPath\":\"/app/results\"}]"
Invoke-Az "az containerapp update --name $ContainerAppName --resource-group $ResourceGroup --set properties.template.volumes='$VolumesJson' properties.template.containers[0].volumeMounts='$VolumeMountsJson'"

$Fqdn = az containerapp show --name $ContainerAppName --resource-group $ResourceGroup --query properties.configuration.ingress.fqdn -o tsv
Write-Host "\nDeployment klaar." -ForegroundColor Green
Write-Host "App URL: https://$Fqdn" -ForegroundColor Green
Write-Host "\nVolgende stap: test /api/health en start daarna een volledige scan in de UI." -ForegroundColor Yellow
