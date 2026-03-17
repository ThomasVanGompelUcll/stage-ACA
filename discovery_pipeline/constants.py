import os

SEC_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
]

TAKEOVER_FINGERPRINTS = [
    {"provider": "GitHub Pages", "suffixes": ["github.io"]},
    {"provider": "Heroku", "suffixes": ["herokudns.com", "herokuapp.com"]},
    {"provider": "Azure App Service", "suffixes": ["azurewebsites.net"]},
    {"provider": "Fastly", "suffixes": ["fastly.net"]},
    {"provider": "Pantheon", "suffixes": ["pantheonsite.io"]},
    {"provider": "Shopify", "suffixes": ["myshopify.com"]},
    {"provider": "Zendesk", "suffixes": ["zendesk.com"]},
    {"provider": "Unbounce", "suffixes": ["unbouncepages.com"]},
    {"provider": "Readme", "suffixes": ["readme.io"]},
]

CLOUD_ENDPOINT_PATTERNS = [
    {"provider": "AWS S3", "markers": ["s3.amazonaws.com", "s3-website", ".s3."]},
    {"provider": "Azure Blob", "markers": ["blob.core.windows.net"]},
    {"provider": "Google Cloud Storage", "markers": ["storage.googleapis.com", "storage.cloud.google.com"]},
    {"provider": "CloudFront", "markers": ["cloudfront.net"]},
]

TOOL_PATH_OVERRIDES = {
    "subfinder": [
        os.getenv("SUBFINDER_PATH", "").strip(),
        r"C:\Tools\Subfinder\subfinder.exe",
    ],
    "amass": [
        os.getenv("AMASS_PATH", "").strip(),
        r"C:\Tools\Amass\amass.exe",
    ],
}
