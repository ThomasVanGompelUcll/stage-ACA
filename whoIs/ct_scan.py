import requests

def get_ct_domains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
    except:
        return []

    found = set()

    for entry in data:
        name = entry.get("name_value", "")
        # crt.sh returns weird wildcard formats sometimes
        name = name.replace("*.","").strip().lower()
        if "." in name:
            found.add(name)

    return sorted(found)


if __name__ == "__main__":
    domain = "crowefoederer.nl"
    print("[CRT.SH] Discovering CT logs...")

    ct_domains = get_ct_domains(domain)
    print("\n[CT DOMAINS FOUND]")
    for d in ct_domains:
        print(" -", d)
