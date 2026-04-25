import dns.resolver
import socket
from langchain_core.tools import tool
import whois
import shodan
import os
import re
import requests
import dns.resolver

HIBP_API_KEY = os.getenv("HIBP_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

@tool(description="Perform DNS enumeration for a domain, including A, MX, NS, TXT, CNAME records and attempt zone transfer.")
def dns_lookup(domain: str) -> dict:
    results = {}
    record_types = ["A", "MX", "NS", "TXT", "CNAME", "AAAA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [r.to_text() for r in answers]
        except Exception:
            results[rtype] = []

    # Reverse DNS
    try:
        a_records = results.get("A", [])
        if a_records:
            results["PTR"] = socket.gethostbyaddr(a_records[0])[0]
    except Exception:
        results["PTR"] = None

    return results

@tool(description="Attempt DNS zone transfer (AXFR) for a domain. Expected to fail on properly configured DNS servers.")
def zone_transfer_attempt(domain: str) -> dict:
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
            return {"zone_transfer": True, "records": [str(r) for r in z.nodes.keys()]}
    except Exception as e:
        return {"zone_transfer": False, "reason": str(e)}
    


@tool(description="Retrieve WHOIS registration data for a domain.")
def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "registrant_name": w.name,
            "registrant_org": w.org,
            "country": w.country,
            "status": w.status,
        }
    except Exception as e:
        return {"error": str(e)}
    


@tool(description="Query Shodan for open ports, banners, CVEs on a given IP")
def shodan_host_lookup(ip: str) -> dict:
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "hostnames": host.get("hostnames", []),
            "ports": host.get("ports", []),
            "vulns": list(host.get("vulns", {}).keys()),
            "services": [
                {
                    "port": item["port"],
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": item.get("data", "")[:200],
                }
                for item in host.get("data", [])
            ],
        }
    except Exception as e:
        return {"error": str(e)}

@tool(description="Search Shodan for hosts matching a query.")
def shodan_search(query: str) -> dict:
   
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(query, limit=10)
        return {
            "total": results["total"],
            "matches": [
                {
                    "ip": r["ip_str"],
                    "port": r["port"],
                    "org": r.get("org"),
                    "data": r.get("data", "")[:150],
                }
                for r in results["matches"]
            ],
        }
    except Exception as e:
        return {"error": str(e)}
    



@tool(description="Check HaveIBeenPwned for breaches associated with an email.")
def check_email_breach(email: str) -> dict:
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Agent",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        r = requests.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            return {
                "breached": True,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b["Name"],
                        "date": b["BreachDate"],
                        "data_classes": b["DataClasses"],
                    }
                    for b in breaches
                ],
            }
        elif r.status_code == 404:
            return {"breached": False}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

@tool(description="Extract domain from email and validate MX records exist.")
def validate_email_mx(email: str) -> dict:
    
    match = re.search(r"@(.+)$", email)
    if not match:
        return {"valid": False, "reason": "invalid format"}
    domain = match.group(1)
    try:
        mx = dns.resolver.resolve(domain, "MX")
        return {"valid": True, "mx_records": [r.to_text() for r in mx]}
    except Exception as e:
        return {"valid": False, "reason": str(e)}
    

# ─── SOCIAL ───────────────────────────────────────────────────────────────────

PLATFORMS = {
    "github":      "https://github.com/{username}",
    "twitter":     "https://twitter.com/{username}",
    "instagram":   "https://www.instagram.com/{username}",
    "reddit":      "https://www.reddit.com/user/{username}",
    "linkedin":    "https://www.linkedin.com/in/{username}",
    "hackernews":  "https://news.ycombinator.com/user?id={username}",
    "gitlab":      "https://gitlab.com/{username}",
    "medium":      "https://medium.com/@{username}",
}

@tool(description="Check if a username exists on popular platforms and return profile URLs.")
def username_search(username: str) -> dict:
    
    results = {}
    headers = {"User-Agent": "Mozilla/5.0 OSINT-Agent"}
    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username=username)
        try:
            r = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
            results[platform] = {
                "url":         url,
                "exists":      r.status_code == 200,
                "status_code": r.status_code,
            }
        except Exception as e:
            results[platform] = {"url": url, "exists": False, "error": str(e)}
    return results

@tool(description="Gather public GitHub profile info: name, bio, email, repos, orgs." )
def github_user_recon(username: str) -> dict:
    """Enumerate public GitHub profile: repos, orgs, email from commits."""
    base    = "https://api.github.com"
    headers = {"Accept": "application/vnd.github+json"}
    try:
        profile = requests.get(f"{base}/users/{username}",                          headers=headers, timeout=8).json()
        repos   = requests.get(f"{base}/users/{username}/repos?per_page=30",        headers=headers, timeout=8).json()
        orgs    = requests.get(f"{base}/users/{username}/orgs",                     headers=headers, timeout=8).json()
        return {
            "name":         profile.get("name"),
            "bio":          profile.get("bio"),
            "email":        profile.get("email"),
            "location":     profile.get("location"),
            "company":      profile.get("company"),
            "followers":    profile.get("followers"),
            "public_repos": profile.get("public_repos"),
            "repos": [
                {
                    "name":        r.get("name"),
                    "description": r.get("description"),
                    "language":    r.get("language"),
                    "stars":       r.get("stargazers_count"),
                }
                for r in (repos if isinstance(repos, list) else [])[:10]
            ],
            "orgs": [o.get("login") for o in (orgs if isinstance(orgs, list) else [])],
        }
    except Exception as e:
        return {"error": str(e)}
    

