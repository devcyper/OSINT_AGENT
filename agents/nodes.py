from langchain_core.messages import HumanMessage
from tools.tools import dns_lookup, zone_transfer_attempt, whois_lookup, shodan_host_lookup ,check_email_breach, validate_email_mx , username_search, github_user_recon
from state import OSINTState
from langchain.chat_models import init_chat_model
import socket

llm = init_chat_model("qwen3:latest",model_provider="ollama",base_url="http://localhost:11434")


def dns_node(state :dict):
    """Perform DNS enumeration and update state with results."""
    target = state["target"]
    dns_results = dns_lookup.invoke({"domain": target})
    zone_transfer = zone_transfer_attempt.invoke({"domain": target})
    prompt = f"""You are a DNS recon expert. Analyze this DNS data for {target}:
    DNS Records: {dns_results}
    Zone Transfer: {zone_transfer}

    Extract key findings: exposed mail servers, interesting TXT records (SPF/DKIM/DMARC gaps),
    subdomain hints, and any misconfigurations. Be concise."""

    response = llm.invoke([HumanMessage(content=prompt)])
    return {
        "dns_results": {**dns_results, **zone_transfer},
        "findings": [f"[DNS] {response.content}"],
    }

def whois_agent_node(state: dict) -> dict:
    target = state["target"]
    data = whois_lookup.invoke({"domain": target})

    prompt = f"""You are a WHOIS analyst. Here is registration data for {target}:
{data}

Note: registrant info, registration age, expiry proximity, privacy protection usage,
and any leaked emails/names. Be concise."""

    response = llm.invoke([HumanMessage(content=prompt)])
    return {
        "whois_results": data,
        "findings": [f"[WHOIS] {response.content}"],
    }

def shodan_agent_node(state: dict) -> dict:
    target = state["target"]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    host_data = shodan_host_lookup.invoke({"ip": ip})

    prompt = f"""You are a Shodan expert. Analyze this host intelligence for {target} ({ip}):
{host_data}

Highlight: exposed admin panels, unpatched CVEs, uncommon open ports, banners revealing
software versions, cloud provider info. Be concise."""

    response = llm.invoke([HumanMessage(content=prompt)])
    return {
        "shodan_results": host_data,
        "findings": [f"[SHODAN] {response.content}"],
    }

def email_agent_node(state: dict) -> dict:
    target = state["target"]
    breach_data = check_email_breach.invoke({"email": target})
    mx_data = validate_email_mx.invoke({"email": target})

    prompt = f"""You are an email OSINT analyst. Results for {target}:
Breaches: {breach_data}
MX Validation: {mx_data}

Summarize breach exposure, credential risk severity, and infrastructure notes. Be concise."""

    response = llm.invoke([HumanMessage(content=prompt)])
    return {
        "email_results": {**breach_data, **mx_data},
        "findings": [f"[EMAIL] {response.content}"],
    }

def social_agent_node(state: dict) -> dict:
    target = state["target"]
    username = target.split("@")[0] if "@" in target else target.split(".")[0]

    platform_data = username_search.invoke({"username": username})
    github_data = github_user_recon.invoke({"username": username})

    prompt = f"""You are a social media OSINT specialist. Results for username '{username}':
Platform presence: {platform_data}
GitHub: {github_data}

Summarize active accounts, leaked personal info, org affiliations, and tech stack hints. Be concise."""

    response = llm.invoke([HumanMessage(content=prompt)])
    return {
        "social_results": {"platforms": platform_data, "github": github_data},
        "findings": [f"[SOCIAL] {response.content}"],
    }