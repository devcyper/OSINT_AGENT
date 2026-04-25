from typing import TypedDict, Annotated, List, Optional
from operator import add

class OSINTState(TypedDict):
    target: str                              # domain, IP, or email
    target_type: str                         # "domain" | "email" | "ip"
    tasks: List[str]                         # which agents to invoke
    dns_results: Optional[dict]
    whois_results: Optional[dict]
    shodan_results: Optional[dict]
    email_results: Optional[dict]
    social_results: Optional[dict]
    findings: Annotated[List[str], add]      # accumulated findings
    report: Optional[str]
    error: Optional[str]