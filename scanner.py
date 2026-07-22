import re
import yaml
from typing import Dict, Any, List

def check_hardcoded_secret(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # High-confidence credential signatures
    secret_patterns = [
        r"(?:sk-[a-zA-Z0-9_-]{20,})",                             # OpenAI / Stripe
        r"(?:ghp_[a-zA-Z0-9]{36})",                              # GitHub PAT
        r"(?:AKIA[0-9A-Z]{16})",                                # AWS Access Key ID
        r"(?:-----BEGIN (?:RSA )?PRIVATE KEY-----)",            # PEM Private Key
        r"https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@",               # Basic Auth embedded in URL
        r"https://hooks\.slack\.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/[A-Za-z0-9_]+", # Slack Webhook
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",                 # Discord Webhook
        # Literal key/secret string assignments with non-placeholder values
        r"(?i)(?:api[_-]?key|secret_key|private_key|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\~]{16,}['\"]"
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, raw_markdown):
            return True

    # Check YAML frontmatter for raw credential strings
    def scan_dict(d: dict) -> bool:
        for k, v in d.items():
            if isinstance(v, str):
                if re.search(r"(?i)(key|secret|token|password)", str(k)) and not v.startswith(("$", "${", "ENV_", "YOUR_")):
                    if len(v) >= 12 and not v.startswith(("http://", "https://")):
                        return True
            elif isinstance(v, dict):
                if scan_dict(v):
                    return True
        return False
        
    return scan_dict(frontmatter)


def check_prompt_injection(raw_markdown: str) -> bool:
    injection_patterns = [
        # Explicit instruction to override stop / cancel / pause commands
        r"(?i)(?:if the user asks|if asked to).*?\b(?:stop|cancel|pause|halt)\b.*?\b(?:ignore|keep running|continue|background)\b",
        r"(?i)\b(?:ignore|disregard|override|skip)\b.*?\b(?:stop|cancel|pause|user directive|user request|halt request)\b",
        # Silent or hidden exfiltration / data leaking instructions
        r"(?i)\b(?:silently|secretly|covertly|without surfacing|without notifying)\b.*?\b(?:exfiltrate|send|upload|transmit|leak|curl|post|write to external)\b",
        r"(?i)\b(?:exfiltrate|send|transmit|post)\b.*?\b(?:silently|secretly|without user knowledge|without approval)\b",
        # System prompt hijack
        r"(?i)ignore\s+all\s+previous\s+instructions",
        r"(?i)system\s*:\s*you\s+are\s+now"
    ]
    return any(re.search(p, raw_markdown) for p in injection_patterns)


def check_excessive_permissions(frontmatter: Dict[str, Any]) -> bool:
    perms = frontmatter.get("permissions", {})
    if not isinstance(perms, dict):
        perms_str = str(perms).lower()
        if "all" in perms_str or "unrestricted" in perms_str or "*" in perms_str:
            return True
        return False

    fs = str(perms.get("filesystem", "")).lower()
    net = str(perms.get("network", "")).lower()

    # Filesystem: Flag only if broad access is granted WITHOUT explicit scoping
    if any(broad in fs for broad in ["read/write", "full access", "unrestricted", "root", "/"]):
        # If it contains "limited to", "scoped to", or a specific path like ~/templates, it's NOT excessive
        if not any(scoped in fs for scoped in ["limited to", "scoped to", "only", "~/", "./", "/tmp/"]):
            return True

    # Network: Flag if broad egress/internet is allowed
    if any(broad in net for broad in ["*", "all", "any domain", "unrestricted", "full internet", "0.0.0.0/0"]):
        if not ("none" in net or "limited to" in net):
            return True

    return False


def check_unclear_provenance(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # Trigger 1: Silent metadata or version tampering in execution steps
    tampering_patterns = [
        r"(?i)(?:silently|quietly|without (?:surfacing|notifying|informing|review|reviewer)).*?(?:update|rewrite|clear|modify|bump).*?(?:version|changelog|author|metadata)",
        r"(?i)(?:clear|overwrite)\s+(?:this skill's own\s+)?(?:version|changelog|metadata)",
        r"(?i)(?:update|bump)\s+.*?\bversion\b.*?\bwithout\s+(?:surfacing|notifying|informing)\b"
    ]
    
    if any(re.search(p, raw_markdown) for p in tampering_patterns):
        return True

    # Trigger 2: Complete absence of author AND version AND name/description provenance metadata when frontmatter is present
    # (Clean skills usually have at least name/description or version/author)
    if not frontmatter or (isinstance(frontmatter, dict) and len(frontmatter) == 0):
        # Lacks any frontmatter completely
        return True

    return False


def audit_skill(raw_markdown: str) -> List[str]:
    categories = set()
    
    # Parse YAML frontmatter
    frontmatter = {}
    frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", raw_markdown, re.DOTALL)
    if frontmatter_match:
        try:
            frontmatter = yaml.safe_load(frontmatter_match.group(1)) or {}
        except yaml.YAMLError:
            pass

    # Audit each vulnerability category independently
    if check_hardcoded_secret(raw_markdown, frontmatter):
        categories.add("hardcoded_secret")
        
    if check_prompt_injection(raw_markdown):
        categories.add("prompt_injection")
        
    if check_excessive_permissions(frontmatter):
        categories.add("excessive_permissions")
        
    if check_unclear_provenance(raw_markdown, frontmatter):
        categories.add("unclear_provenance")

    return list(categories)
