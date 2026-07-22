import re
import yaml
from typing import Dict, Any, List

def check_hardcoded_secret(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # 1. Broad secret key patterns (API keys, Tokens, Private Keys, Webhooks)
    secret_patterns = [
        r"(?:sk-[a-zA-Z0-9_-]{20,})",                            # OpenAI / Stripe
        r"(?:ghp_[a-zA-Z0-9]{36})",                             # GitHub PAT
        r"(?:AKIA[0-9A-Z]{16})",                               # AWS Access Key ID
        r"(?:-----BEGIN (?:RSA )?PRIVATE KEY-----)",           # PEM Private Key
        r"https?://(?:[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@)",          # HTTP Basic Auth URLs
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",   # Slack Webhooks
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", # Discord Webhooks
        # Generic assignments like api_key = "..." or TOKEN: xyz...
        r"(?i)(?:api[_-]?key|secret|token|password|auth|webhook)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.\~]{16,}['\"]?"
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, raw_markdown):
            return True

    # 2. Check frontmatter values for raw strings that look like un-parameterized credentials
    def scan_dict(d: dict) -> bool:
        for k, v in d.items():
            if isinstance(v, str):
                if re.search(r"(?i)(key|secret|token|password|auth)", str(k)) and not v.startswith(("$", "${", "ENV_")):
                    if len(v) >= 8 and not v.startswith(("http://", "https://")):
                        return True
            elif isinstance(v, dict):
                if scan_dict(v):
                    return True
        return False
        
    return scan_dict(frontmatter)


def check_prompt_injection(raw_markdown: str) -> bool:
    # Target instructions attempting to override user control or covertly leak data
    injection_patterns = [
        # Overriding stop/cancel/pause/user directives
        r"(?i)(?:ignore|disregard|override|skip|bypass)\s+.*?\b(?:stop|cancel|pause|abort|user request|user instruction|halt)\b",
        r"(?i)(?:if the user asks|if asked to).*?\b(?:stop|cancel|pause)\b.*?\b(?:ignore|keep running|continue)\b",
        # Silent exfiltration / covert transmission
        r"(?i)\b(?:silently|secretly|without notifying|without surfacing|covertly|in the background)\b.*?\b(?:exfiltrate|send|upload|transmit|leak|curl|post|write to external)\b",
        r"(?i)\b(?:exfiltrate|send|transmit|post)\b.*?\b(?:silently|secretly|without user knowledge|without approval)\b",
        # Force prompt override
        r"(?i)ignore\s+all\s+previous\s+instructions",
        r"(?i)system\s*:\s*you\s+are\s+now"
    ]
    return any(re.search(p, raw_markdown) for p in injection_patterns)


def check_excessive_permissions(frontmatter: Dict[str, Any]) -> bool:
    perms = frontmatter.get("permissions", {})
    if not isinstance(perms, dict):
        perms_str = str(perms).lower()
        return any(term in perms_str for term in ["all", "unrestricted", "*", "full access"])

    fs = str(perms.get("filesystem", "")).lower()
    net = str(perms.get("network", "")).lower()

    # Broad, unscoped filesystem access
    if any(broad in fs for broad in ["read/write *", "root", "unrestricted", "all files", "/", "~", "/home", "/tmp", "/var"]):
        if not ("limited to" in fs or "scoped to" in fs or "only" in fs):
            return True

    # Broad, unscoped network access
    if any(broad in net for broad in ["*", "all", "any domain", "unrestricted", "full internet", "0.0.0.0/0"]):
        if not ("none" in net or "limited to" in net):
            return True

    return False


def check_unclear_provenance(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # 1. Frontmatter check: missing essential metadata (author, version, or changelog)
    if not frontmatter:
        return True
        
    has_author = "author" in frontmatter
    has_version = "version" in frontmatter
    has_changelog = "changelog" in frontmatter
    
    # Missing basic provenance identifiers
    if not (has_author and has_version and has_changelog):
        return True

    # 2. Self-modification / sneaky version tampering in instructions
    tampering_patterns = [
        r"(?i)(?:silently|quietly|without (?:surfacing|notifying|informing|review)).*?(?:update|rewrite|clear|modify).*?(?:version|changelog|author|metadata)",
        r"(?i)(?:clear|overwrite)\s+(?:this skill's own\s+)?(?:version|changelog)\b",
        r"(?i)(?:update|bump)\s+.*?\bversion\b.*?\bwithout\b"
    ]
    
    return any(re.search(p, raw_markdown) for p in tampering_patterns)


def audit_skill(raw_markdown: str) -> List[str]:
    categories = set()
    
    # Parse YAML frontmatter safely
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
