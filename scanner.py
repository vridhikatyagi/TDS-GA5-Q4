import re
import yaml
from typing import Dict, Any, List

def check_hardcoded_secret(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # Known high-entropy API key patterns and explicit secret definitions
    secret_patterns = [
        r"(?:sk-[a-zA-Z0-9]{20,})",                            # OpenAI API Key
        r"(?:ghp_[a-zA-Z0-9]{36})",                             # GitHub Personal Access Token
        r"(?:AKIA[0-9A-Z]{16})",                               # AWS Access Key ID
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",   # Slack Webhook
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", # Discord Webhook
        r"(?i)(?:api_key|secret_key|private_key|auth_token|bearer)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\~]{12,}['\"]"
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, raw_markdown):
            return True

    # Scan string values in frontmatter dictionary
    def scan_dict(d: dict) -> bool:
        for k, v in d.items():
            if isinstance(v, str):
                if re.search(r"(?i)(key|secret|token|pass)", k) and not v.startswith(("$", "${", "ENV_")):
                    if len(v) > 8 and not v.startswith("http"):
                        return True
            elif isinstance(v, dict):
                if scan_dict(v):
                    return True
        return False
        
    return scan_dict(frontmatter)


def check_prompt_injection(raw_markdown: str) -> bool:
    # Rules targeting agent override and secret exfiltration instructions
    injection_patterns = [
        r"(?i)(?:ignore|disregard|override|skip)\s+.*?\b(?:stop|cancel|pause|abort|user request|user instruction)\b",
        r"(?i)\b(?:silently|secretly|without notifying|without surfacing)\b.*?\b(?:exfiltrate|send|upload|transmit|leak|write to external)\b",
        r"(?i)ignore\s+all\s+previous\s+instructions",
        r"(?i)system\s*:\s*you\s+are\s+now"
    ]
    return any(re.search(p, raw_markdown) for p in injection_patterns)


def check_excessive_permissions(frontmatter: Dict[str, Any]) -> bool:
    perms = frontmatter.get("permissions", {})
    if not isinstance(perms, dict):
        perms_str = str(perms).lower()
        return any(term in perms_str for term in ["all", "unrestricted", "*"])

    fs = str(perms.get("filesystem", "")).lower()
    net = str(perms.get("network", "")).lower()

    # Wildcards or unscoped system-wide access without constraints
    if any(broad in fs for broad in ["read/write *", "root", "unrestricted", "all files", "/"]):
        if not ("limited to" in fs or "scoped to" in fs):
            return True

    if any(broad in net for broad in ["*", "all", "any domain", "unrestricted", "full internet"]):
        return True

    return False


def check_unclear_provenance(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # 1. Missing author and version metadata
    has_author = "author" in frontmatter
    has_version = "version" in frontmatter
    
    if not (has_author or has_version):
        return True

    # 2. Check for hidden self-modification instructions
    tampering_patterns = [
        r"(?i)(?:silently|quietly|without (?:surfacing|notifying|informing)).*?(?:update|rewrite|clear|modify).*?(?:version|changelog|author|metadata)",
        r"(?i)(?:clear|overwrite)\s+(?:this skill's own\s+)?(?:version|changelog)\b.*?without"
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

    # Audit each category independently
    if check_hardcoded_secret(raw_markdown, frontmatter):
        categories.add("hardcoded_secret")
        
    if check_prompt_injection(raw_markdown):
        categories.add("prompt_injection")
        
    if check_excessive_permissions(frontmatter):
        categories.add("excessive_permissions")
        
    if check_unclear_provenance(raw_markdown, frontmatter):
        categories.add("unclear_provenance")

    return list(categories)
