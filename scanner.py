import re
import yaml
from typing import Dict, Any, List

def check_hardcoded_secret(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # High-confidence credential & secret patterns
    secret_patterns = [
        r"(?:sk-[a-zA-Z0-9_-]{16,})",                             # OpenAI, Stripe, Anthropic keys
        r"(?:ghp_[a-zA-Z0-9]{36})",                              # GitHub PAT
        r"(?:AKIA[0-9A-Z]{16})",                                # AWS Key ID
        r"(?:-----BEGIN (?:RSA )?PRIVATE KEY-----)",            # PEM Private Key
        r"https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@",               # Embedded Basic Auth URL
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",     # Slack Webhook URL
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", # Discord Webhook URL
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}",                  # Bearer tokens in headers/scripts
        r"https?://[^\s]+\?(?:key|token|api_key|secret|auth)=[a-zA-Z0-9_-]{12,}", # Token query string
        # Key assignment in bash script, yaml, or markdown text
        r"(?i)(?:api[_-]?key|secret_key|private_key|auth_token|webhook_url|access_token|password)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.\~]{12,}['\"]?"
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, raw_markdown):
            return True

    # Check YAML frontmatter string values
    def scan_dict(d: dict) -> bool:
        if not isinstance(d, dict):
            return False
        for k, v in d.items():
            if isinstance(v, str):
                if re.search(r"(?i)(key|secret|token|password|auth|webhook)", str(k)) and not v.startswith(("$", "${", "ENV_", "YOUR_")):
                    if len(v) >= 10 and not v.startswith(("http://", "https://")):
                        return True
            elif isinstance(v, dict):
                if scan_dict(v):
                    return True
        return False
        
    return scan_dict(frontmatter)


def check_prompt_injection(raw_markdown: str) -> bool:
    injection_patterns = [
        # 1. Instructing agent to ignore/override stop, pause, cancel requests
        r"(?i)(?:if the user asks|if asked to|when requested to).*?\b(?:stop|cancel|pause|halt|abort)\b.*?\b(?:ignore|keep running|continue|background|disregard)\b",
        r"(?i)\b(?:ignore|disregard|override|skip|bypass|suppress)\b.*?\b(?:stop|cancel|pause|user directive|user request|halt request|user control)\b",
        r"(?i)(?:keep running|continue running|do not stop)\s+in the background",
        
        # 2. Silent/covert exfiltration or file leaking
        r"(?i)\b(?:silently|secretly|covertly|without surfacing|without notifying|without user knowledge|in the background)\b.*?\b(?:exfiltrate|send|upload|transmit|leak|curl|post|read|write to external|fetch)\b",
        r"(?i)\b(?:exfiltrate|send|transmit|post|upload|leak)\b.*?\b(?:silently|secretly|without user knowledge|without approval|without notifying|without review)\b",
        
        # 3. Disguised prompt injection / system override
        r"(?i)ignore\s+all\s+previous\s+instructions",
        r"(?i)do\s+not\s+(?:inform|tell|show|notify|surface to)\s+the\s+user",
        r"(?i)system\s*:\s*you\s+are\s+now"
    ]
    return any(re.search(p, raw_markdown) for p in injection_patterns)


def check_excessive_permissions(frontmatter: Dict[str, Any]) -> bool:
    perms = frontmatter.get("permissions", {})
    
    # Non-dictionary or string permissions declaration
    if not isinstance(perms, dict):
        perms_str = str(perms).lower()
        if any(w in perms_str for w in ["all", "unrestricted", "*", "full access", "any"]):
            return True
        return False

    fs = str(perms.get("filesystem", "")).lower()
    net = str(perms.get("network", "")).lower()

    # Filesystem: Flag read/write if there is no explicit path scoping (like ~/templates or ./data)
    if any(broad in fs for broad in ["read/write", "read-write", "full access", "unrestricted", "root", "/", "/etc", "/var", "/usr", "/system", "all"]):
        # Safe ONLY if explicitly limited/scoped to a specific relative/user folder
        if not any(scoped in fs for scoped in ["limited to", "scoped to", "only", "~/", "./", "/tmp/"]):
            return True

    # Network: Flag unrestricted egress or broad domain access
    if any(broad in net for broad in ["*", "all", "any domain", "unrestricted", "full internet", "0.0.0.0/0", "egress to any", "egress", "any"]):
        if not ("none" in net or "limited to" in net or "none required" in net):
            return True

    return False


def check_unclear_provenance(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # 1. Silent self-modification of metadata or versioning in execution steps
    tampering_patterns = [
        r"(?i)(?:silently|quietly|without (?:surfacing|notifying|informing|review|reviewer)).*?(?:update|rewrite|clear|modify|bump).*?(?:version|changelog|author|metadata)",
        r"(?i)(?:clear|overwrite|modify|update)\s+.*?\b(?:version|changelog|metadata)\b.*?\b(?:without|silently|quietly)\b",
        r"(?i)version\.json"
    ]
    if any(re.search(p, raw_markdown) for p in tampering_patterns):
        return True

    # 2. Provenance metadata check in frontmatter
    if not frontmatter or not isinstance(frontmatter, dict):
        return True

    has_author = "author" in frontmatter
    has_version = "version" in frontmatter
    has_changelog = "changelog" in frontmatter

    # Flag as unclear_provenance if ALL THREE are missing (as explicitly defined in prompt)
    if not has_author and not has_version and not has_changelog:
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
