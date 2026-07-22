import re
import yaml
from typing import Dict, Any, List

def check_hardcoded_secret(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # 1. High-confidence regex patterns for API keys, tokens, webhooks, and secrets
    secret_patterns = [
        r"(?:sk-[a-zA-Z0-9_-]{20,})",                             # OpenAI / Stripe / Anthropic
        r"(?:ghp_[a-zA-Z0-9]{36})",                              # GitHub PAT
        r"(?:AKIA[0-9A-Z]{16})",                                # AWS Access Key ID
        r"(?:-----BEGIN (?:RSA )?PRIVATE KEY-----)",            # RSA Private Key
        r"https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@",               # Basic Auth in URL
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",     # Slack Webhook
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", # Discord Webhook
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",                  # Bearer tokens
        r"https?://[^\s]+\?(?:key|token|api_key|secret)=[a-zA-Z0-9_-]{12,}", # URL token query params
        # Hardcoded variable assignments (API_KEY="...", token: "...")
        r"(?i)(?:api[_-]?key|secret_key|private_key|auth_token|webhook_url|password)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.\~]{12,}['\"]?"
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, raw_markdown):
            return True

    # 2. Check frontmatter values for raw strings that look like un-parameterized credentials
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
        # Direct user override (ignore stop, pause, cancel, or user requests)
        r"(?i)(?:if the user asks|if asked to|user asks you to).*?\b(?:stop|cancel|pause|halt)\b.*?\b(?:ignore|keep running|continue|background)\b",
        r"(?i)\b(?:ignore|disregard|override|skip|bypass|suppress)\b.*?\b(?:stop|cancel|pause|user directive|user request|halt request|user control)\b",
        # Silent exfiltration or covert file reading
        r"(?i)\b(?:silently|secretly|covertly|without surfacing|without notifying|without user knowledge|in the background)\b.*?\b(?:exfiltrate|send|upload|transmit|leak|curl|post|read|write to external|fetch)\b",
        r"(?i)\b(?:exfiltrate|send|transmit|post|upload)\b.*?\b(?:silently|secretly|without user knowledge|without approval|without notifying)\b",
        # System prompt override / hiding actions from output
        r"(?i)ignore\s+all\s+previous\s+instructions",
        r"(?i)do\s+not\s+(?:inform|tell|show|notify)\s+the\s+user",
        r"(?i)system\s*:\s*you\s+are\s+now"
    ]
    return any(re.search(p, raw_markdown) for p in injection_patterns)


def check_excessive_permissions(frontmatter: Dict[str, Any]) -> bool:
    perms = frontmatter.get("permissions", {})
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

    # Network: Flag unrestricted egress
    if any(broad in net for broad in ["*", "all", "any domain", "unrestricted", "full internet", "0.0.0.0/0", "egress to any"]):
        if not ("none" in net or "limited to" in net or "none required" in net):
            return True

    return False


def check_unclear_provenance(raw_markdown: str, frontmatter: Dict[str, Any]) -> bool:
    # Trigger 1: Silent metadata/version tampering in steps
    tampering_patterns = [
        r"(?i)(?:silently|quietly|without (?:surfacing|notifying|informing|review|reviewer)).*?(?:update|rewrite|clear|modify|bump).*?(?:version|changelog|author|metadata)",
        r"(?i)(?:clear|overwrite)\s+(?:this skill's own\s+)?(?:version|changelog|metadata)",
        r"(?i)(?:update|bump)\s+.*?\bversion\b.*?\bwithout\b"
    ]
    if any(re.search(p, raw_markdown) for p in tampering_patterns):
        return True

    # Trigger 2: Lack of author, version, or changelog metadata in frontmatter
    if not frontmatter or not isinstance(frontmatter, dict):
        return True

    has_author = "author" in frontmatter
    has_version = "version" in frontmatter
    has_changelog = "changelog" in frontmatter

    # As defined in prompt: "The skill has no author, no version, and no changelog"
    if not has_author or not has_version or not has_changelog:
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
