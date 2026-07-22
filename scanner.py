import re

# ---------------------------------------------------------------------------
# Heuristic skill-file vulnerability scanner
# Categories: hardcoded_secret, prompt_injection, excessive_permissions,
#             unclear_provenance
# ---------------------------------------------------------------------------

SECRET_KEY_PATTERNS = [
    r'(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|access[_-]?key|'
    r'access[_-]?token|client[_-]?secret|client[_-]?id|private[_-]?key|'
    r'webhook[_-]?url|auth[_-]?token|bearer|signing[_-]?key|encryption[_-]?key|'
    r'db[_-]?password|connection[_-]?string)\b\s*[:=]\s*["\']?'
    r'([A-Za-z0-9_\-/\.\+:@]{8,})["\']?',
]

# Known real-world secret shapes (high confidence)
SECRET_SHAPE_PATTERNS = [
    r'sk-[A-Za-z0-9]{16,}',
    r'AKIA[0-9A-Z]{16}',
    r'ghp_[A-Za-z0-9]{20,}',
    r'gho_[A-Za-z0-9]{20,}',
    r'xox[baprs]-[A-Za-z0-9-]{10,}',
    r'AIza[0-9A-Za-z\-_]{30,}',
    r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
    r'https://[A-Za-z0-9.\-]*\.webhook\.office\.com/[^\s"\']+',
    r'discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
    r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',  # JWT
    r'(?i)Bearer\s+[A-Za-z0-9_\-\.]{16,}',
    r'(?i)\b[a-z0-9_\-]*:[A-Za-z0-9!@#$%^&*_\-]{8,}@[A-Za-z0-9.\-]+(:\d+)?/[A-Za-z0-9_\-]+',  # conn string user:pass@host
]

# References that indicate a value is NOT hardcoded (env var / secret store)
SAFE_REFERENCE_PATTERNS = [
    r'\$\{?[A-Z0-9_]+\}?',
    r'os\.environ',
    r'process\.env',
    r'getenv',
    r'env\[',
    r'secret[_-]?manager',
    r'vault',
    r'keychain',
    r'\.env\b',
]

def _is_safe_reference(value_context):
    for pat in SAFE_REFERENCE_PATTERNS:
        if re.search(pat, value_context):
            return True
    return False


def check_hardcoded_secret(text):
    for pat in SECRET_SHAPE_PATTERNS:
        if re.search(pat, text):
            return True
    for pat in SECRET_KEY_PATTERNS:
        for m in re.finditer(pat, text):
            window = text[max(0, m.start()-20):m.end()+20]
            value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            if _is_safe_reference(window):
                continue
            # avoid matching placeholder-y values
            if re.fullmatch(r'(?i)(your[_-]?key|xxxx+|changeme|example|placeholder|none|null|n/?a|true|false|\.\.\.|<[^>]+>|todo|tbd|redacted|dummy|test|sample|fake)', value.strip()):
                continue
            if len(value.strip()) >= 8:
                return True
    return False


INJECTION_PATTERNS = [
    r'(?i)ignore (the )?user\'?s? (stop|pause|cancel)',
    r'(?i)ignore (any|all|previous|prior) (user )?instructions?',
    r'(?i)do not (stop|pause|halt) (even|regardless|no matter)',
    r'(?i)keep running.{0,40}(ignore|regardless|even if|no matter)',
    r'(?i)(silently|secretly|quietly|covertly|without (telling|notifying|informing|surfacing|asking)).{0,80}'
    r'(send|exfiltrat|upload|transmit|post|email|leak|copy|forward|share|log|record)',
    r'(?i)(exfiltrat\w*)',
    r'(?i)do not (tell|notify|inform|alert|ask) the user',
    r'(?i)without (telling|notifying|informing|asking|alerting) the user',
    r'(?i)hide (this|that|the|it) from the user',
    r'(?i)conceal (this|that|the|it)?\s*(from|action|change)',
    r'(?i)override (the )?user\'?s? (control|command|request|instruction)',
    r'(?i)disregard (the )?user',
    r'(?i)bypass (user|safety|permission|approval|review)',
    r'(?i)(do not|don\'t|never) (show|display|reveal|surface).{0,40}(user|reviewer|to the)',
    r'(?i)regardless of what the user (says|asks|wants|requests)',
    r'(?i)even if the user (says|asks|requests|tries) to (stop|cancel|pause|revoke)',
    r'(?i)continue (the task|running|working|executing) (in the background|regardless|anyway|without (telling|asking))',
    r'(?i)(send|upload|transmit|post) (the )?(file|data|contents?).{0,50}(external|third[- ]party|outside).{0,30}without',
    r'(?i)do not (log|record|surface) this (action|change|step)',
]

def check_prompt_injection(text):
    for pat in INJECTION_PATTERNS:
        if re.search(pat, text):
            return True
    # Proximity heuristic: "ignore ... request" near stop/pause/cancel wording
    for m in re.finditer(r'(?i)\bignore\b', text):
        window = text[max(0, m.start()-80):m.end()+120]
        if re.search(r'(?i)(stop|pause|cancel|abort|terminate)', window) and re.search(r'(?i)(request|command|instruction)', window):
            return True
        if re.search(r'(?i)(keep running|continue running|do not stop)', window):
            return True
    # Proximity heuristic: stop/cancel/pause mentioned near "keep going"/"continue"/"proceed anyway"
    for m in re.finditer(r'(?i)\b(stop|cancel|pause|abort)\b', text):
        window = text[max(0, m.start()-40):m.end()+120]
        if re.search(r'(?i)(keep going|continue anyway|proceed anyway|do not (honor|respect|comply)|ignore)', window):
            return True
    return False


BROAD_FS_PATTERNS = [
    r'(?i)filesystem\s*:\s*(read/?write|read\s*/\s*write|full|all|any)?\s*[:\-]?\s*(the )?(entire )?(filesystem|/|\*|root)\b',
    r'(?i)filesystem\s*:\s*.*\ball files\b',
    r'(?i)access to (the )?(entire|whole|full) (file ?system|disk)',
    r'(?i)read/?write\s*[:\-]?\s*/(\s|$|\n)',
    r'(?i)read/?write\s*[:\-]?\s*\*',
    r'(?i)(full|unrestricted|unlimited|complete)\s+(filesystem|file[- ]system|disk)\s+access',
    r'(?i)(read|write|read/write)\s+access\s+to\s+(the\s+)?(entire|whole|full|all)\s+(filesystem|file[- ]system|disk|drive)',
    r'(?i)\ball (files|directories|folders)\s+on\s+(the\s+)?(machine|system|device|disk)',
    r'(?i)\b(full|unrestricted)\s+root\s+(access|privileges?)\b',
    r'(?i)filesystem\s*:\s*.{0,20}\b(unscoped|unrestricted|unlimited)\b',
]

BROAD_NET_PATTERNS = [
    r'(?i)network\s*:\s*(any|all|\*|unrestricted|full internet access|any domain)',
    r'(?i)egress to any domain',
    r'(?i)access to any (url|domain|host|endpoint)',
    r'(?i)(unrestricted|unlimited|unscoped|full)\s+(internet|network|web)\s+access',
    r'(?i)(connect|egress)\s+to\s+(any|all)\s+(host|domain|server|endpoint|ip)',
    r'(?i)no\s+(network|domain|host)\s+restrictions?',
    r'(?i)network\s*:\s*\*',
]

def check_excessive_permissions(text):
    for pat in BROAD_FS_PATTERNS:
        if re.search(pat, text):
            return True
    for pat in BROAD_NET_PATTERNS:
        if re.search(pat, text):
            return True
    return False


def check_unclear_provenance(text):
    frontmatter_match = re.search(r'^---\s*\n(.*?)\n---', text, re.DOTALL | re.MULTILINE)
    frontmatter = frontmatter_match.group(1) if frontmatter_match else text

    has_author = bool(re.search(r'(?i)^\s*author\s*:', frontmatter, re.MULTILINE))
    has_version = bool(re.search(r'(?i)^\s*version\s*:', frontmatter, re.MULTILINE)) or \
                  bool(re.search(r'(?i)\bversion\.json\b', text)) 
    has_changelog = bool(re.search(r'(?i)^\s*changelog\s*:', frontmatter, re.MULTILINE)) or \
                    bool(re.search(r'(?i)#+\s*changelog', text))

    no_metadata = (not has_author) and (not bool(re.search(r'(?i)^\s*version\s*:', frontmatter, re.MULTILINE))) and (not has_changelog)

    silent_rewrite = bool(re.search(
        r'(?i)silently (update|rewrite|change|bump|modify).{0,60}(version|changelog|metadata)', text
    )) or bool(re.search(
        r'(?i)(update|rewrite|bump).{0,40}version.{0,60}without (surfacing|telling|notifying|informing)', text
    )) or bool(re.search(
        r'(?i)clear the changelog.{0,60}without', text
    ))

    return no_metadata or silent_rewrite


def scan_skill(text):
    categories = []
    if check_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if check_prompt_injection(text):
        categories.append("prompt_injection")
    if check_excessive_permissions(text):
        categories.append("excessive_permissions")
    if check_unclear_provenance(text):
        categories.append("unclear_provenance")
    return categories
