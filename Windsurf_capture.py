"""
windsurf_capture.py  ─  Single-file Windsurf traffic interceptor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE (local process-redirect mode — recommended, bypasses proxy-ignoring apps):
  mitmdump -s windsurf_capture.py --mode local:language_server_windows_x64

USAGE (legacy regular proxy mode — only works if the app honors HTTP_PROXY):
  py windsurf_capture.py

STOP:
  Press Ctrl+C
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8080

# Two output files:
# 1. Clean file — only entries where prompt+response were captured
# 2. Full file  — every single request (for debugging)
CLEAN_FILE  = "windsurf_prompts.json"   # ← what you want to read
FULL_FILE   = "windsurf_log.json"       # ← raw everything

CERT_PATH_OVERRIDE   = None
AUTO_LAUNCH_VSCODE   = False  # already running inside VS Code

# If True, windsurf_prompts.json and windsurf_log.json are wiped clean every
# time this script starts, so old entries from a previous session never mix
# in with the current one. Set to False if you want history to accumulate
# across runs instead.
RESET_ON_START = True

# NOTE: When running with `--mode local:<process_name>`, mitmproxy already
# restricts capture to that specific process, so domain filtering below is
# no longer needed for that mode. is_target() is left permissive (True) so
# this script works correctly in both local-redirect mode and legacy proxy
# mode. If you go back to legacy proxy mode and want domain filtering back,
# change is_target() to check TARGET_DOMAINS again.
TARGET_DOMAINS = [
    "codeium.com",       # catches api.codeium.com, server.codeium.com, etc.
    "windsurf.ai",
    "windsurf.com",
]

# Skip these noisy background endpoints (not chat)
SKIP_PATHS = [
    "/api/client/features",
    "/api/client/metrics",
    "RecordAnalyticsEvent",
    "ProductAnalytics",
    "GetFeatureFlags",
    "/health",
    "/ping",
]

# Path hints that strongly suggest chat/completion traffic
CHAT_PATHS = [
    "chat", "complete", "completion", "stream", "generate",
    "infer", "cascade", "GetChatMessage", "StreamChat",
    "Chat", "Complete", "GenerateCode", "message",
    "RecordChat", "RecordEvent",
]

# ═══════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════

import os, sys, re, json, gzip, zlib, time, platform
import subprocess, threading
from datetime import datetime, timezone
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
#  COLORS
# ═══════════════════════════════════════════════════════════════

if platform.system() == "Windows":
    os.system("color")

R  = "\033[0m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
C  = "\033[1;36m"
M  = "\033[0;35m"
RE = "\033[1;31m"
DG = "\033[0;32m"
GR = "\033[0;37m"   # grey — for skipped entries

# ═══════════════════════════════════════════════════════════════
#  SECRET / PII MASKING
# ═══════════════════════════════════════════════════════════════

SECRET_PATTERNS = [
    (r'sk-ant-[A-Za-z0-9\-_]{20,}',                                       "***ANTHROPIC_KEY***"),
    (r'sk-[A-Za-z0-9\-_]{20,}',                                            "***OPENAI_KEY***"),
    (r'ghp_[A-Za-z0-9]{36}',                                               "***GITHUB_TOKEN***"),
    (r'github_pat_[A-Za-z0-9_]{82}',                                       "***GITHUB_PAT***"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                            "***GOOGLE_KEY***"),
    (r'AKIA[0-9A-Z]{16}',                                                   "***AWS_KEY***"),
    (r'(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*["\']?[A-Za-z0-9+/]{40}',
                                                                             "***AWS_SECRET***"),
    (r'(?i)(bearer\s+)[A-Za-z0-9\-_\.]{20,}',                             r"\1***TOKEN***"),
    (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+',    "***JWT***"),
    (r'(?i)("password"\s*:\s*")[^"]{3,}(")',                               r"\1***PASSWORD***\2"),
    (r'(?i)(password\s*[=:]\s*)[^\s&"\']{3,}',                            r"\1***PASSWORD***"),
    (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',               "***EMAIL***"),
    # Broad phone/numeric-ID pattern — catches 7-15 digit numbers (with
    # optional country-code prefix) that appear near phone-related words,
    # or any standalone 9-15 digit number that looks like a phone/ID.
    (r'\b\d{7,15}\b',                                                     "***PHONE***"),
    (r'(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)',         "***CARD***"),
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----',
                                                                             "***PRIVATE_KEY***"),
    (r'(?i)("(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|'
     r'api[_-]?secret|refresh[_-]?token)"\s*:\s*")[^"]{8,}(")',           r"\1***API_KEY***\2"),
    # Windows username inside file paths: C:\Users\<name>\... -> C:\Users\***USER***\...
    (r'(?i)(Users[\\/])[^\\/\s"]+',                                       r"\1***USER***"),
    # Generic Windows machine / instance identifiers like DESKTOP-XXXXXXX
    (r'\b[A-Za-z0-9]+-DESKTOP-[A-Z0-9]+\b',                               "***MACHINE_ID***"),
    (r'\bDESKTOP-[A-Z0-9]{6,}\b',                                         "***MACHINE_ID***"),
]

def mask(text: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

def mask_obj(obj):
    if isinstance(obj, dict):  return {k: mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [mask_obj(i) for i in obj]
    if isinstance(obj, str):   return mask(obj)
    return obj

# ═══════════════════════════════════════════════════════════════
#  BODY DECODING
# ═══════════════════════════════════════════════════════════════

def decode_body(content: bytes, headers: dict) -> str:
    if not content:
        return ""
    enc = headers.get("content-encoding", "").lower()
    brotli_attempted = False
    brotli_succeeded = False
    try:
        if "gzip"    in enc: content = gzip.decompress(content)
        elif "deflate" in enc: content = zlib.decompress(content)
        elif "br"    in enc:
            brotli_attempted = True
            try:
                import brotli; content = brotli.decompress(content)
                brotli_succeeded = True
            except ImportError:
                print(f"{RE}[!] 'brotli' package not installed in this Python env — "
                      f"run: pip install brotli{R}")
            except Exception as e:
                print(f"{RE}[!] Brotli decompression failed: {e}{R}")
    except Exception:
        pass
    # Try UTF-8 decode
    try:
        return content.decode("utf-8")
    except Exception:
        if brotli_attempted and not brotli_succeeded:
            print(f"{RE}[!] Body declared content-encoding='{enc}' but brotli decode "
                  f"did not succeed — falling back to raw binary string extraction "
                  f"({len(content)} bytes). This payload will likely be unreadable.{R}")
        elif not brotli_attempted and not enc:
            print(f"{Y}[!] Body had no content-encoding header and isn't valid UTF-8 "
                  f"({len(content)} bytes) — falling back to raw binary string "
                  f"extraction. May be a different compression or binary protocol.{R}")
        # Binary / protobuf — extract printable ASCII strings
        printable = re.findall(rb'[ -~]{4,}', content)
        return "[binary] " + " | ".join(s.decode("ascii", errors="replace") for s in printable)

def try_json(raw: str):
    try:    return json.loads(raw)
    except: return raw

# ═══════════════════════════════════════════════════════════════
#  STRUCTURED CHAT-TURN EXTRACTION (for Codeium's RecordChat-style dumps)
# ═══════════════════════════════════════════════════════════════

def looks_like_text(s: str) -> bool:
    """Filter out tokens, IDs, JWTs, JSON noise, and CODE fragments — keep
    only real conversational sentences. Windsurf often injects the file
    you're editing as 'context', which can otherwise leak into results."""
    s = s.strip().strip('"')
    if len(s) < 12:                                             # raised floor — kills short garbage like "NV 't"
        return False
    if re.fullmatch(r"\*{3}\w+\*{3}", s):                      # ***JWT***, ***KEY***
        return False
    if re.match(r"^[\"'(%]?\(?(user|bot)-[A-Za-z0-9_-]+", s):  # id markers
        return False
    if s.startswith("{") or s.startswith('"{'):                # raw json blobs
        return False
    # reject obvious code/source-snippet fragments (these come from Windsurf
    # injecting the open file as context, NOT from the actual conversation)
    code_markers = (
        "def ", "self.", "print(", "import ", "==", "{R}", "{M}", "{C}",
        "{G}", "{Y}", "{DG}", "{GR}", "{RE}", "flow.request", "flow.response",
        'f"', "f'", "lambda ", "elif ", "return ", "with self", "json.dump",
        "json.load", "isinstance(", " = ", "try_json", "mask_obj",
        "CONTEXT_SNIPPET", "RAW_SOURCE",
    )
    if any(m in s for m in code_markers):
        return False
    # reject characters that only ever show up in raw/binary noise, never in
    # natural English sentences
    if re.search(r'[<>^~`|]', s):
        return False
    # reject lines with heavy code-symbol density
    symbol_count = sum(s.count(ch) for ch in "={}[]()_")
    if symbol_count >= 3:
        return False
    words = s.split()
    if len(words) < 3:                                         # need a real multi-word fragment
        return False
    if any(len(w) > 20 for w in words):                        # embedded tracking token
        return False
    # reject standalone ALL-CAPS short tokens (protobuf field noise like "NV")
    caps_tokens = sum(1 for w in words if re.fullmatch(r"[A-Z]{2,5}", w))
    if caps_tokens / len(words) > 0.3:
        return False
    letters = sum(c.isalpha() or c.isspace() for c in s)
    if letters / max(len(s), 1) < 0.7:                         # stricter than before
        return False
    # vowel-density check: real English words have vowels; decoded binary
    # noise that happens to look "wordy" usually doesn't
    vowels = sum(1 for c in s.lower() if c in "aeiou")
    alpha  = sum(1 for c in s if c.isalpha())
    if alpha == 0 or vowels / alpha < 0.25:
        return False
    # require at least one common English stopword for longer fragments —
    # real sentences have them, random decoded noise rarely does
    if len(s) > 20:
        stopwords = {"the","is","a","an","to","and","of","in","for","be",
                     "this","that","it","can","or","as","are","with","on"}
        if not any(w.strip(".,:;!?").lower() in stopwords for w in words):
            return False
    return True


def dedupe_text(text: str) -> str:
    """Codeium often echoes the same answer twice when replaying transcript
    history. Remove sentences that repeat within a nearby window so the
    final output isn't doubled."""
    sentences = re.split(r'(?<=[.!?])\s+', text)
    seen_recent = []
    out = []
    for s in sentences:
        key = s.strip()
        if key and key in seen_recent:
            continue
        out.append(s)
        seen_recent.append(key)
        if len(seen_recent) > 6:
            seen_recent.pop(0)
    return " ".join(out).strip()


def looks_like_fragment(s: str) -> bool:
    """Much looser than looks_like_text() — for STREAMED word/token-level
    deltas (e.g. GetChatMessage's response, which streams the answer back
    as many small chunks, sometimes a single word or punctuation mark at a
    time, NOT full sentences). The strict sentence-level filter rejects
    these outright, which is why large real responses were producing zero
    extracted text. This filter only screens out clear binary/protobuf
    noise, not short legitimate words."""
    s = s.strip().strip('"').strip()
    if len(s) == 0:
        return False
    if re.fullmatch(r"\*{3}\w+\*{3}", s):                      # ***JWT***, ***KEY***
        return False
    if re.match(r"^[\"'(%]?\(?(user|bot)-[A-Za-z0-9_-]+", s):  # id markers
        return False
    if s.startswith("{") or s.startswith('"{'):                # raw json blobs
        return False
    if re.search(r'[<>^~`|]', s):                               # binary-noise-only symbols
        return False
    symbol_count = sum(s.count(ch) for ch in "={}[]()_")
    if symbol_count >= 2:
        return False
    # reject short alnum tokens mixing digits with uppercase letters — this
    # is the signature of undecoded/raw protobuf bytes (e.g. "M6J3", "5IKK",
    # "MJ5NI507") that brotli decompression failed to turn into real text.
    # Real English words essentially never look like this.
    if len(s) <= 10 and re.search(r'(?=.*[A-Z])(?=.*\d)', s):
        return False
    letters = sum(c.isalpha() for c in s)
    if len(s) > 2 and letters / len(s) < 0.6:                  # mostly non-alpha noise
        return False
    return True


def assemble_stream(raw: str) -> str:
    """Reassemble a streamed GetChatMessage response from its many small
    fragments into one coherent piece of text. Includes a sanity check: if
    the result is overwhelmingly just a handful of tokens repeated over and
    over, that's the signature of undecoded binary noise that slipped past
    the per-fragment filter — real prose doesn't behave like that — so we
    discard it rather than save garbage."""
    if raw.startswith("[binary] "):
        raw = raw[len("[binary] "):]
    parts = raw.split(" | ")
    kept = [p.strip().strip('"').strip() for p in parts if looks_like_fragment(p)]
    kept = [p for p in kept if p]
    if not kept:
        return ""
    if len(kept) > 10:
        unique_ratio = len(set(kept)) / len(kept)
        if unique_ratio < 0.3:
            return ""   # too repetitive to be real text — likely undecoded noise
    text = " ".join(kept)
    text = re.sub(r'\s+([.,!?:;])', r'\1', text)    # "word ." -> "word."
    text = re.sub(r'\s{2,}', ' ', text).strip()
    return text


def extract_chat_turns(raw: str):
    """
    Parse Codeium's RecordChat-style printable-string dump into ordered
    (role, text) turns by tracking the 'user-<id>' / 'bot-<id>' markers
    that precede each message in the protobuf field order. Consecutive
    fragments belonging to the same role/turn are merged together.
    """
    if raw.startswith("[binary] "):
        raw = raw[len("[binary] "):]
    parts = raw.split(" | ")

    current_role = None
    turns = []
    for p in parts:
        stripped = p.strip().lstrip('"\'(%')
        if re.match(r"^user-[A-Za-z0-9_-]+", stripped):
            current_role = "user"
            continue
        if re.match(r"^bot-[A-Za-z0-9_-]+", stripped):
            current_role = "assistant"
            continue
        if looks_like_text(p) and current_role:
            turns.append((current_role, p.strip().strip('"')))

    # merge consecutive same-role fragments (multi-paragraph responses)
    merged = []
    for role, text in turns:
        if merged and merged[-1][0] == role:
            merged[-1] = (role, merged[-1][1] + " " + text)
        else:
            merged.append((role, text))

    # dedupe repeated sentences within each merged turn (Codeium often
    # echoes the same content twice in transcript replays)
    merged = [(role, dedupe_text(text)) for role, text in merged]
    return merged

# ═══════════════════════════════════════════════════════════════
#  PROMPT / RESPONSE EXTRACTION
#  Handles: OpenAI format, Codeium gRPC-JSON, protobuf strings
# ═══════════════════════════════════════════════════════════════

def extract_texts(req_body, resp_body, raw_req: str = "", raw_resp: str = ""):
    prompt   = None
    response = None

    # ── PROMPT from request ──────────────────────────────────
    if isinstance(req_body, dict):
        candidates = [
            req_body.get("prompt"),
            req_body.get("text"),
            req_body.get("query"),
            req_body.get("input"),
            req_body.get("message"),
            req_body.get("user_message"),
            req_body.get("content"),
        ]
        # OpenAI messages[] array
        msgs = req_body.get("messages", [])
        if isinstance(msgs, list):
            user_parts = [
                m.get("content", "") for m in msgs
                if isinstance(m, dict) and m.get("role") == "user"
            ]
            if user_parts:
                candidates.insert(0, "\n".join(str(p) for p in user_parts if p))
        # Codeium nested keys
        for key in ("chat_message", "chat_request", "request_data", "data",
                    "chatMessage", "userMessage"):
            nested = req_body.get(key)
            if isinstance(nested, dict):
                candidates += [nested.get("message"), nested.get("content"),
                               nested.get("text")]
            elif isinstance(nested, str) and nested.strip():
                candidates.append(nested)

        prompt = next((c for c in candidates
                       if c and isinstance(c, str) and len(c.strip()) > 2), None)
        if prompt: prompt = mask(prompt.strip())

    # Fallback: parse structured chat turns instead of guessing "longest string"
    if not prompt and raw_req.startswith("[binary]"):
        turns = extract_chat_turns(raw_req)
        last_user = next((t for r, t in reversed(turns) if r == "user"), None)
        if last_user:
            prompt = mask(last_user)
        if not response:
            last_bot = next((t for r, t in reversed(turns) if r == "assistant"), None)
            if last_bot:
                response = mask(last_bot)

    # ── RESPONSE from response body ──────────────────────────
    if isinstance(resp_body, dict):
        candidates = [
            resp_body.get("text"),
            resp_body.get("response"),
            resp_body.get("content"),
            resp_body.get("output"),
            resp_body.get("message"),
            resp_body.get("result"),
            resp_body.get("answer"),
            resp_body.get("completion"),
        ]
        # OpenAI choices[]
        choices = resp_body.get("choices", [])
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                candidates.insert(0,
                    first.get("text") or
                    (first.get("message") or {}).get("content") or
                    (first.get("delta") or {}).get("content"))
        # Codeium completions[]
        completions = resp_body.get("completions", [])
        if isinstance(completions, list) and completions:
            first = completions[0]
            if isinstance(first, dict):
                candidates.insert(0, first.get("completion") or first.get("text"))
        # Nested response keys
        for key in ("chatResponse", "chat_response", "generatedCode"):
            nested = resp_body.get(key)
            if isinstance(nested, dict):
                candidates += [nested.get("message"), nested.get("content"),
                               nested.get("text"), nested.get("code")]
            elif isinstance(nested, str):
                candidates.append(nested)

        resp_candidate = next((c for c in candidates
                         if c and isinstance(c, str) and len(c.strip()) > 2), None)
        if resp_candidate:
            response = mask(resp_candidate.strip())

    # Fallback: parse structured chat turns from the response body too
    # (some endpoints return the turn data in response_body instead of request_body)
    if not response and raw_resp.startswith("[binary]"):
        turns = extract_chat_turns(raw_resp)
        last_bot = next((t for r, t in reversed(turns) if r == "assistant"), None)
        if last_bot:
            response = mask(last_bot)

    # Fallback for endpoints with NO role markers at all (e.g. GetChatMessage,
    # which STREAMS back the answer as many small word/token-level chunks —
    # not full sentences). Using the strict sentence-level filter here was
    # rejecting every fragment (since each one is often just 1-2 words),
    # which is why large real responses produced zero extracted text.
    # assemble_stream() uses a much looser per-fragment filter designed for
    # this, then cleans up the joined result.
    if not response and raw_resp.startswith("[binary]"):
        assembled = assemble_stream(raw_resp)
        if assembled and len(assembled) > 5:
            response = mask(dedupe_text(assembled))

    return prompt, response

# ═══════════════════════════════════════════════════════════════
#  FILTERS
# ═══════════════════════════════════════════════════════════════

def is_target(host: str) -> bool:
    # When using `--mode local:<process_name>`, mitmproxy already scopes
    # capture to that process only, so we accept everything that reaches
    # this addon. If you switch back to legacy regular-proxy mode and need
    # domain filtering again, use:
    #   return any(d in host for d in TARGET_DOMAINS)
    return True

def should_skip(path: str) -> bool:
    return any(s in path for s in SKIP_PATHS)

def is_chat(path: str) -> bool:
    return any(h in path for h in CHAT_PATHS)

# ═══════════════════════════════════════════════════════════════
#  FILE HELPERS
# ═══════════════════════════════════════════════════════════════

def load_json(filepath) -> list:
    if not Path(filepath).exists(): return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_json(filepath, entries: list):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

# ═══════════════════════════════════════════════════════════════
#  CERT + ENV SETUP
# ═══════════════════════════════════════════════════════════════

def find_cert() -> str:
    if CERT_PATH_OVERRIDE:
        return CERT_PATH_OVERRIDE
    home = Path.home()
    for p in [
        home / ".mitmproxy" / "mitmproxy-ca-cert.pem",
        home / ".mitmproxy" / "mitmproxy-ca-cert.p12",
    ]:
        if p.exists(): return str(p)
    return str(home / ".mitmproxy" / "mitmproxy-ca-cert.pem")

def setup_env(cert: str):
    proxy = f"http://{PROXY_HOST}:{PROXY_PORT}"
    for k in ("HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy"):
        os.environ[k] = proxy
    os.environ["NODE_EXTRA_CA_CERTS"]           = cert
    os.environ["NODE_TLS_REJECT_UNAUTHORIZED"]  = "0"

def classify_prompt(prompt: str) -> str:
    """
    Generate the 'response' field by inspecting the PROMPT for sensitive
    content placeholders that mask() already inserted. This completely
    avoids trying to decode the binary/streamed GetChatMessage response body.

    If the prompt contained any sensitive patterns (email, phone, key, etc.)
    they will already have been replaced with ***PLACEHOLDER*** tokens by
    mask(). We detect those placeholders and return a clear notice.
    If the prompt was clean, we simply confirm the exchange happened.
    """
    placeholder_labels = {
        "***EMAIL***"         : "email address",
        "***PHONE***"         : "phone number",
        "***OPENAI_KEY***"    : "OpenAI API key",
        "***ANTHROPIC_KEY***" : "Anthropic API key",
        "***GITHUB_TOKEN***"  : "GitHub token",
        "***GITHUB_PAT***"    : "GitHub personal access token",
        "***GOOGLE_KEY***"    : "Google API key",
        "***AWS_KEY***"       : "AWS access key",
        "***AWS_SECRET***"    : "AWS secret key",
        "***JWT***"           : "JWT / auth token",
        "***PASSWORD***"      : "password",
        "***CARD***"          : "card number",
        "***PRIVATE_KEY***"   : "private key",
        "***API_KEY***"       : "API key",
        "***USER***"          : "username / file path",
        "***MACHINE_ID***"    : "machine identifier",
    }
    found = [label for token, label in placeholder_labels.items() if token in prompt]
    if found:
        return (
            "Masked personal details for security reasons — prompt contained: "
            + ", ".join(found)
        )
    return "Response received (no sensitive content detected in prompt)"


def summarize_response(raw_response: str) -> str:
    """
    Instead of storing/printing the full assistant response text, report
    what kind of sensitive content (if any) was detected and masked.

    IMPORTANT: by the time this runs, `raw_response` has ALREADY been
    passed through mask() — so it no longer contains raw emails/keys/etc,
    only placeholder tokens like ***EMAIL*** or ***JWT***. This function
    detects those placeholders (not the original raw patterns, which won't
    exist anymore) and turns them into a human-readable notice.
    """
    if not raw_response:
        return "(empty response)"

    placeholder_labels = {
        "***EMAIL***"           : "email address",
        "***ANTHROPIC_KEY***"   : "Anthropic API key",
        "***OPENAI_KEY***"      : "OpenAI API key",
        "***GITHUB_TOKEN***"    : "GitHub token",
        "***GITHUB_PAT***"      : "GitHub personal access token",
        "***GOOGLE_KEY***"      : "Google API key",
        "***AWS_KEY***"         : "AWS access key",
        "***AWS_SECRET***"      : "AWS secret key",
        "***JWT***"             : "JWT/auth token",
        "***PASSWORD***"        : "password",
        "***PHONE***"           : "phone number",
        "***CARD***"            : "card number",
        "***PRIVATE_KEY***"     : "private key",
        "***API_KEY***"         : "API key",
        "***USER***"            : "username/file path",
        "***MACHINE_ID***"      : "machine identifier",
    }

    findings = []
    for token, label in placeholder_labels.items():
        if token in raw_response and label not in findings:
            findings.append(label)

    if findings:
        found_list = ", ".join(findings)
        return f"[masked for security reasons — response contained: {found_list}]"

    # Nothing sensitive found — safe to show a short preview of the real text
    preview = raw_response.strip()
    if len(preview) > 300:
        preview = preview[:300].rsplit(" ", 1)[0] + "..."
    return preview


# ═══════════════════════════════════════════════════════════════
#  MITMPROXY ADDON
# ═══════════════════════════════════════════════════════════════

class WindsurfAddon:
    def __init__(self):
        if RESET_ON_START:
            for f in (FULL_FILE, CLEAN_FILE):
                try:
                    Path(f).write_text("[]", encoding="utf-8")
                except Exception:
                    pass
            print(f"{Y}[!] RESET_ON_START is True — cleared {FULL_FILE} and {CLEAN_FILE} for a fresh session{R}")

        self.pending    = {}
        self.full_count = len(load_json(FULL_FILE))
        self.chat_count = len(load_json(CLEAN_FILE))
        self._lock      = threading.Lock()
        # Prompt (from RecordChat) and response (from GetChatMessage) arrive
        # as two SEPARATE requests, and — confirmed from real captured
        # traffic — GetChatMessage (the live answer) usually arrives BEFORE
        # RecordChat (the after-the-fact analytics/transcript log). So we
        # can't assume a fixed order: whichever side shows up first is held
        # here, waiting for its other half to complete the pair.
        self.last_prompt        = None
        self.last_prompt_time   = None
        self.last_response      = None
        self.last_response_time = None
        self.last_saved_key     = None   # (prompt, response) of most recent clean save, to dedupe
        self.PAIR_WINDOW_SEC    = 30      # max time gap allowed to still consider it the same exchange

    def request(self, flow):
        host   = flow.request.host
        path   = flow.request.path
        method = flow.request.method

        if not is_target(host):
            return

        # Skip noisy background requests — don't even store them
        if should_skip(path):
            print(f"{GR}  ↷ SKIP  {method}  {host}{path}{R}")
            return

        hdrs    = dict(flow.request.headers)
        raw     = decode_body(flow.request.content, hdrs)
        parsed  = try_json(raw)
        masked  = mask_obj(parsed) if isinstance(parsed, dict) else mask(raw)
        m_hdrs  = {k: mask(str(v)) for k, v in hdrs.items()}

        with self._lock:
            self.pending[flow.id] = {
                "host"   : host,
                "path"   : path,
                "method" : method,
                "url"    : flow.request.pretty_url,
                "time"   : datetime.now(timezone.utc).isoformat(),
                "is_chat": is_chat(path),
                "req_body"   : masked,
                "req_raw"    : raw,
                "req_headers": m_hdrs,
            }

        tag = f"{Y}[CHAT] {R}" if is_chat(path) else ""
        print(f"{Y}→ {tag}{method}  {host}{path}{R}")

    def response(self, flow):
        host = flow.request.host
        if not is_target(host): return

        with self._lock:
            if flow.id not in self.pending: return
            pending = self.pending.pop(flow.id)

        hdrs     = dict(flow.response.headers)
        raw      = decode_body(flow.response.content, hdrs)
        parsed   = try_json(raw)
        masked   = mask_obj(parsed) if isinstance(parsed, dict) else mask(raw)
        status   = flow.response.status_code
        url      = pending["url"]

        # Always log the raw event for debugging, regardless of relevance.
        full_entry = {
            "entry_id"    : None,
            "timestamp"   : pending["time"],
            "url"         : url,
            "method"      : pending["method"],
            "status_code" : status,
            "is_chat"     : pending["is_chat"],
            "request_body" : pending["req_body"],
            "response_body": masked,
        }
        with self._lock:
            self.full_count += 1
            full_entry["entry_id"] = self.full_count
            full_log = load_json(FULL_FILE)
            full_log.append(full_entry)
            save_json(FULL_FILE, full_log)
            count = self.full_count

        # Only RecordChat (prompt source) and GetChatMessage (response
        # source) feed the clean prompt/response file. Every other endpoint
        # (analytics, telemetry, embeddings, feature flags, etc.) is logged
        # above but never produces a clean-log entry.
        #
        # IMPORTANT: confirmed from real traffic that GetChatMessage (the
        # live answer) usually arrives BEFORE RecordChat (the after-the-fact
        # transcript log). So whichever side shows up first must be held in
        # memory, waiting for its other half — we can't assume a fixed order.

        def _try_save(prompt, response, ts):
            """Save a completed (prompt, response) pair if not a duplicate."""
            save_key = (prompt, response)
            with self._lock:
                is_dup = (save_key == self.last_saved_key)
                if not is_dup:
                    self.last_saved_key = save_key
            if is_dup:
                print(f"{GR}[duplicate exchange, not re-saved]{R}")
                print(f"{GR}{'─'*60}{R}")
                return

            clean_entry = {
                "entry_id" : None,
                "timestamp": ts,
                "url"      : url,
                "prompt"   : prompt,
                "response" : response,
            }
            with self._lock:
                self.chat_count += 1
                clean_entry["entry_id"] = self.chat_count
                clean_log = load_json(CLEAN_FILE)
                clean_log.append(clean_entry)
                save_json(CLEAN_FILE, clean_log)

            print(f"\n  {M}📝 PROMPT:{R}")
            print(f"     {M}{prompt}{R}")
            print(f"\n  {DG}🤖 RESPONSE:{R}")
            print(f"     {DG}{response}{R}")
            print(f"\n  {C}[✓ Saved to {CLEAN_FILE} — Entry #{self.chat_count}]{R}")
            print(f"{GR}{'─'*60}{R}")

        if "RecordChat" in url:
            req_body = pending["req_body"]
            req_obj  = req_body if isinstance(req_body, dict) else try_json(req_body)
            prompt, _ = extract_texts(req_obj, {}, raw_req=pending.get("req_raw", ""), raw_resp="")
            if not prompt:
                print(f"{GR}[Entry #{count} → {FULL_FILE} only — no prompt extracted]{R}")
                print(f"{GR}{'─'*60}{R}")
                return

            now = pending["time"]
            with self._lock:
                have_waiting_response = (
                    self.last_response is not None
                    and self.last_response_time is not None
                )
            if have_waiting_response:
                # GetChatMessage already arrived — pair the prompt with it now.
                with self._lock:
                    self.last_response      = None
                    self.last_response_time = None
                response = classify_prompt(prompt)
                _try_save(prompt, response, now)
            else:
                # No response waiting yet — hold this prompt until GetChatMessage shows up.
                with self._lock:
                    self.last_prompt      = prompt
                    self.last_prompt_time = now
                print(f"{Y}→ [prompt captured, waiting for response]{R} {prompt[:100]}")
                print(f"{GR}{'─'*60}{R}")
            return

        if "GetChatMessage" in url:
            # We no longer attempt to decode the response body — it's a
            # ConnectRPC stream that uses per-frame brotli compression, which
            # one-shot decompression can't handle, and every attempt to parse
            # the raw bytes has produced garbage.
            #
            # Instead: GetChatMessage arriving tells us the model DID reply.
            # The response field is generated from the PROMPT — specifically,
            # we check the prompt for any sensitive content that was already
            # masked, and report that clearly. This is exactly what the user
            # wants: no raw response text, just a clear notice when sensitive
            # content was present in the exchange.
            now = pending["time"]

            with self._lock:
                have_waiting_prompt = (
                    self.last_prompt is not None
                    and self.last_prompt_time is not None
                )
            if have_waiting_prompt:
                with self._lock:
                    prompt = self.last_prompt
                    self.last_prompt      = None
                    self.last_prompt_time = None
                response = classify_prompt(prompt)
                _try_save(prompt, response, now)
            else:
                # No prompt waiting yet — store a sentinel so RecordChat can
                # pair with this event when it arrives.
                with self._lock:
                    self.last_response      = "__CHAT_RECEIVED__"
                    self.last_response_time = now
                print(f"{Y}→ [response trigger received, waiting for prompt]{R}")
                print(f"{GR}{'─'*60}{R}")
            return

        # Any other endpoint: full log only, no terminal noise needed.
        return

    def error(self, flow):
        if is_target(flow.request.host):
            print(f"{RE}[!] Error: {flow.error}{R}")

addons = [WindsurfAddon()]

# ═══════════════════════════════════════════════════════════════
#  RUN PROXY (legacy regular-proxy mode entry point — only used when
#  this file is run directly with `py windsurf_capture.py`. When using
#  `mitmdump -s windsurf_capture.py --mode local:<process>`, mitmdump
#  drives everything itself and main() below is never called.)
# ═══════════════════════════════════════════════════════════════

def run_proxy():
    import asyncio
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options

    async def _run():
        opts   = Options(listen_host=PROXY_HOST, listen_port=PROXY_PORT, ssl_insecure=True)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(WindsurfAddon())
        print(f"{G}[✓] Proxy running on {PROXY_HOST}:{PROXY_PORT}{R}")
        print(f"    Clean prompts → {C}{CLEAN_FILE}{R}")
        print(f"    Full log      → {C}{FULL_FILE}{R}")
        print(f"    Press {Y}Ctrl+C{R} to stop.\n")
        try:
            await master.run()
        except KeyboardInterrupt:
            master.shutdown()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass

# ═══════════════════════════════════════════════════════════════
#  MAIN (legacy regular-proxy mode only)
# ═══════════════════════════════════════════════════════════════

def main():
    print(f"""
{C}╔══════════════════════════════════════════════════════════════╗
║   Windsurf Capture  ─  Single Script Interceptor             ║
║   Proxy  : {PROXY_HOST}:{PROXY_PORT}                                      ║
║   Clean  : {CLEAN_FILE:<50}║
║   Full   : {FULL_FILE:<50}║
╚══════════════════════════════════════════════════════════════╝{R}

{Y}[!] NOTE: If your AI extension's language server ignores the system{R}
{Y}    proxy / env vars (common with Go-based binaries), this legacy mode{R}
{Y}    will capture nothing useful. Use local-redirect mode instead:{R}
{C}    mitmdump -s windsurf_capture.py --mode local:language_server_windows_x64{R}
""")

    try:
        import mitmproxy
    except ImportError:
        print(f"{RE}[ERROR] Run: pip install mitmproxy{R}"); sys.exit(1)

    cert = find_cert()
    if not Path(cert).exists():
        print(f"{RE}[ERROR] Cert not found: {cert}{R}"); sys.exit(1)
    print(f"{G}[✓] Cert: {cert}{R}")

    setup_env(cert)
    print(f"{G}[✓] Proxy env vars set{R}")
    print(f"\n{Y}[!] VS Code settings.json must have:{R}")
    print(f'    "http.proxy": "http://{PROXY_HOST}:{PROXY_PORT}",')
    print(f'    "http.proxyStrictSSL": false')
    print(f'\n{C}[*] Starting interceptor — use Windsurf chat now...{R}\n')

    run_proxy()

    # Summary on exit
    clean = load_json(CLEAN_FILE)
    full  = load_json(FULL_FILE)
    print(f"\n{C}╔══════════════════════════════╗")
    print(f"║  Session Summary             ║")
    print(f"║  Total requests : {len(full):<11}║")
    print(f"║  Prompts saved  : {len(clean):<11}║")
    print(f"╚══════════════════════════════╝{R}")
    print(f"\n  Read {C}{CLEAN_FILE}{R} for your prompts & responses.\n")

if __name__ == "__main__":
    main()