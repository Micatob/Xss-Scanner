import random
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path("scan_results")
RESULTS_DIR.mkdir(exist_ok=True)

VERSION = "3.0.0"

DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 0.3
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.5
MAX_THREADS = 10
MAX_CRAWL_PAGES = 50
COLLAB_PORT = 9999

# WAF evasion: when a payload is blocked, generate up to WAF_MAX_MUTATIONS
# obfuscated variants (case/entity/hex/unicode/base64/whitespace/comment...) and
# retry until one slips through. No WAF fingerprinting required.
WAF_MAX_MUTATIONS = 12
WAF_RETRY_DELAY = 0.15

GROQ_API_KEY = ""
GROQ_MODEL = "mixtral-8x7b-32768"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
ENABLE_AI = False

AI_MAX_REQUESTS = 50
AI_TEMPERATURE = 0.3
AI_MAX_TOKENS = 4000

# CAPTCHA Bypass Configuration
CAPTCHA_API_KEY_2CAPTCHA = ""
CAPTCHA_API_KEY_ANTICAPTCHA = ""
CAPTCHA_API_KEY_AZURE = ""
CAPTCHA_MAX_ATTEMPTS = 5
CAPTCHA_AUTO_SOLVE = True  # Automatically attempt to solve any CAPTCHA
CAPTCHA_SOLVE_TIMEOUT = 120  # Seconds to wait for CAPTCHA solving
CAPTCHA_PYTESSERACT = False  # Set True if pytesseract is installed

# AUTONOMOUS MODE Configuration
AUTONOMOUS_MODE = True  # Default to autonomous (zero interaction)
AUTONOMOUS_STEALTH = True  # Always use stealth by default
AUTONOMOUS_GEO_SPOOF = True  # Always geo-spoof by default
AUTONOMOUS_AUTO_EXPLOIT = True  # Automatically exploit on confirmed findings
AUTONOMOUS_AUTO_POC = True  # Always generate PoC files
AUTONOMOUS_MAX_PAGES = 500  # Maximum pages to crawl
AUTONOMOUS_MAX_RESULTS = 1000  # Maximum results to keep
AUTONOMOUS_MAX_CAPTCHAS = 5  # Max CAPTCHA solve attempts per scan
AUTONOMOUS_HEADLESS_VERIFY = True  # Auto-verify with headless browser
AUTONOMOUS_CHECKPOINT = True  # Enable scan checkpoints for resume

# ADVANCED WAF BYPASS
WAF_AUTO_DETECT = True  # Automatically detect WAF type
WAF_AUTO_EVASION = True  # Automatically enable evasion
WAF_MAX_MUTATIONS = 20  # Increased from 12 for stronger bypass
WAF_RETRY_DELAY = 0.1
WAF_LAYERED_ENCODING = True  # Apply layered encoding combinations
WAF_RANDOMIZED_HEADERS = True  # Randomize headers per request
WAF_PROTOCOL_SPLIT = True  # Split protocols (java\tscript:)
WAF_NULL_BYTE = True  # Null byte injection
WAF_COMMENT_INJECTION = True  # HTML comment injection
WAF_UNICODE_HOMOGLOPHS = True  # Unicode character substitution
WAF_UTF8_OVERLONG = True  # Overlong UTF-8 encoding
WAF_BASE64_WRAPPING = True  # Base64 wrapping for eval(atob())
WAF_STRING_FROM_CHAR_CODE = True  # String.fromCharCode obfuscation
WAF_AUTO_CSP_BYPASS = True  # Automatically find CSP bypasses
WAF_AUTO_FRAMEWORK_PAYLOADS = True  # Auto-generate framework-specific payloads

# RESILIENCE
RESILIENT_MAX_RETRIES = 5
RESILIENT_BACKOFF_FACTOR = 0.5
RESILIENT_CIRCUIT_BREAKER_THRESHOLD = 10
RESILIENT_CIRCUIT_BREAKER_TIMEOUT = 120
RESILIENT_AUTO_THROTTLE = True  # Automatically throttle on errors
RESILIENT_ANTI_FINGERPRINT = True  # Anti-bot fingerprint management
RESILIENT_MEMORY_MANAGEMENT = True  # Auto-trim results
RESILIENT_CHECKPOINT_INTERVAL = 50  # Save checkpoint every N results
RESILIENT_MEMORY_MAX_RESULTS = 1000

# COLLAB
COLLAB_AUTO_START = True  # Always auto-start collab server
COLLAB_AUTO_PORT = 9999  # Auto-find available port if this is taken
COLLAB_MAX_WAIT = 10  # Seconds to wait for blind callbacks

# HEADLESS AUTO
HEADLESS_AUTO_VERIFY = True  # Automatically verify with headless browser
HEADLESS_AUTO_SCREENSHOT = True  # Take screenshots of verified findings

COMMON_PARAMS = [
    "q", "search", "keyword", "id", "name", "email", "msg", "message", "comment",
    "text", "input", "query", "term", "page", "url", "link", "next", "redirect",
    "return", "callback", "data", "file", "dir", "action", "mode", "view", "cat",
    "category", "product", "item", "article", "title", "subject", "body", "content",
    "user", "username", "pass", "password", "token", "session", "lang", "locale",
    "ref", "src", "type", "format", "ajax", "api", "cmd", "command", "exec",
]

COMMON_HEADERS_TO_TEST = ["Referer", "User-Agent", "X-Forwarded-For", "Cookie", "X-Real-IP"]

DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "document.writeln", "eval", "setTimeout", "setInterval", "setImmediate",
    "new Function", "execScript",
]

JQUERY_SINKS = [
    ".html()", ".append()", ".prepend()", ".before()", ".after()",
    ".replaceAll()", ".replaceWith()", ".appendTo()", ".prependTo()",
    ".insertAfter()", ".insertBefore()", ".wrap()", ".wrapAll()",
    ".wrapInner()", ".text()", "$()", "jQuery()",
]

LOCATION_SINKS = [
    "location.href", "location.replace", "location.assign", "location.hash",
    "location.search", "location.pathname", "document.location",
]

POSTMESSAGE_SINKS = ["postMessage", "onmessage", "addEventListener"]

STORAGE_SURFACES = [
    "comment", "post", "review", "feedback", "message", "profile", "bio",
    "about", "signature", "status", "tweet", "reply", "forum", "thread",
    "support", "ticket", "contact", "register", "settings", "config",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

FRAMEWORK_PATTERNS = {
    "React": [r"react\.js", r"react\.min\.js", r"__REACT_DEVTOOLS", r"_reactRootContainer", r"data-reactroot", r"data-reactid"],
    "Angular": [r"angular\.js", r"angular\.min\.js", r"ng-app", r"ng-controller", r"ng-model", r"ng-bind", r"AngularJS"],
    "Vue": [r"vue\.js", r"vue\.min\.js", r"v-bind", r"v-model", r"v-if", r"v-for", r"vue-router", r"vuex"],
    "jQuery": [r"jquery", r"\$\(\.", r"jQuery\(\\."],
    "Svelte": [r"svelte"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Nuxt": [r"_nuxt/", r"__NUXT__"],
    "Gatsby": [r"gatsby"],
}

USER_AGENTS_MOBILE = [
    UA for UA in USER_AGENTS if "iPhone" in UA or "Android" in UA or "iPad" in UA
]
