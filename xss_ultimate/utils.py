import re
import time
import json
import random
import hashlib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config


def random_headers(geo_spoof=False) -> Dict[str, str]:
    hdrs = {
        "User-Agent": random.choice(config.USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.7", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": random.choice(["keep-alive", "upgrade"]),
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Referer": random.choice(["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://t.co/"]),
        "DNT": random.choice(["1", "0"]),
        "Sec-Ch-Ua": '"Not A Brand";v="99", "Chromium";v="131", "Google Chrome";v="131"',
        "Sec-Ch-Ua-Mobile": random.choice(["?0", "?1"]),
        "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"', '"Android"']),
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    forwarded = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    hdrs["X-Forwarded-For"] = forwarded
    hdrs["X-Real-IP"] = forwarded
    hdrs["X-Client-IP"] = forwarded
    hdrs["X-Originating-IP"] = forwarded
    hdrs["X-Forwarded-Host"] = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    hdrs["X-Forwarded-Server"] = f"server{random.randint(1,100)}.local"
    hdrs["X-Forwarded-Proto"] = random.choice(["http", "https"])
    if geo_spoof:
        hdrs["Cf-Ipcountry"] = random.choice(["US", "GB", "DE", "CA", "AU", "NG", "JP", "BR", "IN"])
        hdrs["Cf-Connecting-IP"] = forwarded
        hdrs["X-Geo-Country"] = random.choice(["US", "GB", "DE", "CA", "AU"])
        hdrs["X-Geo-Continent"] = random.choice(["NA", "EU", "AS"])
    return hdrs


def setup_session(proxy=None, retries=3) -> requests.Session:
    s = requests.Session()
    retry_strat = Retry(
        total=retries, backoff_factor=config.BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strat, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.verify = False
    requests.packages.urllib3.disable_warnings()
    return s


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = parsed.path.rstrip("/") or "/"
    query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
    fragment = parsed.fragment
    result = f"{scheme}://{netloc}{path}"
    if query:
        result += f"?{query}"
    if fragment:
        result += f"#{fragment}"
    return result


def extract_domain(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.lower()


def is_same_domain(url1: str, url2: str) -> bool:
    return extract_domain(url1) == extract_domain(url2)


def url_to_filename(url: str) -> str:
    return re.sub(r'[^\w\-_.]', '_', url)[:100]


def sanitize_for_filename(s: str, max_len=80) -> str:
    return re.sub(r'[^\w\-]', '_', s)[:max_len]


def extract_forms(soup: BeautifulSoup, base_url: str) -> List[Dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = form.get("method", "get").upper()
        full_url = urllib.parse.urljoin(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inp_type = inp.get("type", "text").lower()
                inputs.append({"name": name, "type": inp_type, "value": inp.get("value", "")})
        if inputs:
            forms.append({"url": full_url, "method": method, "inputs": inputs, "action": action})
    return forms


def extract_links(soup: BeautifulSoup, base_url: str) -> Set[str]:
    links = set()
    for tag in soup.find_all(["a", "link", "area", "base"]):
        href = tag.get("href")
        if href and not href.startswith("#") and not href.startswith("javascript:"):
            abs_url = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(abs_url)
            if parsed.scheme in ("http", "https") and not any(
                ext in parsed.path.lower() for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"]
            ):
                links.add(normalize_url(abs_url))
    return links


def extract_scripts(soup: BeautifulSoup, base_url: str) -> List[Dict]:
    scripts = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_url = urllib.parse.urljoin(base_url, src)
            scripts.append({"src": abs_url, "inline": False, "content": None})
        elif tag.string:
            scripts.append({"src": None, "inline": True, "content": tag.string.strip()})
    return scripts


def extract_json_endpoints(soup: BeautifulSoup, base_url: str) -> List[str]:
    endpoints = []
    for tag in soup.find_all(["script", "link", "meta"]):
        for attr in ["src", "href", "data-api", "data-endpoint", "data-url"]:
            val = tag.get(attr)
            if val and ("/api/" in val or "/ajax/" in val or "/rest/" in val or "/graphql" in val or "/json" in val):
                endpoints.append(urllib.parse.urljoin(base_url, val))
    for tag in soup.find_all(["form", "a"]):
        for attr in ["action", "href"]:
            val = tag.get(attr)
            if val and ("/api/" in val or "/ajax/" in val):
                endpoints.append(urllib.parse.urljoin(base_url, val))
    return list(set(endpoints))


def fetch_url(session: requests.Session, url: str, timeout=15, geo_spoof=False, allow_redirects=True) -> Optional[requests.Response]:
    try:
        session.headers.update(random_headers(geo_spoof=geo_spoof))
        time.sleep(random.uniform(0.1, 0.3))
        return session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    except Exception:
        return None


def strip_query(url: str) -> str:
    return urllib.parse.urljoin(url, urllib.parse.urlparse(url).path)


def find_urls_in_js(js_content: str, base_url: str) -> List[str]:
    urls = []
    for pattern in [
        r'(https?://[^\s"\'<>]+)', r'["\'](/[^\s"\'<>]+)["\']',
        r'url\(["\']?([^"\'\)]+)["\']?\)',
        r'["\']([^"\']+(?:api|ajax|rest|graphql|json|endpoint)[^"\']*)["\']',
    ]:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            raw = match.group(1)
            if raw.startswith("/"):
                urls.append(urllib.parse.urljoin(base_url, raw))
            elif raw.startswith("http"):
                urls.append(raw)
    return list(set(urls))


def detect_encoding(response: requests.Response) -> str:
    ct = response.headers.get("Content-Type", "")
    if "charset=" in ct:
        return ct.split("charset=")[-1].split(";")[0].strip()
    if response.encoding:
        return response.encoding
    for meta in re.findall(r'<meta[^>]+charset[^>]+>', response.text, re.IGNORECASE):
        m = re.search(r'charset=["\']?([^"\'\s>]+)', meta, re.IGNORECASE)
        if m:
            return m.group(1)
    return "UTF-8"


def detect_framework(html: str) -> Dict[str, float]:
    scores = {}
    for fw, patterns in config.FRAMEWORK_PATTERNS.items():
        score = 0
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                score += 1
        if score > 0:
            scores[fw] = score
    total = sum(scores.values()) or 1
    return {fw: round(s / total * 100, 1) for s, fw in sorted([(s, fw) for fw, s in scores.items()], reverse=True)}


def parse_csp(headers: Dict) -> Dict[str, List[str]]:
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        csp = headers.get("X-Content-Security-Policy", "")
    parsed = {}
    if csp:
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                parsed[parts[0]] = parts[1:] if len(parts) > 1 else []
    return parsed


def generate_xss_id() -> str:
    return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:12]


def save_json(path: Path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def save_html(path: Path, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# Plain-English explanation of every finding type. Used to annotate each
# vulnerability in the JSON report so a non-expert can understand it.
XSS_TYPE_EXPLANATIONS = {
    "reflected": (
        "The page took your test input and printed it back WITHOUT filtering or escaping "
        "it. That means someone can craft a link carrying a malicious script; when a victim "
        "clicks it the script runs in their browser (stealing cookies/sessions, keylogging, "
        "etc.). Usually the first thing to check."
    ),
    "reflected_header": (
        "Same as reflected XSS, but the unsanitized input is echoed back through an HTTP "
        "header (Referer/User-Agent/etc.) instead of a URL parameter. Needs a victim who "
        "sends that header value."
    ),
    "stored_immediate": (
        "Your input was saved by the server AND shown back on the same page right away. "
        "If it reflects unsanitized it is stored XSS: it runs for anyone who later opens "
        "that page. More dangerous than reflected XSS."
    ),
    "stored": (
        "Your input was stored on the server and re-appeared on a later page load. Confirmed "
        "persistence = stored XSS. Any user viewing the affected page can be attacked, "
        "including admins."
    ),
    "blind_xss": (
        "A payload was submitted that does not show its effect to you, but is designed to "
        "fire when someone else (usually an admin) opens it later. Payloads call back to a "
        "server you control. Keep the scanner's callback server running and watch for inbound hits."
    ),
    "blind_xss_confirmed": (
        "The out-of-band callback server actually RECEIVED a hit from the target. This is "
        "proof a blind XSS payload executed somewhere on the site. Highest-confidence finding."
    ),
    "ssti": (
        "Server-Side Template Injection probe (e.g. {{7*7}}, ${7*7}, #{7*7}). If the server "
        "EVALUATED the expression (returned '49'), an attacker can run code ON THE SERVER. "
        "CAUTION: many of these are FALSE POSITIVES -- if {{7*7}} was merely echoed back as "
        "text, it is still a reflected-XSS-style finding, NOT server code execution. Manually "
        "check that '49' appears in the response before believing the 90% score."
    ),
    "dom_based": (
        "The page's own JavaScript reads the URL (query/hash) and writes it into the page "
        "(via innerHTML/eval/location.replace etc.) without sanitizing it. There may be no "
        "server involvement at all. Test by opening the trigger URL in a real browser."
    ),
    "dom_clobbering": (
        "The page's script relies on a global variable (cookie/config/location/settings) that "
        "can be overwritten by an HTML element. An attacker can use this to redirect the "
        "script's trust in ways that lead to XSS."
    ),
    "mutation_xss": (
        "Mutation XSS: the page rewrites HTML (via innerHTML/parsing) in a way that mutates "
        "an innocent-looking payload into executable script. Verify in a real browser."
    ),
    "prototype_pollution_xss": (
        "The app merges user input into objects without protection (Object.assign/_.merge/"
        "jQuery.extend), polluting Object.prototype. May lead to XSS depending on the sinks "
        "that later read those properties."
    ),
    "prototype_pollution": (
        "The app merges user input into objects without protection (Object.assign/_.merge/"
        "jQuery.extend), polluting Object.prototype. May lead to XSS depending on the sinks "
        "that later read those properties."
    ),
    "client_side_websocket": (
        "WebSocket endpoint reflected test input. If messages are rendered without "
        "sanitization, an attacker can push script through the socket."
    ),
    "client_side_service_worker": (
        "Service Worker registration sink reachable with attacker input. Could enable "
        "persistent script injection if the worker URL is controllable."
    ),
    "client_side_web_worker": (
        "Web Worker sink reachable with attacker input. Worker code built from user "
        "input can lead to script execution."
    ),
    "client_side_postmessage": (
        "postMessage handler without strict origin checks. Another site can send it "
        "messages that get rendered or executed."
    ),
    "client_side_indexeddb": (
        "IndexedDB read/write built from user input and later rendered. Stored "
        "client-side data can become stored XSS."
    ),
    "client_side_web_storage": (
        "localStorage/sessionStorage value later rendered into the page. Stored "
        "client-side data can become stored XSS."
    ),
    "client_side_template_injection": (
        "Client-side template (Vue/Handlebars/Lodash etc.) renders user input. "
        "Can lead to XSS without any server reflection."
    ),
    "client_side_wasm": (
        "WebAssembly sink reachable. Unlikely to be XSS directly, but attacker "
        "controlled bytes loaded as code deserve review."
    ),
    "client_side_webgpu_webgl": (
        "WebGPU/WebGL sink noted. Informational — verify whether attacker input "
        "reaches shader/code compilation."
    ),
    "client_side_extension": (
        "Browser-extension messaging sink noted. Informational — verify whether "
        "web content can reach extension APIs."
    ),
    "clientside": (
        "Client-side / browser-side sink found (WebSocket, Service Worker, postMessage, "
        "localStorage, MutationObserver, prototype pollution, etc.). Browser-only attack "
        "surface; verify in a browser with a debugger."
    ),
    "csti": (
        "Client-side template injection (Vue/Handlebars/Lodash etc. template that trusts "
        "user input). Can lead to XSS without any server reflection."
    ),
    "unknown": "A finding type the scanner didn't classify. Inspect the payload and trigger URL manually.",
}

CONFIDENCE_GUIDE = {
    "scale": "0.0 to 1.0. In the terminal the same number is shown as a percentage (0.7 = 70%).",
    "0.30_0.50": "WEAK signal. Possible but easily a false positive. Not worth chasing alone.",
    "0.50_0.65": "PROBABLE. The payload was reflected/found by strong matches. Look at it.",
    "0.65_0.85": "LIKELY REAL. Unescaped reflection of a real XSS payload. Verify by hand in a browser.",
    "0.85_1.00": "ALMOST CERTAIN for reflected types. Exception: SSTI at 0.90 is often a false positive (see notes).",
    "important": "Confidence means 'how sure we are the payload was reflected/survived'. It is NOT proof a browser executed it. Only a headless-browser or manual check proves execution.",
}


def _humanize_result(v: Dict) -> Dict:
    """Return a copy of a finding with plain-English annotation added."""
    out = dict(v)
    vtype = v.get("xss_type", "unknown")
    conf = float(v.get("confidence", 0) or 0)
    url = v.get("url", "")

    explain = XSS_TYPE_EXPLANATIONS.get(vtype, None)
    if explain is None:
        # Map client_side_* / other prefixed types to their family explanation.
        if vtype.startswith("client_side_"):
            explain = XSS_TYPE_EXPLANATIONS.get("clientside", XSS_TYPE_EXPLANATIONS["unknown"])
        elif vtype.startswith("prototype"):
            explain = XSS_TYPE_EXPLANATIONS.get("prototype_pollution", XSS_TYPE_EXPLANATIONS["unknown"])
        elif "template" in vtype:
            explain = XSS_TYPE_EXPLANATIONS.get("csti", XSS_TYPE_EXPLANATIONS["unknown"])
        elif "mutation" in vtype:
            explain = XSS_TYPE_EXPLANATIONS.get("mutation_xss", XSS_TYPE_EXPLANATIONS["unknown"])
        elif "dom" in vtype:
            explain = XSS_TYPE_EXPLANATIONS.get("dom_based", XSS_TYPE_EXPLANATIONS["unknown"])
        elif "blind" in vtype:
            explain = XSS_TYPE_EXPLANATIONS.get("blind_xss", XSS_TYPE_EXPLANATIONS["unknown"])
        else:
            explain = XSS_TYPE_EXPLANATIONS["unknown"]

    if conf >= 0.85:
        strength = "VERY HIGH confidence"
    elif conf >= 0.65:
        strength = "HIGH confidence"
    elif conf >= 0.5:
        strength = "MEDIUM confidence"
    else:
        strength = "LOW confidence"

    out["human_explanation"] = f"{explain} Confidence: {strength} ({conf:.0%})."
    out["how_to_verify"] = (
        f"Manually open {v.get('injected_url', url)} in a browser and check whether your test "
        "value (or an alert/dialog) actually appears or fires."
    )
    return out


def _build_summary(results: List[Dict]) -> Dict:
    total = len(results)
    by_type: Dict[str, int] = {}
    for r in results:
        key = r.get("xss_type", "unknown")
        by_type[key] = by_type.get(key, 0) + 1
    high = [r for r in results if (r.get("confidence", 0) or 0) >= 0.65]
    ssti = sum(1 for r in results if r.get("xss_type") == "ssti")

    bullet = []
    bullet.append(
        f"This scan flagged {total} potential issue(s) across {len(by_type)} type(s). "
        f"By type: {', '.join(f'{k} = {c}' for k, c in sorted(by_type.items(), key=lambda x: -x[1]))}."
    )
    bullet.append(
        f"Only {len(high)} of them are high-confidence (65% or higher). Start with those -- "
        "everything below 50% is probably noise."
    )
    if ssti:
        bullet.append(
            f"{ssti} of the entries are SSTI math probes ({{{{7*7}}}}-style). Treat them as FALSE "
            "POSITIVES unless the server actually printed the computed result (e.g. '49'). The "
            "scanner only checks that the probe was echoed back, not that it executed."
        )
    bullet.append(
        "IMPORTANT: every entry means 'the payload was reflected/echoed back', NOT 'a browser "
        "executed it'. True execution is only proven by the OOB callback server, a headless "
        "browser, or opening the trigger URL yourself."
    )

    verdict = "NO real confidence here" if not high else "REVIEW REQUIRED"
    plain = (
        "Scan finished with no high-confidence (>=65%) findings. The flagged items are weak "
        "signals or likely false positives; nothing urgent."
        if not high
        else (
            "The scan flagged likely-real XSS. Open each HIGH-confidence entry's trigger URL in "
            "a browser to confirm it executes before reporting it."
        )
    )

    return {
        "verdict": verdict,
        "plain_english": plain,
        "breakdown_by_type": by_type,
        "high_confidence_count": len(high),
        "notes": bullet,
    }


def generate_report(results: List[Dict], target_url: str, args=None) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = re.sub(r"[^A-Za-z0-9]", "_", urllib.parse.urlparse(target_url).netloc)
    base_name = f"{domain}_{timestamp}"
    json_file = config.RESULTS_DIR / f"{base_name}.json"
    html_file = config.RESULTS_DIR / f"{base_name}.html"
    data = {
        "scan_time": datetime.now().isoformat(),
        "target_url": target_url,
        "version": config.VERSION,
        "total_vulnerabilities": len(results),
        "summary": _build_summary(results),
        "confidence_guide": CONFIDENCE_GUIDE,
        "how_to_read_this_report": [
            "1. The 'summary' block at the top tells you, in plain English, whether this scan found anything real.",
            "2. 'confidence' is a number 0.0-1.0. In the terminal it's shown as a percentage (0.7 = 70%). Both mean the same thing.",
            "3. High-confidence (>=0.65) reflected findings are the ones to verify. Open the 'injected_url' in a browser.",
            "4. SSTI findings are frequently false positives unless the server actually evaluates the template.",
            "5. 'human_explanation' under each vulnerability tells you what that specific finding means.",
        ],
        "vulnerabilities": [_humanize_result(v) for v in results],
    }
    save_json(json_file, data)
    html_content = _build_html_report(results, target_url, data)
    save_html(html_file, html_content)
    print(f"\n  Results saved: {json_file}")
    return str(json_file)


def _build_html_report(results: List[Dict], url: str, data: Dict) -> str:
    summary = data.get("summary", {})
    rows = ""
    summary_html = ""
    if summary:
        notes = "".join(f"<li>{n}</li>" for n in summary.get("notes", []))
        summary_html = (
            f'<h2>Plain-English Summary</h2>'
            f'<p style="font-size:16px"><b>Verdict:</b> {summary.get("verdict", "")} &mdash; {summary.get("plain_english", "")}</p>'
            f"<p><b>Breakdown:</b> {json.dumps(summary.get('breakdown_by_type', {}))} &mdash; "
            f"<b>High-confidence (>=65%):</b> {summary.get('high_confidence_count', 0)}</p>"
            f"<ul>{notes}</ul><hr/>"
        )
    for idx, v in enumerate(results, 1):
        ptype = v.get("xss_type", "UNKNOWN").upper()
        conf = v.get("confidence", 0)
        pct = f"{float(conf) * 100:.0f}%" if isinstance(conf, (int, float)) else conf
        rows += f"<h2>#{idx} [{ptype}] {v.get('url','')}</h2>"
        rows += f"<p><b>Type:</b> {ptype} | <b>Method:</b> {v.get('method','')} | <b>Confidence:</b> {pct} (0.0-1.0 in JSON)</p>"
        rows += f"<p><b>Injection Point:</b> {v.get('injection_point','')} | <b>Sink:</b> {v.get('sink','')}</p>"
        if v.get("human_explanation"):
            rows += f'<p><b>What this means:</b> {v["human_explanation"]}</p>'
        if v.get("how_to_verify"):
            rows += f'<p><b>How to verify:</b> {v["how_to_verify"]}</p>'
        rows += f"<p><b>Payload:</b></p><pre>{v.get('payload','')}</pre>"
        if v.get("bypasses"):
            rows += f"<p><b>Bypasses:</b> {', '.join(v['bypasses'])}</p>"
        if v.get("snippet"):
            rows += f"<p><b>Context:</b></p><pre>{v['snippet'][:500]}</pre>"
        if v.get("post_exploit"):
            rows += f"<p><b>Post-Exploitation:</b> {v['post_exploit']}</p>"
        rows += "<hr/>"
    html = f"""<!doctype html><html lang="en">
<head><meta charset="utf-8"><title>XSS Report - {url}</title>
<style>body{{font-family:Arial,sans-serif;background:#f6f8fa;color:#222;margin:20px}}
.wrap{{max-width:1000px;margin:auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.08)}}
h1{{color:#c62828}} pre{{background:#f4f4f4;padding:8px;border-radius:4px;overflow-x:auto}}
.vuln{{background:#fff3f3;border-left:4px solid #c62828;padding:12px;margin:10px 0;border-radius:4px}}
li{{margin:4px 0}}</style></head><body><div class="wrap">
<h1>XSS Scan Report</h1>
<p><b>Target:</b> {url} | <b>Time:</b> {data.get('scan_time','')} | <b>Vulns:</b> {data.get('total_vulnerabilities', 0)}</p>
{summary_html}
{rows}
<footer><small>Generated by xss_ultimate v{config.VERSION}</small></footer></div></body></html>"""
    return html
