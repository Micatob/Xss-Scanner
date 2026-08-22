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


def generate_report(results: List[Dict], target_url: str, args=None) -> str:
    if not results:
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urllib.parse.urlparse(target_url).netloc.replace('.', '_')
    base_name = f"{domain}_{timestamp}"
    json_file = config.RESULTS_DIR / f"{base_name}.json"
    html_file = config.RESULTS_DIR / f"{base_name}.html"
    data = {
        "scan_time": datetime.now().isoformat(),
        "target_url": target_url,
        "version": config.VERSION,
        "total_vulnerabilities": len(results),
        "vulnerabilities": results,
    }
    save_json(json_file, data)
    html_content = _build_html_report(results, target_url, data)
    save_html(html_file, html_content)
    print(f"\n  Results saved: {json_file}")
    return str(json_file)


def _build_html_report(results: List[Dict], url: str, data: Dict) -> str:
    rows = ""
    for idx, v in enumerate(results, 1):
        ptype = v.get("xss_type", "UNKNOWN").upper()
        rows += f"<h2>#{idx} [{ptype}] {v.get('url','')}</h2>"
        rows += f"<p><b>Type:</b> {ptype} | <b>Method:</b> {v.get('method','')} | <b>Confidence:</b> {v.get('confidence','')}%</p>"
        rows += f"<p><b>Injection Point:</b> {v.get('injection_point','')} | <b>Sink:</b> {v.get('sink','')}</p>"
        rows += f"<p><b>Payload:</b></p><pre>{v.get('payload','')}</pre>"
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
</style></head><body><div class="wrap">
<h1>XSS Scan Report</h1>
<p><b>Target:</b> {url} | <b>Time:</b> {data['scan_time']} | <b>Vulns:</b> {data['total_vulnerabilities']}</p>
{rows}
<footer><small>Generated by xss_ultimate v{config.VERSION}</small></footer></div></body></html>"""
    return html
