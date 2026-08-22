import re
import time
import random
from collections import deque
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils


class SiteSpider:
    def __init__(self, start_url: str, session: requests.Session, timeout=15, max_pages=50, geo_spoof=False):
        self.start_url = start_url
        self.session = session
        self.timeout = timeout
        self.max_pages = max_pages
        self.geo_spoof = geo_spoof
        self.visited: Set[str] = set()
        self.to_visit: deque = deque()
        self.start_domain = utils.extract_domain(start_url)
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.discovered_scripts: List[Dict] = []
        self.discovered_js_files: List[str] = []
        self.discovered_headers_to_test: List[str] = []
        self.discovered_ajax: List[str] = []
        self.crawl_results = {
            "urls": [],
            "forms": [],
            "scripts": [],
            "js_files": [],
            "headers_to_test": list(config.COMMON_HEADERS_TO_TEST),
            "ajax_endpoints": [],
            "params": set(),
        }

    def crawl(self) -> Dict:
        print("  Spidering site...")
        self.to_visit.append(self.start_url)
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue
            if not utils.is_same_domain(url, self.start_url):
                continue
            self.visited.add(url)
            resp = utils.fetch_url(self.session, url, self.timeout, self.geo_spoof)
            if not resp or not resp.text:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            # Extract forms
            forms = utils.extract_forms(soup, url)
            for f in forms:
                if f not in self.discovered_forms:
                    self.discovered_forms.append(f)
                    self.crawl_results["forms"].append(f)
                    print(f"    Form: {f['method']} {f['url']} [{', '.join(i['name'] for i in f['inputs'])}]")
            # Extract URL params from discovered URLs
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                self.crawl_results["params"].update(params.keys())
            # Extract scripts
            scripts = utils.extract_scripts(soup, url)
            for sc in scripts:
                if sc not in self.discovered_scripts:
                    self.discovered_scripts.append(sc)
                    self.crawl_results["scripts"].append(sc)
                    if sc.get("src"):
                        self.discovered_js_files.append(sc["src"])
                        self.crawl_results["js_files"].append(sc["src"])
            # Extract AJAX endpoints
            ajax = utils.extract_json_endpoints(soup, url)
            for a in ajax:
                if a not in self.discovered_ajax:
                    self.discovered_ajax.append(a)
                    self.crawl_results["ajax_endpoints"].append(a)
                    print(f"    AJAX: {a}")
            # Extract links
            links = utils.extract_links(soup, url)
            for link in links:
                if link not in self.visited and utils.is_same_domain(link, self.start_url):
                    self.discovered_urls.add(link)
                    self.to_visit.append(link)
                    self.crawl_results["urls"].append(link)
            time.sleep(random.uniform(0.3, 0.8))
        print(f"  Crawled {len(self.visited)} pages, found {len(self.discovered_forms)} forms, {len(self.discovered_js_files)} JS files, {len(self.discovered_ajax)} API endpoints")
        return self.crawl_results

    def get_injection_points(self) -> List[Dict]:
        points = []
        # From URL params
        for url in self.visited:
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                points.append({"type": "url_param", "url": url.split("?")[0] + "?" + parsed.query, "method": "GET", "params": params})
        # From forms
        for f in self.discovered_forms:
            input_names = [i["name"] for i in f["inputs"]]
            points.append({"type": "form", "url": f["url"], "method": f["method"], "params": input_names, "inputs": f["inputs"]})
        # Add test for common params on each discovered URL
        for url in list(self.visited)[:20]:
            for param in config.COMMON_PARAMS[:10]:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=xss_test_marker_{random.randint(1000,9999)}"
                try:
                    self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))
                    time.sleep(random.uniform(0.1, 0.3))
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True, verify=False)
                    marker = test_url.split("=")[-1]
                    if marker in resp.text and resp.status_code == 200:
                        points.append({"type": "url_param_discovered", "url": url, "method": "GET", "params": [param]})
                        print(f"    Discovered injectable param: {param} on {url}")
                except:
                    pass
        return points


class InjectionSurface:
    def __init__(self, session: requests.Session, timeout=15, geo_spoof=False):
        self.session = session
        self.timeout = timeout
        self.geo_spoof = geo_spoof

    def discover_storage_surfaces(self, url: str) -> List[Dict]:
        surfaces = []
        # Use a focused set of high-value storage surfaces to stay fast
        for surface_type in config.STORAGE_SURFACES[:6]:
            surfaces.append({"type": surface_type, "url": url, "method": "POST", "fields": [surface_type]})
        return surfaces

    def discover_header_surfaces(self, spider_results: Dict) -> List[Dict]:
        headers = []
        for hdr in config.COMMON_HEADERS_TO_TEST:
            headers.append({"type": "header", "header_name": hdr, "urls": spider_results.get("urls", [])})
        return headers

    def discover_cookie_surfaces(self, url: str) -> List[str]:
        try:
            resp = utils.fetch_url(self.session, url, self.timeout, self.geo_spoof)
            if resp and resp.headers.get("Set-Cookie"):
                return [c.split("=")[0] for c in resp.headers.get("Set-Cookie", "").split(";")]
        except:
            pass
        return []
