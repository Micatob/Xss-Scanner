import re
import random
import time
import urllib.parse
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils
from .js_analyzer import JSAnalyzer
from .response_analyzer import ResponseAnalyzer
from .payload_engine import PayloadEngine


class DOMXSSTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.3, geo_spoof=False, collab_url=None):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.js_analyzer = JSAnalyzer(session, timeout, geo_spoof)
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.results = []

    def analyze_and_test(self, spider_results: Dict, base_url: str, js_analysis: Optional[Dict] = None) -> List[Dict]:
        print("\n=== PHASE 4: DOM-BASED XSS TESTING ===")
        # Step 1: Static analysis of JS (reuse precomputed results if provided)
        if js_analysis is None:
            js_analysis = self.js_analyzer.analyze_all(spider_results.get("scripts", []), base_url)
        # Step 2: Collect unique sinks/sources found
        sinks = set(s.get("sink", "") for s in js_analysis.get("dom_sinks", []) if s.get("sink"))
        sources = set(s.get("source", "") for s in js_analysis.get("sources", []) if s.get("source"))
        if not sinks:
            print("  No DOM sinks found in JS; skipping DOM execution tests")
            return self.results
        # Step 3: Test payloads against each discovered URL, reporting matched sinks
        test_urls = [base_url]
        for u in spider_results.get("urls", [])[:10]:
            if u not in test_urls:
                test_urls.append(u)
        for url in test_urls:
            res = self._test_url(url, sorted(sinks), sorted(sources))
            self.results.extend(res)
        return self.results

    def _test_url(self, url: str, sinks: List[str], sources: List[str]) -> List[Dict]:
        results = []
        print(f"  Testing DOM sinks {', '.join(sinks[:4])} on {url}")
        payloads = self.payload_engine.generate_dom(max_payloads=15)
        for payload in payloads:
            time.sleep(self.delay)
            matched_sinks = []
            try:
                # Inject payload via fragment
                fragment_url = f"{url}#{urllib.parse.quote(payload)}"
                resp = self.session.get(fragment_url, timeout=self.timeout, verify=False)
                for sink in sinks:
                    if self._check_dom_execution(payload, resp.text, sink):
                        matched_sinks.append(sink)
                if matched_sinks:
                    results.append({
                        "xss_type": "dom_based",
                        "url": fragment_url,
                        "method": "GET",
                        "params": ["#fragment"],
                        "payload": payload,
                        "detection_method": f"DOM-based via {','.join(matched_sinks)}",
                        "confidence": 0.7,
                        "sink": ",".join(matched_sinks),
                        "source": ",".join(sources) or "unknown",
                        "injection_point": "fragment",
                    })
                    print(f"    [V] DOM XSS via fragment: {matched_sinks}")

                # Try via search param injection (append correctly to existing query)
                sep = "&" if "?" in url else "?"
                search_url = f"{url}{sep}{urllib.parse.urlencode({'q': payload})}"
                resp = self.session.get(search_url, timeout=self.timeout, verify=False)
                for sink in sinks:
                    if self._check_dom_execution(payload, resp.text, sink) and sink not in matched_sinks:
                        matched_sinks.append(sink)
                if matched_sinks:
                    results.append({
                        "xss_type": "dom_based",
                        "url": search_url,
                        "method": "GET",
                        "params": ["q"],
                        "payload": payload,
                        "detection_method": f"DOM-based via {','.join(matched_sinks)} (search)",
                        "confidence": 0.7,
                        "sink": ",".join(matched_sinks),
                        "source": ",".join(sources) or "location.search",
                        "injection_point": "search_param",
                    })
                    print(f"    [V] DOM XSS via search param: {matched_sinks}")
            except Exception:
                pass
        return results

    def _check_dom_execution(self, payload: str, html: str, sink: str) -> bool:
        reflected, _, _ = self.analyzer.detect_reflection(payload, html)
        sink_present = sink.lower() in html.lower() if sink else False
        # Check for DOM-specific indicators
        dom_indicators = [
            "location.hash", "location.search", "location.href",
            "document.URL", "document.documentURI", "document.baseURI",
        ]
        has_dom_trigger = any(ind in html.lower() for ind in dom_indicators)
        return reflected and (sink_present or has_dom_trigger)

    def detect_angular_expression(self, url: str) -> bool:
        try:
            test_payload = "{{7*7}}"
            test_url = f"{url}?q={urllib.parse.quote(test_payload)}"
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            return "49" in resp.text or "{{7*7}}" not in resp.text
        except Exception:
            return False

    def detect_vue_template(self, url: str) -> bool:
        try:
            test_payload = "{{constructor.constructor('alert(1)')()}}"
            test_url = f"{url}?q={urllib.parse.quote(test_payload)}"
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            return "alert" in resp.text.lower() or test_payload in resp.text
        except Exception:
            return False
