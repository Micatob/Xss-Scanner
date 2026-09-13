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
    def __init__(self, session: requests.Session, timeout=15, delay=0.3, geo_spoof=False, collab_url=None, max_payloads=0):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.js_analyzer = JSAnalyzer(session, timeout, geo_spoof)
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.max_payloads = max_payloads
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
        # Static taint finding: a source flowing to a sink in the same page is
        # reportable even when the server never reflects our probe (fragments
        # like #payload are never sent over HTTP, so requiring reflection for
        # fragment tests guarantees zero findings).
        static_sources = sorted(sources) or ["location.hash/location.search"]
        for url in [base_url] + [u for u in spider_results.get("urls", [])[:2] if u != base_url]:
            self.results.append({
                "xss_type": "dom_based",
                "url": url,
                "method": "GET",
                "params": ["#fragment", "query"],
                "payload": "#<img src=x onerror=alert(1)>",
                "detection_method": f"Static DOM source->sink: {', '.join(static_sources[:3])} -> {', '.join(sorted(sinks)[:4])}",
                "confidence": 0.6,
                "sink": ",".join(sorted(sinks)[:6]),
                "source": ",".join(static_sources[:6]),
                "injection_point": "dom_static",
            })
        print(f"  Static DOM taint: {len(sinks)} sink(s), {len(sources)} source(s)")
        # Step 3: Dynamic test — inject via real query params (not fragments,
        # which never reach the server) and check reflection + sink presence.
        test_urls = [base_url]
        for u in spider_results.get("urls", [])[:2]:
            if u not in test_urls:
                test_urls.append(u)
        # Discover which query params this site actually reflects.
        test_params = self._discover_reflected_params(test_urls)
        for url in test_urls:
            res = self._test_url(url, sorted(sinks), sorted(sources), test_params)
            self.results.extend(res)
        return self.results

    def _discover_reflected_params(self, urls: List[str]) -> List[str]:
        """Return query-param names worth testing (site-specific first)."""
        params: List[str] = []
        for url in urls:
            try:
                parsed = urlparse(url)
                for p in parse_qs(parsed.query).keys():
                    if p not in params:
                        params.append(p)
            except Exception:
                pass
        for p in ("search", "name", "comment", "q"):
            if p not in params:
                params.append(p)
        return params[:4]

    def _test_url(self, url: str, sinks: List[str], sources: List[str], test_params: List[str]) -> List[Dict]:
        results = []
        print(f"  Testing DOM sinks {', '.join(sinks[:4])} on {url}")
        payloads = self.payload_engine.generate_dom(max_payloads=self.max_payloads or 8)
        base = url.split("#")[0].split("?")[0]
        for payload in payloads:
            time.sleep(self.delay)
            try:
                # Inject via a real query param the server reflects (fragments
                # are never sent to the server, so fragment-only tests can
                # never show reflection over HTTP). Overwrite (don't append)
                # so servers that read the first value see our payload.
                param = test_params[0] if test_params else "q"
                parsed = urlparse(url.split("#")[0])
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                search_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                resp = self.session.get(search_url, timeout=self.timeout, verify=False)
                matched_sinks = []
                for sink in sinks:
                    if self._check_dom_execution(payload, resp.text, sink):
                        matched_sinks.append(sink)
                if matched_sinks:
                    results.append({
                        "xss_type": "dom_based",
                        "url": search_url,
                        "method": "GET",
                        "params": [param],
                        "payload": payload,
                        "detection_method": f"DOM-based via {','.join(matched_sinks)} (query)",
                        "confidence": 0.7,
                        "sink": ",".join(matched_sinks),
                        "source": ",".join(sources) or "location.search",
                        "injection_point": "query_param",
                    })
                    print(f"    [V] DOM XSS via query param: {matched_sinks}")
                    if len(results) >= 5:
                        break
            except Exception:
                pass
        # Also record the fragment trigger URL for manual browser verification
        # (fragment payloads only execute client-side, never over HTTP).
        if sinks and payloads:
            results.append({
                "xss_type": "dom_based",
                "url": f"{base}#{urllib.parse.quote(payloads[0])}",
                "method": "GET",
                "params": ["#fragment"],
                "payload": payloads[0],
                "detection_method": "DOM fragment trigger (verify manually in browser)",
                "confidence": 0.55,
                "sink": ",".join(sinks[:4]),
                "source": ",".join(sources) or "location.hash",
                "injection_point": "fragment",
            })
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
            base = url.split("?")[0]
            # Baseline first: only trust '49' when it newly appears.
            resp_base = self.session.get(base, timeout=self.timeout, verify=False)
            base_has_49 = "49" in (resp_base.text if resp_base is not None else "")
            test_payload = "{{7*7}}"
            test_url = f"{base}?q={urllib.parse.quote(test_payload)}"
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            if resp is None:
                return False
            # Evaluated (49 appears, probe gone) and not in baseline.
            if "49" in resp.text and test_payload not in resp.text and not base_has_49:
                return True
            return False
        except Exception:
            return False

    def detect_vue_template(self, url: str) -> bool:
        try:
            test_payload = "{{constructor.constructor('alert(1)')()}}"
            test_url = f"{url}?q={urllib.parse.quote(test_payload)}"
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            if resp is None:
                return False
            # Require the exact probe to be reflected, not just any page that
            # happens to contain the word "alert".
            return test_payload in resp.text
        except Exception:
            return False
