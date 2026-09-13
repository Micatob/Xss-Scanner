import random
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils
from .response_analyzer import ResponseAnalyzer, WAFDetector
from .waf_bypass import WAFBypass
from .payload_engine import PayloadEngine


class StoredXSSTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.5, geo_spoof=False, collab_url=None, max_payloads=0, aggressive_waf=False):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.waf_detector = WAFDetector()
        self.waf_bypass = WAFBypass()
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.max_payloads = max_payloads
        self.aggressive_waf = aggressive_waf
        self.results = []
        self.submitted_payloads = []
        self._seen_stored = set()

    def test_storage_surfaces(self, surfaces: List[Dict]) -> List[Dict]:
        print("\n=== PHASE 3: STORED XSS TESTING ===")
        payloads = self.payload_engine.generate_blind(max_payloads=self.max_payloads or 8)
        # Prefer real forms; synthetic storage surfaces are noise + slowness.
        real = [s for s in surfaces if s.get("inputs")]
        synthetic = [s for s in surfaces if not s.get("inputs")]
        ordered = (real + synthetic[:2])[:6]
        for surface in ordered:
            res = self._test_surface(surface, payloads)
            self.results.extend(res)
        return self.results

    def _test_surface(self, surface: Dict, payloads: List[str]) -> List[Dict]:
        results = []
        url = surface.get("url")
        if not url:
            return results
        surface_type = surface.get("type", "form")
        if surface.get("inputs"):
            fields = [i.get("name") for i in surface["inputs"] if i.get("name")]
            method = surface.get("method", "POST")
        else:
            fields = surface.get("fields", [surface_type])
            method = surface.get("method", "POST")
        if not fields:
            return results

        print(f"\n  Testing {surface_type} surface at {url}")
        print(f"    Fields: {', '.join(fields)}")

        variant_limit = config.WAF_MAX_MUTATIONS if self.aggressive_waf else 2
        for payload in payloads[: (self.max_payloads or 4)]:
            time.sleep(self.delay)
            if self.geo_spoof:
                self.session.headers.update(utils.random_headers(geo_spoof=True))
            try:
                # WAF evasion: if the form submission is blocked, retry with
                # obfuscated variants until one gets through (or all fail).
                actual_payload = payload
                resp = None
                inbound = [payload] + self.waf_bypass.generate_evasive_variants(payload, limit=variant_limit)
                for actual_payload in inbound:
                    time.sleep(config.WAF_RETRY_DELAY)
                    data = {f: actual_payload for f in fields}
                    data["submit"] = "Submit"
                    if method == "POST":
                        resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)
                    else:
                        # Overwrite (not append) existing query params so the
                        # server sees our payload even if it reads the first
                        # value for a duplicated key.
                        from urllib.parse import urlparse as _up, parse_qs as _pqs, urlencode as _ue
                        _parsed = _up(url.split("#")[0])
                        _qs = _pqs(_parsed.query, keep_blank_values=True)
                        for _k, _v in data.items():
                            _qs[_k] = [_v]
                        _full = _parsed._replace(query=_ue(_qs, doseq=True)).geturl()
                        resp = self.session.get(_full, timeout=self.timeout, allow_redirects=True, verify=False)
                    if self.waf_detector.detect(resp)["likely_blocked"]:
                        continue
                    break

                # Check if submission succeeded
                if resp is not None and resp.status_code in [200, 201, 302, 303, 307]:
                    self.submitted_payloads.append({"payload": actual_payload, "url": url, "fields": fields, "surface": surface_type})
                    print(f"      Submitted payload to {surface_type}: {actual_payload[:40]}...")
                    # Check immediate reflection
                    reflected, method_desc, conf = self.analyzer.detect_reflection(actual_payload, resp.text)
                    if reflected and conf >= 0.6:
                        results.append({
                            "xss_type": "stored_immediate",
                            "url": url,
                            "method": method,
                            "params": fields,
                            "payload": actual_payload,
                            "detection_method": f"Stored (immediate reflection) on {surface_type}",
                            "confidence": conf,
                            "injection_point": surface_type,
                            "waf_bypassed": actual_payload != payload,
                            "snippet": self.analyzer.extract_snippet(resp.text, actual_payload),
                        })
                        print(f"      [V] IMMEDIATE REFLECTION: {actual_payload[:40]}")
                    else:
                        print(f"        (submitted, waiting for reflection)")
            except Exception as e:
                print(f"      Error submitting to {surface_type}: {e}")

        # Re-fetch the page to check for stored payload
        print(f"    Re-fetching to check stored payloads...")
        for p_entry in self.submitted_payloads[-10:]:
            try:
                check_resp = self.session.get(p_entry["url"], timeout=self.timeout, verify=False)
                reflected, method_desc, conf = self.analyzer.detect_reflection(p_entry["payload"], check_resp.text)
                if reflected and conf >= 0.6:
                    key = (p_entry["url"], p_entry["payload"])
                    if key in self._seen_stored:
                        continue
                    self._seen_stored.add(key)
                    # Skip if we already reported this payload as immediate
                    # reflection — don't double-count the same finding.
                    if any(r.get("payload") == p_entry["payload"] and r.get("url") == p_entry["url"] for r in results):
                        continue
                    result = {
                        "xss_type": "stored",
                        "url": p_entry["url"],
                        "method": "GET",
                        "params": p_entry["fields"],
                        "payload": p_entry["payload"],
                        "detection_method": f"Stored XSS ({p_entry['surface']})",
                        "confidence": conf,
                        "injection_point": p_entry["surface"],
                        "snippet": self.analyzer.extract_snippet(check_resp.text, p_entry["payload"]),
                    }
                    if result not in results:
                        results.append(result)
                        print(f"      [V] CONFIRMED STORED: {p_entry['payload'][:40]}")
            except Exception:
                pass
        return results

    def get_submitted_payloads(self) -> List[Dict]:
        return self.submitted_payloads


class BlindXSSTester:
    def __init__(self, session: requests.Session, collab_url: str, timeout=15, delay=0.5, geo_spoof=False, max_payloads=0, aggressive_waf=False):
        self.session = session
        self.collab_url = collab_url
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.waf_detector = WAFDetector()
        self.waf_bypass = WAFBypass()
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.max_payloads = max_payloads
        self.aggressive_waf = aggressive_waf
        self.results = []

    def test_blind_surfaces(self, surfaces: List[Dict]) -> List[Dict]:
        print("\n  Testing blind XSS surfaces...")
        payloads = self.payload_engine.generate_blind(max_payloads=self.max_payloads or 6)
        for surface in surfaces[:4]:
            res = self._test_blind(surface, payloads)
            self.results.extend(res)
        return self.results

    def _test_blind(self, surface: Dict, payloads: List[str]) -> List[Dict]:
        results = []
        url = surface.get("url")
        if not url:
            return results
        surface_type = surface.get("type", "form")
        if surface.get("inputs"):
            fields = [i.get("name") for i in surface["inputs"] if i.get("name")]
        else:
            fields = surface.get("fields", [surface_type])
        if not fields:
            return results
        print(f"    Blind testing {surface_type} at {url}")
        variant_limit = config.WAF_MAX_MUTATIONS if self.aggressive_waf else 2
        for payload in payloads[:(self.max_payloads or 3)]:
            time.sleep(self.delay)
            actual_payload = payload
            submitted = False
            inbound = [payload] + self.waf_bypass.generate_evasive_variants(payload, limit=variant_limit)
            for actual_payload in inbound:
                try:
                    data = {f: actual_payload for f in fields}
                    data["submit"] = "Submit"
                    self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))
                    resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)
                    if self.waf_detector.detect(resp)["likely_blocked"]:
                        time.sleep(config.WAF_RETRY_DELAY)
                        continue
                    if resp.status_code in [200, 201, 302]:
                        submitted = True
                        break
                except Exception:
                    pass
            if submitted:
                results.append({
                    "xss_type": "blind_xss",
                    "url": url,
                    "method": "POST",
                    "params": fields,
                    "payload": actual_payload,
                    "detection_method": f"Blind XSS payload submitted to {surface_type}",
                    "confidence": 0.5,
                    "injection_point": surface_type,
                    "waf_bypassed": actual_payload != payload,
                    "collab_url": self.collab_url,
                    "pending_callback": True,
                })
                print(f"      Submitted blind payload: {actual_payload[:50]}...")
        return results
