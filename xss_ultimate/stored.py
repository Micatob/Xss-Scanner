import random
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils
from .response_analyzer import ResponseAnalyzer
from .payload_engine import PayloadEngine


class StoredXSSTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.5, geo_spoof=False, collab_url=None):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.results = []
        self.submitted_payloads = []

    def test_storage_surfaces(self, surfaces: List[Dict]) -> List[Dict]:
        print("\n=== PHASE 3: STORED XSS TESTING ===")
        payloads = self.payload_engine.generate_blind(max_payloads=12)
        for surface in surfaces:
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

        for payload in payloads[:4]:
            time.sleep(self.delay)
            if self.geo_spoof:
                self.session.headers.update(utils.random_headers(geo_spoof=True))
            try:
                data = {f: payload for f in fields}
                data["submit"] = "Submit"
                if method == "POST":
                    resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)
                else:
                    resp = self.session.get(url, params=data, timeout=self.timeout, allow_redirects=True, verify=False)

                # Check if submission succeeded
                if resp.status_code in [200, 201, 302, 303, 307]:
                    self.submitted_payloads.append({"payload": payload, "url": url, "fields": fields, "surface": surface_type})
                    print(f"      Submitted payload to {surface_type}: {payload[:40]}...")
                    # Check immediate reflection
                    reflected, method_desc, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        results.append({
                            "xss_type": "stored_immediate",
                            "url": url,
                            "method": method,
                            "params": fields,
                            "payload": payload,
                            "detection_method": f"Stored (immediate reflection) on {surface_type}",
                            "confidence": conf,
                            "injection_point": surface_type,
                            "snippet": self.analyzer.extract_snippet(resp.text, payload),
                        })
                        print(f"      [V] IMMEDIATE REFLECTION: {payload[:40]}")
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
                if reflected:
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
    def __init__(self, session: requests.Session, collab_url: str, timeout=15, delay=0.5, geo_spoof=False):
        self.session = session
        self.collab_url = collab_url
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.results = []

    def test_blind_surfaces(self, surfaces: List[Dict]) -> List[Dict]:
        print("\n  Testing blind XSS surfaces...")
        payloads = self.payload_engine.generate_blind(max_payloads=8)
        for surface in surfaces:
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
        for payload in payloads[:3]:
            time.sleep(self.delay)
            try:
                data = {f: payload for f in fields}
                data["submit"] = "Submit"
                self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)
                if resp.status_code in [200, 201, 302]:
                    results.append({
                        "xss_type": "blind_xss",
                        "url": url,
                        "method": "POST",
                        "params": fields,
                        "payload": payload,
                        "detection_method": f"Blind XSS payload submitted to {surface_type}",
                        "confidence": 0.5,
                        "injection_point": surface_type,
                        "collab_url": self.collab_url,
                        "pending_callback": True,
                    })
                    print(f"      Submitted blind payload: {payload[:50]}...")
            except Exception:
                pass
        return results
