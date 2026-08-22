import random
import time
import urllib.parse
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils
from .response_analyzer import ResponseAnalyzer, WAFDetector
from .waf_bypass import WAFBypass
from .payload_engine import PayloadEngine, context_specific_payloads
from .ai_integration import AIEnhancedPayloadEngine, AIResponseAnalyzer, AIInjectionAnalyzer, AIAnalysisResult, InjectionCandidate


class ReflectedXSSTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.3, geo_spoof=False, aggressive_waf=True, max_payloads=0, collab_url=None,
                 ai_payload_engine: Optional[AIEnhancedPayloadEngine] = None,
                 ai_response_analyzer: Optional[AIResponseAnalyzer] = None,
                 ai_analysis: Optional[AIAnalysisResult] = None):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.aggressive_waf = aggressive_waf
        self.max_payloads = max_payloads
        self.analyzer = ResponseAnalyzer()
        self.waf_detector = WAFDetector()
        self.waf_bypass = WAFBypass()
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.ai_payload_engine = ai_payload_engine
        self.ai_response_analyzer = ai_response_analyzer
        self.ai_analysis = ai_analysis
        self.results: List[Dict] = []

    def test_all_points(self, injection_points: List[Dict]) -> List[Dict]:
        print("\n=== PHASE 2: REFLECTED XSS TESTING ===")
        for point in injection_points:
            results = self._test_point(point)
            self.results.extend(results)
        return self.results

    def _test_point(self, point: Dict) -> List[Dict]:
        results = []
        url = point["url"]
        method = point.get("method", "GET")
        params = point.get("params", [])
        point_type = point.get("type", "form")
        inputs = point.get("inputs", [])
        print(f"\n  Testing {point_type.upper()} {method} {url}")
        print(f"    Params: {', '.join(params[:5])}{'...' if len(params) > 5 else ''}")

        if not params:
            return results

        # Get baseline response
        baseline = self._fetch_baseline(url, method, params)
        if baseline is None:
            return results

        # Detect context for smarter payload selection
        detected_context = self._detect_injection_context(baseline, url, params)
        print(f"    Detected context: {detected_context}")
        
        # Get target framework from AI analysis
        target_framework = ""
        if self.ai_analysis:
            for candidate in self.ai_analysis.candidates:
                if candidate.url == url and candidate.parameter in params:
                    target_framework = candidate.reasoning  # Use reasoning as framework hint
                    break

        # Select payloads based on context
        payloads = self._select_payloads(detected_context, params, url, target_framework)
        print(f"    Testing {len(payloads)} payloads")

        consecutive_blocks = 0
        for i, payload in enumerate(payloads):
            # Adaptive delay when rate limited
            if consecutive_blocks > 2:
                extra_delay = min(self.delay * (consecutive_blocks // 2), 8)
                time.sleep(extra_delay)
            elif isinstance(self.delay, (list, tuple)):
                time.sleep(random.uniform(*self.delay))
            else:
                time.sleep(self.delay)

            if self.aggressive_waf:
                self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))

            try:
                result = self._test_single(url, method, params, payload, point_type, inputs, detected_context, target_framework)
                if result:
                    # Verification with headless browser
                    if result.get("confidence", 0) >= 0.5:
                        browser_ok = self._verify_with_browser(payload, result.get("injected_url", url))
                        if browser_ok:
                            result["browser_verified"] = True
                            result["confidence"] = min(result.get("confidence", 0) + 0.2, 0.99)
                            print(f"      [V] VERIFIED (browser execution confirmed)")
                    results.append(result)
                    print(f"      [V] FOUND: {result.get('detection_method','')} (confidence: {result.get('confidence',0):.0%})")
                consecutive_blocks = 0
            except Exception as e:
                consecutive_blocks += 1

        return results

    def _fetch_baseline(self, url: str, method: str, params: List[str]) -> Optional[str]:
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            else:
                data = {p: "test" for p in params[:5]}
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)
            return resp.text
        except Exception:
            return None

    def _detect_injection_context(self, baseline: str, url: str, params: List[str]) -> str:
        for test_val in ["XSS_TEST\"'<>", "XSS_TEST${}", "XSS_TEST(;)", "XSS_TEST'}]"]:
            try:
                if "?" in url:
                    test_url = url + "&" + urllib.parse.urlencode({p: test_val for p in params[:2]})
                else:
                    test_url = url + "?" + urllib.parse.urlencode({p: test_val for p in params[:2]})
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    return self.analyzer.detect_context(test_val, resp.text)
            except Exception:
                pass
        return "html"

    def _select_payloads(self, context: str, params: List[str], url: str = "", target_framework: str = "") -> List[str]:
        # Use AI-enhanced payloads if available
        if self.ai_payload_engine and self.ai_analysis:
            # Get WAF info from ai_analysis
            waf_info = {"waf_detected": self.ai_analysis.waf_evasion_plan, "csp": {}}
            ai_payloads = self.ai_payload_engine.generate_smart_payloads(
                context, target_framework, waf_info, url, params[0] if params else "q"
            )
            if ai_payloads:
                base = self.payload_engine.generate_reflected(max_payloads=40)
                ctx = context_specific_payloads(context, self.payload_engine.collab_url)
                combined = list(set(base + ctx + ai_payloads))
                random.shuffle(combined)
                if self.max_payloads and self.max_payloads > 0:
                    return combined[:self.max_payloads]
                return combined[:120]
        
        base = self.payload_engine.generate_reflected(max_payloads=80)
        ctx = context_specific_payloads(context, self.payload_engine.collab_url)
        combined = list(set(base + ctx))
        random.shuffle(combined)
        if self.max_payloads and self.max_payloads > 0:
            return combined[:self.max_payloads]
        return combined[:100]

    def _test_single(self, url: str, method: str, params: List[str], payload: str, point_type: str, inputs: List[Dict], 
                  context: str = "html", target_framework: str = "") -> Optional[Dict]:
        payload_display = payload[:50].replace("\n", "\\n")
        print(f"    [{payload_display}] ", end="", flush=True)

        try:
            if method == "GET":
                injected_url, data = self._build_injected_get(url, params, payload, point_type)
                if not injected_url:
                    print("FAIL (build)")
                    return None
                resp = self.session.get(injected_url, timeout=self.timeout, allow_redirects=True, verify=False)
            else:
                injected_url, data = self._build_injected_post(url, params, payload, inputs)
                if not data:
                    print("FAIL (build)")
                    return None
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, verify=False)

            # WAF detection
            waf_result = self.waf_detector.detect(resp)
            if waf_result["likely_blocked"]:
                print(f" [BLOCKED]", end="")
                return None

            if resp.status_code not in [200, 201, 204, 301, 302, 304]:
                print(f" [HTTP {resp.status_code}]", end="")
                return None

            text = resp.text
            headers = dict(resp.headers)
            
            # Use AI response analyzer if available
            if self.ai_response_analyzer:
                ai_result = self.ai_response_analyzer.analyze(payload, text, headers, context)
                is_reflected = ai_result.get("vulnerable", False)
                method_desc = ai_result.get("evidence", ["AI analysis"])[0] if ai_result.get("evidence") else "AI detection"
                confidence = ai_result.get("confidence", 0.0)
                bypasses = ai_result.get("bypass_techniques", [])
            else:
                is_reflected, method_desc, confidence = self.analyzer.detect_reflection(payload, text)
                if not is_reflected:
                    is_reflected, method_desc, confidence = self.analyzer.detect_reflection(payload[:40], text)
                    if is_reflected:
                        confidence *= 0.6
                bypasses = self.waf_bypass.detect_bypass_techniques(payload, text)

            if is_reflected and confidence >= 0.3:
                dom_ok, dom_desc = self.analyzer.detect_dom_sink_in_response(payload, text)
                snippet = self.analyzer.extract_snippet(text, payload)
                final_confidence = min(confidence + (0.1 if dom_ok else 0), 0.99)
                print(f" [V] ({method_desc})", end="")
                result = {
                    "xss_type": "reflected",
                    "url": url,
                    "injected_url": injected_url if method == "GET" else url,
                    "method": method,
                    "params": params,
                    "payload": payload,
                    "detection_method": method_desc,
                    "confidence": round(final_confidence, 3),
                    "dom_sink": dom_desc if dom_ok else "",
                    "bypasses": bypasses,
                    "snippet": snippet,
                    "injection_point": point_type,
                    "waf_bypassed": len(bypasses) > 0,
                    "status_code": resp.status_code,
                    "context": context,
                }
                return result
            else:
                # Record failure for AI learning
                if self.ai_payload_engine:
                    self.ai_payload_engine.record_failure(
                        context, target_framework, {"waf_detected": []}, url, params[0] if params else "q", payload
                    )
            print(" -", end="")
            return None
        except requests.exceptions.Timeout:
            print(" [TIMEOUT]", end="")
            return None
        except requests.exceptions.ConnectionError:
            print(" [CONNERR]", end="")
            return None
        except Exception as e:
            print(f" [ERR: {str(e)[:80]}]", end="")
            return None
        finally:
            print()

    def _build_injected_get(self, url: str, params: List[str], payload: str, point_type: str) -> Tuple[Optional[str], None]:
        if point_type == "fragment":
            base = url.split("#")[0]
            return f"{base}#{payload}", None
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for p in params:
            qs[p] = [payload]
        injected = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
        return injected, None

    def _build_injected_post(self, url: str, params: List[str], payload: str, inputs: List[Dict]) -> Tuple[str, Dict]:
        data = {}
        for p in params:
            data[p] = payload
        # Also send any default values
        for inp in inputs:
            if inp["name"] not in data:
                data[inp["name"]] = inp.get("value", "")
        return url, data

    def _verify_with_browser(self, payload: str, url: str) -> bool:
        return False


class HeaderXSSTester:
    def __init__(self, session: requests.Session, timeout=15, geo_spoof=False):
        self.session = session
        self.timeout = timeout
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.results = []

    def test_headers(self, urls: List[str], payloads: List[str]) -> List[Dict]:
        print("\n  Testing header-based XSS...")
        test_headers = config.COMMON_HEADERS_TO_TEST
        for url in urls[:5]:
            for payload in payloads[:10]:
                for header in test_headers:
                    try:
                        hdrs = utils.random_headers(geo_spoof=self.geo_spoof)
                        hdrs[header] = payload
                        resp = self.session.get(url, headers=hdrs, timeout=self.timeout, verify=False)
                        reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                        if reflected:
                            self.results.append({
                                "xss_type": "reflected_header",
                                "url": url,
                                "method": "GET",
                                "params": [header],
                                "payload": payload,
                                "detection_method": f"Header reflection: {header}",
                                "confidence": conf,
                                "injection_point": f"header:{header}",
                            })
                            print(f"      [V] Header XSS via {header}: {payload[:40]}")
                    except Exception:
                        pass
        return self.results
