import re
import base64
import urllib.parse
import json
from typing import List, Dict, Tuple, Optional, Set

from bs4 import BeautifulSoup

from . import config


class ResponseAnalyzer:
    def __init__(self):
        self.context_cache: Dict[str, str] = {}

    def detect_context(self, payload: str, response_text: str, injection_point: str = "") -> str:
        """Detect the injection context (html, attribute, javascript, url, css)."""
        # Check if payload appears in attribute context
        attribute_patterns = [
            rf'(["\'])\s*on\w+\s*=\s*["\']?{re.escape(payload[:30])}',
            rf'{re.escape(payload[:20])}.*?["\']\s*[>]',
            rf'<[^>]+{re.escape(payload[:20])}[^>]*["\']',
        ]
        for pat in attribute_patterns:
            if re.search(pat, response_text, re.IGNORECASE):
                return "attribute"

        # Check if in JavaScript context
        js_patterns = [
            rf'<script[^>]*>[^<]*{re.escape(payload[:30])}',
            rf"'[^']*{re.escape(payload[:20])}[^']*'",
            rf'"[^"]*{re.escape(payload[:20])}[^"]*"',
            rf'`[^`]*{re.escape(payload[:20])}[^`]*`',
            rf'return\s+["\']?{re.escape(payload[:20])}',
            rf'eval\([^)]*{re.escape(payload[:20])}',
            rf'new\s+Function\([^)]*{re.escape(payload[:20])}',
        ]
        for pat in js_patterns:
            if re.search(pat, response_text, re.IGNORECASE):
                return "javascript"

        # Check if in URL context
        url_patterns = [
            rf'href\s*=\s*["\']?{re.escape(payload[:30])}',
            rf'src\s*=\s*["\']?{re.escape(payload[:30])}',
            rf'action\s*=\s*["\']?{re.escape(payload[:30])}',
            rf'url\(["\']?{re.escape(payload[:20])}',
        ]
        for pat in url_patterns:
            if re.search(pat, response_text, re.IGNORECASE):
                return "url"

        # Check if in CSS context
        if re.search(rf'<style[^>]*>[^<]*{re.escape(payload[:20])}', response_text, re.IGNORECASE):
            return "css"
        if re.search(rf'style\s*=\s*["\'][^"\'{re.escape(payload[:20])}]', response_text, re.IGNORECASE):
            return "css"

        # Default: HTML context
        if re.search(rf'<[^>]*{re.escape(payload[:20])}[^>]*>', response_text, re.IGNORECASE):
            return "html"

        return "unknown"

    def detect_reflection(self, payload: str, response_text: str) -> Tuple[bool, str, float]:
        """Detect if payload is reflected; returns (found, method, confidence)."""
        confidence = 0.0
        method = ""

        if not payload or not response_text:
            return False, "", 0.0

        # Direct reflection (strongest)
        if payload in response_text:
            count = response_text.count(payload)
            confidence = 0.95 + (min(count, 10) * 0.005)
            method = "direct_match"
            return True, "Direct reflection in response", min(confidence, 0.99)

        # Partial payload (first 40 chars)
        short = payload[:40]
        if len(short) > 10 and short in response_text:
            confidence = 0.7
            method = "partial_match"
            return True, "Partial payload reflected", 0.7

        # Key XSS tokens
        tokens = []
        if "<script" in payload.lower():
            tokens.append("<script")
        if "onerror" in payload.lower():
            tokens.append("onerror")
        if "onload" in payload.lower():
            tokens.append("onload")
        if "alert" in payload.lower():
            tokens.append("alert")
        if "onfocus" in payload.lower():
            tokens.append("onfocus")
        if "javascript:" in payload.lower():
            tokens.append("javascript")
        if "svg" in payload.lower():
            tokens.append("svg")
        if "onmouseover" in payload.lower():
            tokens.append("onmouseover")
        if "prompt" in payload.lower():
            tokens.append("prompt")
        if "confirm" in payload.lower():
            tokens.append("confirm")

        matched_tokens = [t for t in tokens if t in response_text.lower()]
        if matched_tokens and tokens:
            ratio = len(matched_tokens) / len(tokens)
            if ratio >= 0.6:
                confidence = ratio * 0.65
                method = f"token_match({','.join(matched_tokens)})"
                return True, f"XSS tokens reflected: {', '.join(matched_tokens)}", round(confidence, 2)

        # Encoded variations
        encoded_checks = [
            (payload.replace("<", "&lt;").replace(">", "&gt;"), "html_encoded"),
            (self._url_encode(payload), "url_encoded"),
            (self._double_url_encode(payload), "double_url_encoded"),
            (self._base64_encode(payload), "base64"),
        ]
        for encoded, enc_method in encoded_checks:
            if encoded and len(encoded) > 5 and encoded in response_text:
                confidence = 0.6
                method = enc_method
                return True, f"Encoded reflection ({enc_method})", 0.6

        return False, method, confidence

    def detect_dom_sink_in_response(self, payload: str, response_text: str) -> Tuple[bool, str]:
        """Check if response includes DOM sinks that the payload could reach."""
        for sink in config.DOM_SINKS:
            if sink in response_text:
                # Check if payload also appears nearby
                idx = response_text.find(sink)
                nearby = response_text[max(0, idx - 200):idx + 200]
                if any(t in nearby for t in ["<script", "onerror", "onload", "onfocus", "javascript"]):
                    return True, f"DOM sink {sink} reachable by script context"
        return False, ""

    def detect_csp_bypass(self, csp: Dict[str, List[str]], payload: str) -> List[str]:
        """Detect if CSP allows the payload to execute."""
        bypasses = []
        script_src = csp.get("default-src", csp.get("script-src", []))
        script_src_str = " ".join(script_src)
        if "'unsafe-inline'" in script_src_str or "cdn.jsdelivr.net" in script_src_str:
            bypasses.append("unsafe-inline CSP")
        if "'unsafe-eval'" in script_src_str:
            bypasses.append("unsafe-eval CSP")
        if "http:" in script_src_str or "https:" in script_src_str or "*" in script_src_str:
            bypasses.append("permissive CSP")
        if not script_src or "'none'" in script_src_str:
            bypasses.append("restrictive CSP")
        if "nonce-" in script_src_str:
            bypasses.append("nonce-based CSP")
        return bypasses

    def extract_snippet(self, response_text: str, payload: str, context_chars=150) -> str:
        idx = response_text.find(payload[:50]) if len(payload) > 50 else response_text.find(payload[:30])
        if idx >= 0:
            start = max(0, idx - context_chars)
            end = min(len(response_text), idx + context_chars)
            snippet = response_text[start:end]
            if start > 0:
                snippet = "..." + snippet
            if end < len(response_text):
                snippet = snippet + "..."
            return snippet
        return response_text[:300]

    def _url_encode(self, s: str) -> str:
        return urllib.parse.quote(s, safe='')

    def _double_url_encode(self, s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

    def _base64_encode(self, s: str) -> str:
        try:
            return base64.b64encode(s.encode()).decode()
        except Exception:
            return ""

    def verify_with_browser(self, payload: str, url: str) -> Dict:
        return {"verified": False, "message": "Browser not available"}


class WAFDetector:
    def __init__(self):
        self.waf_signatures = {
            "Cloudflare": [r"cf-ray", r"cloudflare", r"__cfduid", r"cf_email"],
            "Cloudflare CAPTCHA": [r"cf-browser-verification", r"challenge-form"],
            "ModSecurity": [r"ModSecurity", r"NOYB", r"owasp"],
            "AWS WAF": [r"AWSWAF", r"awswaf", r"x-amzn-RequestId"],
            "F5 BIG-IP": [r"BigIP", r"TS[a-f0-9]", r"F5\-"],
            "Akamai": [r"akamai", r"ak_bmsc"],
            "Sucuri": [r"Sucuri", r"cloudproxy"],
            "Barracuda": [r"barracuda", r"Barracuda"],
            "Imperva": [r"incapsula", r"X-Iinfo", r"visid_incap"],
            "WordFence": [r"wordfence", r"wfwaf"],
        }
        self.block_indicators = ["code=403", "code=406", "code=418", "blocked", "waf", "forbidden"]

    def detect(self, response: requests.Response) -> Dict:
        detected = []
        headers_str = str(response.headers)
        body_lower = response.text.lower() if response.text else ""
        for waf_name, patterns in self.waf_signatures.items():
            for pat in patterns:
                if re.search(pat, headers_str, re.IGNORECASE) or re.search(pat, body_lower):
                    detected.append(waf_name)
                    break
        score = 0
        for ind in self.block_indicators:
            if ind in body_lower:
                score += 1
        if response.status_code in [403, 406, 418, 429]:
            score += 2
        return {
            "waf_detected": list(set(detected)),
            "block_score": score,
            "likely_blocked": score >= 2,
        }
