import re
import time
import random
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from . import config
from . import utils


class JSAnalyzer:
    def __init__(self, session: requests.Session, timeout=15, geo_spoof=False):
        self.session = session
        self.timeout = timeout
        self.geo_spoof = geo_spoof
        self.analyzed_files: Set[str] = set()
        self.dom_sinks_found: List[Dict] = []
        self.sources_found: List[Dict] = []

    def analyze_all(self, scripts: List[Dict], base_url: str) -> Dict:
        print("  Analyzing JavaScript for DOM sinks...")
        for script in scripts:
            if script.get("src"):
                self._analyze_js_file(script["src"])
            elif script.get("inline"):
                self._analyze_inline_js(script["content"], base_url)
        results = {
            "dom_sinks": self.dom_sinks_found,
            "sources": self.sources_found,
            "dangerous_patterns": self._classify_danger(),
        }
        if results["dom_sinks"]:
            print(f"    DOM sinks found: {len(results['dom_sinks'])}")
            for sink in results["dom_sinks"][:10]:
                print(f"      {sink['type']}:{sink['sink']} in {sink.get('file','inline')}")
        if results["dangerous_patterns"]:
            print(f"    Dangerous patterns: {results['dangerous_patterns']}")
        return results

    def _analyze_js_file(self, url: str):
        if url in self.analyzed_files:
            return
        self.analyzed_files.add(url)
        try:
            self.session.headers.update(utils.random_headers(geo_spoof=self.geo_spoof))
            time.sleep(random.uniform(0.1, 0.3))
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text
                self._scan_js_content(content, url)
        except Exception:
            pass

    def _analyze_inline_js(self, content: str, base_url: str):
        if not content:
            return
        self._scan_js_content(content, "inline")

    def _scan_js_content(self, content: str, source: str):
        # DOM sinks (handles both sink() calls and sink = assignments)
        for sink in config.DOM_SINKS:
            if sink in ("innerHTML", "outerHTML"):
                pattern = rf'\b{re.escape(sink)}\s*(?:\(|=)'
            else:
                pattern = rf'\b{re.escape(sink)}\s*\('
            for match in re.finditer(pattern, content, re.IGNORECASE):
                ctx = self._get_context(content, match.start())
                self.dom_sinks_found.append({
                    "type": "dom_sink", "sink": sink, "file": source,
                    "position": match.start(), "context": ctx,
                })
        # jQuery sinks
        for sink in config.JQUERY_SINKS:
            escaped = re.escape(sink)
            for match in re.finditer(escaped, content, re.IGNORECASE):
                ctx = self._get_context(content, match.start())
                self.dom_sinks_found.append({
                    "type": "jquery_sink", "sink": sink, "file": source,
                    "position": match.start(), "context": ctx,
                })
        # Location sinks
        for sink in config.LOCATION_SINKS:
            escaped = re.escape(sink)
            for match in re.finditer(escaped, content, re.IGNORECASE):
                ctx = self._get_context(content, match.start())
                self.dom_sinks_found.append({
                    "type": "location_sink", "sink": sink, "file": source,
                    "position": match.start(), "context": ctx,
                })
        # postMessage sinks
        for match in re.finditer(r'\.postMessage\s*\(', content, re.IGNORECASE):
            ctx = self._get_context(content, match.start())
            self.dom_sinks_found.append({
                "type": "postmessage_sink", "sink": "postMessage",
                "file": source, "position": match.start(), "context": ctx,
            })
        # Sources
        for source_pattern in [
            r'(location|document\.URL|document\.documentURI|document\.baseURI)',
            r'(location\.hash|location\.search|location\.href|location\.pathname)',
            r'(document\.referrer)',
            r'(window\.name)',
            r'(document\.cookie)',
            r'(sessionStorage|localStorage)',
            r'(history\.state)',
        ]:
            for match in re.finditer(source_pattern, content, re.IGNORECASE):
                self.sources_found.append({
                    "type": "source", "source": match.group(1),
                    "file": source, "position": match.start(),
                    "context": self._get_context(content, match.start()),
                })
        # Framework detection per JS file
        for fw, patterns in config.FRAMEWORK_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    self.dom_sinks_found.append({
                        "type": "framework", "framework": fw, "file": source,
                    })

    def _get_context(self, content: str, pos: int, width=80) -> str:
        start = max(0, pos - width)
        end = min(len(content), pos + width)
        ctx = content[start:end]
        if start > 0:
            ctx = "..." + ctx
        if end < len(content):
            ctx = ctx + "..."
        return ctx

    def _classify_danger(self) -> Dict:
        high = [s for s in self.dom_sinks_found if s.get("sink") in ["eval", "innerHTML", "outerHTML", "document.write"]]
        medium = [s for s in self.dom_sinks_found if s.get("sink") in ["insertAdjacentHTML", "setTimeout", "setInterval", "Function", ".html()"]]
        return {
            "high_risk": len(high),
            "medium_risk": len(medium),
            "total": len(self.dom_sinks_found),
        }
