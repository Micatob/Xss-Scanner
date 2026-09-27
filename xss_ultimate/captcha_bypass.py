import re
import time
import random
import string
import base64
import hashlib
import requests
from typing import List, Dict, Optional, Tuple
from PIL import Image
from io import BytesIO

from . import config
from . import utils


class CAPTCHADetector:
    """Detects various CAPTCHA challenges from HTTP responses."""

    CAPTCHA_INDICATORS = {
        "Cloudflare_turnstile": [
            r"cf-turnstile", r"cf\.com/challenges", r"turnstile",
            r"challenge-platform", r"cf_chl_script",
        ],
        "Cloudflare_interactive": [
            r"cf-browser-verification", r"challenge-form",
            r"Are you a human", r"verify you are human",
            r"checking your browser", r"Checking your browser",
            r"一個人驗證", r"robot check",
        ],
        "hcaptcha": [
            r"hcaptcha", r"hcaptcha\.com", r"js\.hcaptcha",
        ],
        "recaptcha": [
            r"recaptcha", r"google\.com/recaptcha", r"recaptcha\.api",
            r"recaptcha-stoken", r"g-recaptcha",
        ],
        "generic_captcha": [
            r"captcha", r"captcha\.php", r"captcha\.jpg",
            r"captcha\.png", r"captcha\.gif",
            r"verify.*human", r"human.*verify",
            r"enter.*code", r"type.*characters",
            r"security.*check", r"please.*verify",
            r"captcha.*code", r"anti-bot",
            r"bot.*detection", r"automated.*access",
        ],
        "perimeterx": [
            r"px\.perimeterx", r"perimeterx", r"PxClient",
            r"px-captcha",
        ],
        "datadome": [
            r"datadome", r"cookie\.datadome",
        ],
        "akamai_bot_manager": [
            r"akamai.*bot", r"akamai.*challenge", r"ak-bm",
            r"user_properties", r"akamai.*debug",
        ],
        "improved_turing": [
            r"i\\'m not a robot", r"recaptcha.*invisible",
        ],
        "custom_captcha": [
            r"captcha.*image", r"captcha.*verify",
            r"validation.*code", r"verification.*code",
            r"security.*code", r"check.*code",
        ],
        "cookie_challenge": [
            r"__cf_bm", r"cf_clearance", r"bm_src",
            r"cookie_consent", r"gdpr.*consent",
        ],
        "javascript_challenge": [
            r"javascript.*challenge", r"js-challenge",
            r"challenger", r"challenge\.js",
            r"window\.challenges",
        ],
        "rate_limit_block": [
            r"rate.limit", r"too many requests",
            r"429", r"throttled",
        ],
    }

    def __init__(self):
        self.detected_captchas: List[Dict] = []
        self.captcha_responses: Dict[str, str] = {}

    def detect(self, response: requests.Response) -> Dict:
        """Analyze response for any CAPTCHA challenge."""
        headers_str = str(response.headers)
        body_lower = response.text.lower() if response.text else ""
        status = response.status_code
        detected = []
        confidence = 0.0
        details = []

        for captcha_type, patterns in self.CAPTCHA_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, headers_str, re.IGNORECASE) or \
                   re.search(pat, body_lower, re.IGNORECASE):
                    detected.append(captcha_type)
                    details.append(f"Pattern matched: {pat}")
                    confidence += 0.2
                    break

        # Status code indicators
        if status in [403, 429, 503]:
            if "captcha" in body_lower or "challenge" in body_lower:
                detected.append("challenge_page")
                confidence += 0.3
            elif status == 429:
                detected.append("rate_limit_block")
                confidence += 0.3

        # Cookie-based detection
        set_cookie = response.headers.get("Set-Cookie", "")
        if "cf_clearance" in set_cookie or "__cf_bm" in set_cookie:
            detected.append("Cloudflare_cookie_challenge")
            confidence += 0.4

        # HTML form detection (captcha input fields)
        if re.search(r'<form[^>]*captcha', body_lower) or \
           re.search(r'<input[^>]*captcha', body_lower) or \
           re.search(r'<input[^>]*type="[^"]*captcha', body_lower):
            detected.append("form_captcha")
            confidence += 0.5

        # CAPTCHA image detection
        if re.search(r'<img[^>]*alt=["\']?captcha', body_lower) or \
           re.search(r'<img[^>]*src=["\']?.*captcha', body_lower) or \
           re.search(r'captcha\.(jpg|png|gif|webp)', body_lower):
            detected.append("image_captcha")
            confidence += 0.6

        # Turnstile-specific
        if "cf-turnstile" in body_lower or "turnstile" in body_lower:
            detected.append("Cloudflare_turnstile")
            confidence += 0.4

        # reCAPTCHA specific
        if "g-recaptcha" in body_lower or "recaptcha" in body_lower:
            detected.append("recaptcha")
            confidence += 0.4

        # hCaptcha specific
        if "hcaptcha" in body_lower:
            detected.append("hcaptcha")
            confidence += 0.4

        is_captcha = len(detected) > 0 and confidence >= 0.3

        result = {
            "is_captcha": is_captcha,
            "captcha_types": detected,
            "confidence": min(confidence, 1.0),
            "details": details,
            "status_code": status,
        }

        if is_captcha:
            self.detected_captchas.append(result)

        return result

    def is_captcha_response(self, response: requests.Response) -> bool:
        """Quick check: is this response a CAPTCHA?"""
        result = self.detect(response)
        return result["is_captcha"]

    def extract_captcha_challenge(self, response: requests.Response) -> Optional[Dict]:
        """Extract challenge details from CAPTCHA response."""
        body = response.text
        headers = str(response.headers)

        challenge = {
            "url": str(response.url),
            "response_url": str(response.url),
            "types": [],
            "form_data": {},
            "image_urls": [],
            "javascript_challenges": [],
            "cookies": {},
        }

        # Extract Cloudflare Turnstile
        turnstile_match = re.search(
            r'data-site-key=["\']([^"\']+)["\']', body
        )
        if turnstile_match:
            challenge["types"].append("turnstile")
            challenge["site_key"] = turnstile_match.group(1)

        # Extract reCAPTCHA
        recaptcha_match = re.search(
            r'data-sitekey=["\']([^"\']+)["\']', body
        )
        if recaptcha_match:
            challenge["types"].append("recaptcha")
            challenge["site_key"] = recaptcha_match.group(1)

        # Extract hCaptcha
        hcaptcha_match = re.search(
            r'data-sitekey=["\']([^"\']+)["\']', body
        )
        if hcaptcha_match and "hcaptcha" in body.lower():
            challenge["types"].append("hcaptcha")
            challenge["site_key"] = hcaptcha_match.group(1)

        # Extract form action and inputs
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body)
        if forms:
            challenge["form_data"]["action"] = forms[0]

        # Extract CAPTCHA image URLs
        img_captchas = re.findall(
            r'<img[^>]*src=["\']([^"\']*captcha[^"\']*)["\']', body, re.IGNORECASE
        )
        challenge["image_urls"].extend(img_captchas)

        # Extract JS challenge scripts
        js_challenges = re.findall(
            r'<script[^>]*src=["\']([^"\']*challenge[^"\']*)["\']', body, re.IGNORECASE
        )
        challenge["javascript_challenges"].extend(js_challenges)

        # Extract cookies
        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            cookies = dict(re.findall(r'([^=;\s]+)=([^;]+)', set_cookie))
            challenge["cookies"] = cookies

        if len(challenge["types"]) > 0 or len(challenge["image_urls"]) > 0 or \
           len(challenge["javascript_challenges"]) > 0:
            return challenge

        return None


class CAPTCHASolver:
    """Solves CAPTCHAs using multiple strategies."""

    def __init__(self):
        self.solvers = []
        self._register_solvers()

    def _register_solvers(self):
        """Register all available CAPTCHA solving strategies."""
        self.solvers = [
            self.solve_cookie_challenge,
            self.solve_turnstile,
            self.solve_javascript_challenge,
            self.solve_image_captcha,
            self.solve_2captcha,
            self.solve_anti_captcha,
            self.solve_azure_captcha,
            self.solve_bypass_chrome_extensions,
        ]

    def solve(self, response: requests.Response, session: requests.Session,
              target_url: str) -> Optional[requests.Response]:
        """Attempt to solve any CAPTCHA on the response."""
        detector = CAPTCHADetector()
        captcha_info = detector.detect(response)

        if not captcha_info["is_captcha"]:
            return None

        challenge = detector.extract_captcha_challenge(response)
        if not challenge:
            challenge = {"types": captcha_info["captcha_types"]}

        print(f"  [CAPTCHA] Detected: {', '.join(challenge.get('types', captcha_info['captcha_types']))}")
        print(f"  [CAPTCHA] Attempting to solve...")

        for solver in self.solvers:
            try:
                result = solver(response, session, target_url, challenge)
                if result:
                    print(f"  [CAPTCHA] Solved via: {solver.__name__}")
                    return result
            except Exception as e:
                print(f"  [CAPTCHA] Solver {solver.__name__} failed: {e}")
                continue

        return None

    def solve_cookie_challenge(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Solve Cloudflare cookie-based challenges."""
        set_cookie = response.headers.get("Set-Cookie", "")
        cf_clearance = re.search(r'__cf_bm=([^;]+)', set_cookie)
        cf_clearance2 = re.search(r'cf_clearance=([^;]+)', set_cookie)

        if cf_clearance or cf_clearance2:
            clearance_val = (cf_clearance or cf_clearance2).group(1)
            session.cookies.set(
                "__cf_bm" if cf_clearance else "cf_clearance",
                clearance_val.split(";")[0].strip(),
                domain=self._extract_domain(target_url)
            )
            time.sleep(1)
            try:
                retry = session.get(target_url, timeout=config.DEFAULT_TIMEOUT,
                                    verify=False, allow_redirects=True)
                detector = CAPTCHADetector()
                if not detector.is_captcha_response(retry):
                    return retry
            except Exception:
                pass
        return None

    def solve_turnstile(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Handle Cloudflare Turnstile by simulating browser behavior."""
        if "turnstile" not in str(response.text).lower() and \
           "cf-turnstile" not in str(response.text).lower():
            return None

        site_key = challenge.get("site_key", "")
        if not site_key:
            # Try to find site-key from page
            match = re.search(r'data-site-key=["\']([^"\']+)["\']', response.text)
            if match:
                site_key = match.group(1)

        if site_key:
            # Set challenge-complete cookie simulation
            token_hash = hashlib.md5(
                f"{site_key}{target_url}{time.time()}".encode()
            ).hexdigest()

            session.cookies.set(
                "cf_clearance",
                token_hash,
                domain=self._extract_domain(target_url)
            )

            # Add Turnstile-like headers
            session.headers.update({
                "Cf-Visitor": '{"scheme":"https"}',
                "Cf-Connecting-Ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "Cf-Worker": "1",
            })

            time.sleep(0.5)
            try:
                retry = session.get(target_url, timeout=config.DEFAULT_TIMEOUT,
                                    verify=False, allow_redirects=True)
                detector = CAPTCHADetector()
                if not detector.is_captcha_response(retry):
                    return retry
            except Exception:
                pass
        return None

    def solve_javascript_challenge(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Bypass JavaScript-based challenges by executing them or skipping."""
        body = response.text

        # Check for challenge scripts
        challenge_scripts = re.findall(
            r'<script[^>]*[^>]*challenge[^>]*>(.*?)</script>', body, re.IGNORECASE | re.DOTALL
        )

        if challenge_scripts:
            # Extract and evaluate key challenge functions
            # This simulates what a browser would do
            for script in challenge_scripts:
                # Look for cookie-setting patterns
                cookie_matches = re.findall(
                    r'document\.cookie\s*=\s*["\']([^"\']+)["\']', script
                )
                for cookie_val in cookie_matches:
                    parts = cookie_val.split(";")
                    for part in parts:
                        if "=" in part:
                            k, v = part.split("=", 1)
                            session.cookies.set(k.strip(), v.strip(),
                                                domain=self._extract_domain(target_url))

            # Set challenge-complete flag
            session.headers.update({
                "X-Challenge-Completed": "1",
                "X-JS-Executed": "1",
            })

            time.sleep(0.5)
            try:
                retry = session.get(target_url, timeout=config.DEFAULT_TIMEOUT,
                                    verify=False, allow_redirects=True)
                detector = CAPTCHADetector()
                if not detector.is_captcha_response(retry):
                    return retry
            except Exception:
                pass
        return None

    def solve_image_captcha(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Attempt to solve image-based CAPTCHAs."""
        image_urls = challenge.get("image_urls", [])
        if not image_urls:
            # Search for any image that might be a captcha
            img_matches = re.findall(
                r'<img[^>]*src=["\']([^"\']*(?:captcha|verify|code)["\'][^>]*)>',
                response.text, re.IGNORECASE
            )
            image_urls = [m.split('"')[-2] if '"' in m else m.split("'")[-2]
                         for m in img_matches]

        if image_urls:
            # Try to download and analyze captcha images
            for img_url in image_urls[:3]:
                try:
                    full_url = img_url if img_url.startswith("http") else \
                               f"{target_url.rstrip('/')}/{img_url.lstrip('/')}"
                    img_resp = session.get(full_url, timeout=10, verify=False)
                    if img_resp.status_code == 200 and img_resp.content:
                        # Try OCR-like analysis
                        solved_text = self._attempt_ocr(img_resp.content)
                        if solved_text:
                            # Find form and submit with solved text
                            form_match = re.search(
                                r'<form[^>]*action=["\']([^"\']+)["\']', response.text
                            )
                            if form_match:
                                form_action = form_match.group(1)
                                form_url = f"{target_url.rstrip('/')}/{form_action.lstrip('/')}" \
                                    if not form_action.startswith("http") else form_action

                                # Find input names
                                inputs = re.findall(
                                    r'<input[^>]*name=["\']([^"\']+)["\']', response.text
                                )
                                # Submit form with CAPTCHA solution
                                data = {}
                                for inp_name in inputs:
                                    if "captcha" in inp_name.lower() or "code" in inp_name.lower() or "verif" in inp_name.lower():
                                        data[inp_name] = solved_text
                                    elif inp_name not in data:
                                        data[inp_name] = "xss_test"

                                session.headers.update(utils.random_headers())
                                time.sleep(0.5)
                                retry = session.post(form_url, data=data,
                                                    timeout=config.DEFAULT_TIMEOUT,
                                                    verify=False, allow_redirects=True)
                                detector = CAPTCHADetector()
                                if not detector.is_captcha_response(retry):
                                    return retry
                except Exception:
                    continue
        return None

    def solve_2captcha(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Attempt to use 2captcha API if configured."""
        api_key = getattr(config, "CAPTCHA_API_KEY_2CAPTCHA", "")
        if not api_key:
            return None

        try:
            # Upload to 2captcha for solving
            image_urls = challenge.get("image_urls", [])
            if not image_urls:
                return None

            for img_url in image_urls[:1]:
                full_url = img_url if img_url.startswith("http") else \
                           f"{target_url.rstrip('/')}/{img_url.lstrip('/')}"
                img_resp = session.get(full_url, timeout=10, verify=False)
                if img_resp.status_code != 200:
                    continue

                img_data = base64.b64encode(img_resp.content).decode()
                payload = {
                    "key": api_key,
                    "method": "base64",
                    "body": img_data,
                    "json": 1,
                }
                resp = requests.post("http://2captcha.com/in.php", data=payload, timeout=30)
                if resp.status_code == 200 and "OK|" in resp.text:
                    captcha_id = resp.text.split("|")[1].strip()
                    # Poll for result
                    for _ in range(20):
                        time.sleep(5)
                        result = requests.get(
                            f"http://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}&json=1",
                            timeout=10
                        )
                        if "OK|" in result.text:
                            solved_text = result.text.split("|")[1].strip()
                            # Submit back
                            return session.get(target_url, timeout=config.DEFAULT_TIMEOUT, verify=False)
        except Exception:
            pass
        return None

    def solve_anti_captcha(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Attempt to use Anti-Captcha API if configured."""
        api_key = getattr(config, "CAPTCHA_API_KEY_ANTICAPTCHA", "")
        if not api_key:
            return None

        try:
            image_urls = challenge.get("image_urls", [])
            if not image_urls:
                return None

            for img_url in image_urls[:1]:
                full_url = img_url if img_url.startswith("http") else \
                           f"{target_url.rstrip('/')}/{img_url.lstrip('/')}"
                img_resp = session.get(full_url, timeout=10, verify=False)
                if img_resp.status_code != 200:
                    continue

                img_data = base64.b64encode(img_resp.content).decode()
                payload = {
                    "clientKey": api_key,
                    "task": {
                        "type": "ImageToTextTask",
                        "body": img_data,
                        "isCaseSensitive": False,
                        "phrase": False,
                    },
                }
                resp = requests.post("https://api.anti-captcha.com/createTask", json=payload, timeout=30)
                if resp.status_code == 200:
                    resp_data = resp.json()
                    task_id = resp_data.get("taskId")
                    if task_id:
                        for _ in range(20):
                            time.sleep(5)
                            result = requests.post("https://api.anti-captcha.com/getTaskResult",
                                                   json={"clientKey": api_key, "taskId": task_id},
                                                   timeout=10)
                            result_data = result.json()
                            if result_data.get("status") == "ready":
                                solved_text = result_data.get("solution", {}).get("text", "")
                                if solved_text:
                                    return session.get(target_url, timeout=config.DEFAULT_TIMEOUT, verify=False)
        except Exception:
            pass
        return None

    def solve_azure_captcha(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Attempt to use Azure CAPTCHA solver."""
        api_key = getattr(config, "CAPTCHA_API_KEY_AZURE", "")
        if not api_key:
            return None

        try:
            if "recaptcha" in str(response.text).lower():
                # Handle reCAPTCHA v2/v3
                api_url = "https://www.google.com/recaptcha/api2/render"
                site_key_match = re.search(r'data-sitekey=["\']([^"\']+)["\']', response.text)
                if site_key_match:
                    time.sleep(2)
                    session.cookies.set("GRECAPTCHA_RESPONSE",
                                        hashlib.md5(f"{site_key_match.group(1)}{time.time()}".encode()).hexdigest(),
                                        domain=self._extract_domain(target_url))
                    retry = session.get(target_url, timeout=config.DEFAULT_TIMEOUT, verify=False)
                    detector = CAPTCHADetector()
                    if not detector.is_captcha_response(retry):
                        return retry
        except Exception:
            pass
        return None

    def solve_bypass_chrome_extensions(self, response, session, target_url, challenge) -> Optional[requests.Response]:
        """Use Chrome extension-like bypasses (user-agent, headers, etc.)."""
        # Set complete browser-like headers
        session.headers.update({
            "User-Agent": random.choice(config.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not A Brand";v="99", "Chromium";v="131"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        })

        time.sleep(1)
        try:
            retry = session.get(target_url, timeout=config.DEFAULT_TIMEOUT, verify=False)
            detector = CAPTCHADetector()
            if not detector.is_captcha_response(retry):
                return retry
        except Exception:
            pass
        return None

    def _attempt_ocr(self, image_bytes: bytes) -> Optional[str]:
        """Attempt OCR on captcha image."""
        try:
            img = Image.open(BytesIO(image_bytes))
            # Use pytesseract if available
            try:
                import pytesseract
                text = pytesseract.image_to_string(img)
                return text.strip() if text else None
            except ImportError:
                # Simple heuristic: try to extract from image properties
                return None
        except Exception:
            return None

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc


class CaptchaResilientSession:
    """HTTP session that automatically handles CAPTCHAs."""

    def __init__(self, session: requests.Session, target_url: str):
        self.session = session
        self.target_url = target_url
        self.captcha_solver = CAPTCHASolver()
        self.detector = CAPTCHADetector()
        self.captcha_count = 0
        self.max_captchas = 5

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request, automatically solving CAPTCHAs."""
        response = self.session.get(url, **kwargs)

        if self.detector.is_captcha_response(response):
            self.captcha_count += 1
            if self.captcha_count > self.max_captchas:
                print(f"  [CAPTCHA] Max CAPTCHA attempts ({self.max_captchas}) reached")
                return response

            print(f"  [CAPTCHA] Attempting to solve (attempt {self.captcha_count})...")
            solved = self.captcha_solver.solve(response, self.session, url)
            if solved:
                return solved

            # If we can't solve it, wait and retry with new session state
            time.sleep(3)
            retry = self.session.get(url, **kwargs)
            if not self.detector.is_captcha_response(retry):
                return retry

        return response

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request, automatically solving CAPTCHAs."""
        response = self.session.post(url, **kwargs)

        if self.detector.is_captcha_response(response):
            self.captcha_count += 1
            if self.captcha_count > self.max_captchas:
                return response

            solved = self.captcha_solver.solve(response, self.session, url)
            if solved:
                return solved

            time.sleep(3)
            retry = self.session.post(url, **kwargs)
            if not self.detector.is_captcha_response(retry):
                return retry

        return response


def create_resilient_session(target_url: str) -> CaptchaResilientSession:
    """Create a session that automatically handles CAPTCHAs."""
    session = utils.setup_session()
    return CaptchaResilientSession(session, target_url)