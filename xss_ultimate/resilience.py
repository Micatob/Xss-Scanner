import time
import random
import requests
from typing import Optional, Callable, Any
from datetime import datetime, timedelta
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config


class CircuitBreaker:
    """Circuit breaker to prevent cascading failures."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN - too many failures")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return True
        elapsed = (datetime.now() - self.last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout

    def _on_success(self):
        self.failures = 0
        self.state = "CLOSED"

    def _on_failure(self):
        self.failures += 1
        self.last_failure_time = datetime.now()
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"


class ResilientRequester:
    """HTTP requester with automatic retry, backoff, and CAPTCHA handling."""

    def __init__(self, session: requests.Session, max_retries: int = 5):
        self.session = session
        self.max_retries = max_retries
        self.circuit_breaker = CircuitBreaker(failure_threshold=10, recovery_timeout=120)
        self._setup_adapters()

    def _setup_adapters(self):
        """Configure retry adapters for the session."""
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=config.BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a request with full resilience."""
        kwargs.setdefault("timeout", config.DEFAULT_TIMEOUT)
        kwargs.setdefault("verify", False)

        try:
            def _do_request():
                return self.session.request(method, url, **kwargs)

            return self.circuit_breaker.call(_do_request)
        except Exception as e:
            # Try with fresh session state
            if self.circuit_breaker.state == "OPEN":
                print(f"  [RESILIENCE] Circuit breaker open, attempting recovery...")
                time.sleep(config.BACKOFF_FACTOR * 10)
                self.circuit_breaker.state = "HALF_OPEN"
                try:
                    return self.session.request(method, url, **kwargs)
                except Exception:
                    return None
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)


class AntiFingerprintManager:
    """Manages anti-fingerprinting to avoid bot detection."""

    def __init__(self):
        self.user_agents = list(config.USER_AGENTS)
        self.fingerprint_headers = {}
        self._rotation_index = 0

    def get_next_headers(self) -> dict:
        """Get a fresh set of rotating headers."""
        self._rotation_index = (self._rotation_index + 1) % len(self.user_agents)
        headers = {
            "User-Agent": self.user_agents[self._rotation_index],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9",
                "de-DE,de;q=0.9", "es-ES,es;q=0.8", "ja-JP,ja;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": random.choice([
                '"Chromium";v="131", "Not.A.Brand";v="99"',
                '"Google Chrome";v="131", "Not.A.Brand";v="99"',
                '"Microsoft Edge";v="131", "Not.A.Brand";v="99"',
            ]),
            "Sec-Ch-Ua-Mobile": random.choice(["?0", "?1"]),
            "Sec-Ch-Ua-Platform": random.choice([
                '"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"',
            ]),
            "Sec-Fetch-Dest": random.choice(["document", "empty"]),
            "Sec-Fetch-Mode": random.choice(["navigate", "same-origin"]),
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User": "?1",
            "DNT": random.choice(["1", "0"]),
        }

        # Add geo-spoofing headers
        forwarded = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers["X-Forwarded-For"] = forwarded
        headers["X-Real-IP"] = forwarded
        headers["X-Client-IP"] = forwarded
        headers["X-Originating-IP"] = forwarded
        headers["X-Forwarded-Host"] = f"{random.randint(1,254)}.{random.randint(1,254)}"
        headers["X-Forwarded-Proto"] = random.choice(["http", "https"])

        # Randomize header order to appear less bot-like
        self.fingerprint_headers = dict(random.sample(headers.items(), len(headers)))
        return self.fingerprint_headers

    def add_geo_spoof(self, headers: dict) -> dict:
        """Add geo-spoofing headers."""
        headers["Cf-Ipcountry"] = random.choice(["US", "GB", "DE", "CA", "AU", "NG", "JP", "BR", "IN"])
        headers["Cf-Connecting-IP"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers["X-Geo-Country"] = random.choice(["US", "GB", "DE", "CA", "AU"])
        headers["X-Geo-Continent"] = random.choice(["NA", "EU", "AS"])
        return headers


class AutoThrottle:
    """Automatically throttles requests based on server response."""

    def __init__(self, base_delay: float = 0.3):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.error_count = 0
        self.success_count = 0
        self.last_request_time = 0

    def get_delay(self) -> float:
        """Get the appropriate delay before the next request."""
        if self.error_count > 3:
            # Increase delay on errors
            self.current_delay = min(self.base_delay * (1 + self.error_count * 0.5), 5.0)
        elif self.success_count > 10:
            # Gradually decrease delay on successes
            self.current_delay = max(self.base_delay, self.current_delay * 0.95)

        return self.current_delay

    def wait(self):
        """Wait the appropriate amount of time before next request."""
        delay = self.get_delay()
        jitter = random.uniform(0, delay * 0.5)
        total_delay = delay + jitter
        time.sleep(total_delay)
        self.last_request_time = time.time()

    def on_success(self):
        self.success_count += 1
        self.error_count = max(0, self.error_count - 1)

    def on_error(self):
        self.error_count += 1
        self.success_count = max(0, self.success_count - 1)


class MemoryManager:
    """Manages memory usage during large scans."""

    def __init__(self, max_results: int = 1000):
        self.max_results = max_results
        self._results = []
        self._trimmed_count = 0

    def add_result(self, result: dict):
        """Add a result, trimming if necessary."""
        if len(self._results) >= self.max_results:
            # Keep high-confidence results
            self._results = sorted(
                self._results, key=lambda r: r.get("confidence", 0), reverse=True
            )[:self.max_results // 2]
            self._trimmed_count += 1
            print(f"  [MEMORY] Trimmed results to {len(self._results)} (trimmed {self._trimmed_count} times)")
        self._results.append(result)

    def get_results(self) -> list:
        return self._results

    def clear(self):
        self._results = []
        self._trimmed_count = 0


class CheckpointManager:
    """Manages scan checkpoints for resume capability."""

    def __init__(self, checkpoint_dir: str = "scan_checkpoints"):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)

    def save_checkpoint(self, phase: str, results: list, target_url: str):
        """Save current scan state."""
        checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "target_url": target_url,
            "results_count": len(results),
            "results": results[-100:],  # Keep last 100 results
        }
        checkpoint_file = self.checkpoint_dir / f"checkpoint_{target_url.replace(':', '_').replace('/', '_')}.json"
        try:
            import json
            with open(checkpoint_file, "w") as f:
                json.dump(checkpoint, f, indent=2, default=str)
        except Exception:
            pass

    def load_checkpoint(self, target_url: str) -> Optional[dict]:
        """Load previous scan state."""
        checkpoint_file = self.checkpoint_dir / f"checkpoint_{target_url.replace(':', '_').replace('/', '_')}.json"
        try:
            import json
            with open(checkpoint_file, "r") as f:
                return json.load(f)
        except Exception:
            return None


def create_resilient_session() -> requests.Session:
    """Create a fully resilient HTTP session."""
    session = requests.Session()
    retry_strategy = Retry(
        total=config.MAX_RETRIES,
        backoff_factor=config.BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,
        pool_maxsize=20,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    return session


def auto_adjust_scan_parameters(response: requests.Response, current_params: dict) -> dict:
    """Automatically adjust scan parameters based on server response."""
    # If rate limited, increase delay
    if response.status_code == 429:
        current_params["delay"] = min(current_params.get("delay", 0.3) * 2, 5.0)
        print(f"  [AUTO-ADJUST] Rate limited! Increasing delay to {current_params['delay']}s")

    # If WAF detected, enable aggressive mode
    if response.status_code in [403, 406]:
        current_params["aggressive_waf"] = True
        current_params["stealth"] = True
        print(f"  [AUTO-ADJUST] WAF detected! Enabling stealth and aggressive WAF mode")

    # If CAPTCHA detected, increase delay and enable stealth
    body_lower = response.text.lower() if response.text else ""
    if "captcha" in body_lower or "challenge" in body_lower:
        current_params["delay"] = min(current_params.get("delay", 0.3) * 3, 10.0)
        print(f"  [AUTO-ADJUST] CAPTCHA detected! Increasing delay significantly")

    return current_params