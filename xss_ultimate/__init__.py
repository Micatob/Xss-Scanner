from .config import (
    RESULTS_DIR, VERSION, DEFAULT_TIMEOUT, DEFAULT_DELAY, MAX_RETRIES,
    BACKOFF_FACTOR, MAX_THREADS, MAX_CRAWL_PAGES, COLLAB_PORT,
    WAF_MAX_MUTATIONS, WAF_RETRY_DELAY, GROQ_API_KEY, GROQ_MODEL,
    GROQ_BASE_URL, ENABLE_AI, AI_MAX_REQUESTS, AI_TEMPERATURE,
    AI_MAX_TOKENS, COMMON_PARAMS, COMMON_HEADERS_TO_TEST,
    DOM_SINKS, JQUERY_SINKS, LOCATION_SINKS, POSTMESSAGE_SINKS,
    STORAGE_SURFACES, USER_AGENTS, FRAMEWORK_PATTERNS,
)
from .utils import setup_session, generate_report, generate_xss_id, random_headers
from .autonomous_engine import AutonomousScanner, run_autonomous
from .captcha_bypass import CAPTCHADetector, CAPTCHASolver, create_resilient_session as create_captcha_resilient
from .resilience import (
    CircuitBreaker, ResilientRequester, AntiFingerprintManager,
    AutoThrottle, MemoryManager, CheckpointManager,
    create_resilient_session, auto_adjust_scan_parameters,
)