import json
import os
import subprocess
import sys
import time
import tempfile
import threading
from typing import Dict, Optional, List

from . import config


class HeadlessVerifier:
    def __init__(self, browser_type: str = "auto"):
        self.browser_type = browser_type
        self.available = self._check_available()

    def _check_available(self) -> bool:
        for cmd in ["playwright", "selenium", "chromium-browser", "google-chrome"]:
            try:
                subprocess.run([cmd, "--version"], capture_output=True, timeout=5, shell=True)
                return True
            except Exception:
                pass
        try:
            import playwright
            return True
        except ImportError:
            pass
        try:
            import selenium
            return True
        except ImportError:
            pass
        return False

    def verify_xss(self, url: str, payload: str, expected_alert: str = "1") -> Dict:
        if not self.available:
            return {"verified": False, "method": "none", "reason": "No browser automation available"}
        # Try Playwright first, then Selenium
        result = self._try_playwright(url, expected_alert)
        if not result.get("verified"):
            result = self._try_selenium(url, expected_alert)
        return result

    def _try_playwright(self, url: str, expected_alert: str) -> Dict:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"verified": False, "method": "playwright", "reason": "Playwright not installed"}
        try:
            alert_detected = threading.Event()
            alert_text = []

            def handle_dialog(dialog):
                alert_text.append(dialog.message)
                alert_detected.set()
                dialog.accept()

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.on("dialog", handle_dialog)
                try:
                    page.goto(url, timeout=10000, wait_until="networkidle")
                    detected = alert_detected.wait(timeout=5)
                    browser.close()
                    if detected and expected_alert in alert_text:
                        return {"verified": True, "method": "playwright", "alert": alert_text[0]}
                    if detected:
                        return {"verified": True, "method": "playwright", "alert": alert_text[0]}
                except Exception:
                    browser.close()
                    return {"verified": False, "method": "playwright", "reason": "Navigation failed"}
        except Exception as e:
            return {"verified": False, "method": "playwright", "reason": str(e)}


    def _try_selenium(self, url: str, expected_alert: str) -> Dict:
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
        except ImportError:
            return {"verified": False, "method": "selenium", "reason": "Selenium not installed"}
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--ignore-certificate-errors")
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            try:
                alert = WebDriverWait(driver, 5).until(EC.alert_is_present())
                text = alert.text
                alert.accept()
                driver.quit()
                return {"verified": True, "method": "selenium", "alert": text}
            except Exception:
                driver.quit()
                return {"verified": False, "method": "selenium", "reason": "No alert detected"}
        except Exception as e:
            return {"verified": False, "method": "selenium", "reason": str(e)}

    def execute_payload_js(self, url: str, js_code: str) -> Dict:
        if not self.available:
            return {"success": False, "reason": "No browser"}
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(ignore_https_errors=True)
                page.goto(url, timeout=10000, wait_until="domcontentloaded")
                result = page.evaluate(js_code)
                browser.close()
                return {"success": True, "result": str(result)[:500]}
        except Exception as e:
            return {"success": False, "reason": str(e)}

    def capture_screenshot(self, url: str) -> Optional[bytes]:
        if not self.available:
            return None
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(ignore_https_errors=True)
                page.goto(url, timeout=10000)
                screenshot = page.screenshot(full_page=True)
                browser.close()
                return screenshot
        except Exception:
            return None
