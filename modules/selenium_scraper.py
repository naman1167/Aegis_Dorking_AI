import time
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup

import base64
from io import BytesIO
from PIL import Image

class SeleniumScraper:
    def __init__(self, headless=True, timeout=10, rate_limit_delay=2):
        self.headless = headless
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.driver = None

    def _init_driver(self):
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1280,800")
        
        try:
            self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
        except Exception as e:
            print(f"[!] Failed to initialize Selenium Driver: {e}")

    def fetch_content(self, url):
        """
        Fetches the content of a URL using Selenium.
        Returns a dictionary with 'html', 'text', and 'screenshot'.
        """
        if not self.driver:
            self._init_driver()

        try:
            print(f"[*] Scraping: {url}")
            self.driver.get(url)
            time.sleep(self.rate_limit_delay) # Rate limiting
            
            # Capture screenshot
            screenshot_b64 = None
            try:
                screenshot = self.driver.get_screenshot_as_png()
                screenshot_b64 = base64.b64encode(screenshot).decode('utf-8')
            except Exception as e:
                print(f"[!] Screenshot failed for {url}: {e}")

            html = self.driver.page_source
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()

            text = soup.get_text(separator=' ', strip=True)
            
            return {
                "url": url,
                "html": html,
                "text": text,
                "screenshot": screenshot_b64
            }
        except Exception as e:
            print(f"[!] Error scraping {url}: {e}")
            return None

    def close(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
