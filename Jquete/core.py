import os
import json
import base64
import time
import requests
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin

from .constants import (
    DEFAULT_WORDLISTS,
    CROSS_SYSTEM_PATTERNS,
    UNKNOWN_ALG_PAYLOADS,
    TYPE_CONFUSION_CLAIMS,
    OAUTH2_TOKEN_ENDPOINT_PATH,
    load_wordlist,
)


def load_default_wordlists() -> Dict[str, List[str]]:
    return {
        "weak_secrets": load_wordlist(DEFAULT_WORDLISTS["weak_secrets"]),
        "jwks_endpoints": load_wordlist(DEFAULT_WORDLISTS["jwks_endpoints"]),
        "kid_traversal": load_wordlist(DEFAULT_WORDLISTS["kid_traversal"]),
        "kid_sql": load_wordlist(DEFAULT_WORDLISTS["kid_sql"]),
        "kid_cmd": load_wordlist(DEFAULT_WORDLISTS["kid_cmd"]),
        "websocket": load_wordlist(DEFAULT_WORDLISTS["websocket"]),
        "polling": load_wordlist(DEFAULT_WORDLISTS["polling"]),
    }


DEFAULT_WORDLIST_DATA = load_default_wordlists()


class JWTCore:
    def __init__(
        self,
        target_url: str,
        jwt_token: str,
        proxy: Optional[str] = None,
        timeout: int = 15,
        cookie_name: str = "session",
        wordlist_dir: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target_url = target_url.rstrip("/")
        self.original_token = jwt_token
        self.proxy = proxy
        self.timeout = timeout
        self.cookie_name = cookie_name
        self.wordlist_dir = wordlist_dir
        self.verbose = verbose

        self.session = self._create_session()

        self.header: Dict = {}
        self.payload: Dict = {}
        self.signature: str = ""

        self._parse_token()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "Mozilla 5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
            }
        )
        session.verify = False
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        return session

    def _parse_token(self) -> bool:
        try:
            parts = self.original_token.split(".")
            if len(parts) != 3:
                return False

            header_data = parts[0] + "=="
            payload_data = parts[1] + "=="

            self.header = json.loads(base64.urlsafe_b64decode(header_data))
            self.payload = json.loads(base64.urlsafe_b64decode(payload_data))
            self.signature = parts[2]
            return True
        except Exception:
            return False

    def make_request(
        self,
        url: str,
        token: str = None,
        method: str = "GET",
        data: Dict = None,
        follow_redirects: bool = True,
        delay: float = 0,
    ) -> requests.Response:
        time.sleep(delay)
        cookies = {}
        if token:
            cookies[self.cookie_name] = token

        for attempt in range(3):
            try:
                if method.upper() == "GET":
                    response = self.session.get(
                        url,
                        cookies=cookies,
                        timeout=self.timeout,
                        allow_redirects=follow_redirects,
                    )
                else:
                    response = self.session.post(
                        url,
                        cookies=cookies,
                        data=data,
                        timeout=self.timeout,
                        allow_redirects=follow_redirects,
                    )
                return response
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    raise
                time.sleep(1 * (attempt + 1))

    def get_host(self) -> str:
        parsed = urlparse(self.target_url)
        return parsed.netloc


def load_wordlist_file(filepath: str, default_list: List[str]) -> List[str]:
    if not filepath:
        return default_list

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        return default_list
    except Exception:
        return default_list


class WordlistLoader:
    def __init__(self, wordlist_dir: Optional[str], verbose: bool = False):
        self.wordlist_dir = wordlist_dir
        self.verbose = verbose

    def load(self, filename: str, default_key: str) -> List[str]:
        if not self.wordlist_dir:
            return DEFAULT_WORDLIST_DATA.get(default_key, [])

        filepath = os.path.join(self.wordlist_dir, filename)
        return load_wordlist_file(filepath, DEFAULT_WORDLIST_DATA.get(default_key, []))
