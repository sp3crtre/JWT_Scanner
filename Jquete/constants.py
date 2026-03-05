import os

BANNER = """

 ▄▄▄██▀▀▀█████   █    ██ ▓█████▄▄▄█████▓▓█████ 
   ▒██ ▒██▓  ██▒ ██  ▓██▒▓█   ▀▓  ██▒ ▓▒▓█   ▀ 
   ░██ ▒██▒  ██░▓██  ▒██░▒███  ▒ ▓██░ ▒░▒███   
▓██▄██▓░██  █▀ ░▓▓█  ░██░▒▓█  ▄░ ▓██▓ ░ ▒▓█  ▄ 
 ▓███▒ ░▒███▒█▄ ▒▒█████▓ ░▒████▒ ▒██▒ ░ ░▒████▒
 ▒▓▒▒░ ░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒ ░░ ▒░ ░ ▒ ░░   ░░ ▒░ ░
 ▒ ░▒░  ░ ▒░  ░ ░░▒░ ░ ░  ░ ░  ░   ░     ░ ░  ░
 ░ ░ ░    ░   ░  ░░░ ░ ░    ░    ░         ░   
 ░   ░     ░       ░        ░  ░           ░  ░
                                               
JWT vulnerability scanner
Author kurt zamora - github.com/Spectre

"""

JWT_ALGORITHMS = {
    "HS256": "HMAC-SHA256",
    "HS384": "HMAC-SHA384",
    "HS512": "HMAC-SHA512",
    "RS256": "RSA-SHA256",
    "RS384": "RSA-SHA384",
    "RS512": "RSA-SHA512",
    "ES256": "ECDSA-SHA256",
    "ES384": "ECDSA-SHA384",
    "ES512": "ECDSA-SHA512",
    "PS256": "RSA-PSS-SHA256",
    "PS384": "RSA-PSS-SHA384",
    "PS512": "RSA-PSS-SHA512",
    "none": "No signature",
}

CROSS_SYSTEM_PATTERNS = [
    r"Authorization: Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    r"access_token=[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    r"id_token=[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
]

UNKNOWN_ALG_PAYLOADS = ["zzz", "foo", "", "null", "undefined"]

TYPE_CONFUSION_CLAIMS = {
    "nbf": "malicious_string",
    "exp": "malicious_string",
    "iat": "malicious_string",
}

OAUTH2_TOKEN_ENDPOINT_PATH = "/token"

DEFAULT_WORDLISTS = {
    "weak_secrets": "/usr/share/wordlists/rockyou.txt",
    "jwks_endpoints": "/wordlist/jwks_endpoints.txt",
    "kid_traversal": "/wordlist/kid_traversal_payloads.txt",
    "kid_sql": "/wordlist/kid_sql_payloads.txt",
    "kid_cmd": "/wordlist/kid_command_payloads.txt",
    "websocket": "/wordlist/websocket_endpoints.txt",
    "polling": "/wordlist/polling_endpoints.txt",
}


def load_wordlist(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
    except FileNotFoundError:
        return []
