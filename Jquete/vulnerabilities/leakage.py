import re
import json
import time
from urllib.parse import urljoin, urlparse

from ..enums import _kurtVuln_list
from ..models import jq_vuln_list
from ..constants import CROSS_SYSTEM_PATTERNS


def test_websocket_event_leak(scanner) -> None:
    from colorama import Fore, Style
    import websocket

    print(f"\n{Fore.YELLOW}[*] Testing WebSocket event leak...{Style.RESET_ALL}")

    if not scanner.websocket_check:
        return

    parsed = urlparse(scanner.target_url)
    ws_base = (
        f"ws://{parsed.netloc}" if parsed.scheme == "http" else f"wss://{parsed.netloc}"
    )

    for endpoint in scanner.websocket_endpoints:
        ws_url = ws_base + endpoint
        try:
            ws = websocket.create_connection(ws_url, timeout=5)
            ws.settimeout(3)
            messages = []
            start = time.time()
            while time.time() - start < 5:
                try:
                    msg = ws.recv()
                    data = json.loads(msg)
                    if (
                        "ACCESS_REQUEST" in str(data)
                        or "requestId" in str(data)
                        or "token" in str(data)
                    ):
                        messages.append(msg)
                except:
                    break
            ws.close()

            if messages:
                vuln = jq_vuln_list(
                    type=_kurtVuln_list.WEBSOCKET_INFO_LEAK,
                    severity="HIGH",
                    description=f"WebSocket endpoint {ws_url} leaks sensitive events",
                    exploit_payload=ws_url,
                    proof=f"Messages: {messages[0][:200]}",
                    endpoint=ws_url,
                    chainable_with=[_kurtVuln_list.UNAUTH_TOKEN_POLLING],
                    cve_reference="CVE-2025-68620",
                    cvss_score=7.5,
                )
                scanner.vulnerabilities.append(vuln)
                print(
                    f"{Fore.RED}[!] WebSocket event leak detected at {ws_url}{Style.RESET_ALL}"
                )
                return
        except Exception as e:
            if scanner.verbose:
                print(
                    f"{Fore.RED}[DEBUG] WebSocket {ws_url} error: {e}{Style.RESET_ALL}"
                )
            continue

    print(f"{Fore.GREEN}[-] No WebSocket event leak detected{Style.RESET_ALL}")


def test_unauth_token_polling(scanner) -> None:
    from colorama import Fore, Style

    print(
        f"\n{Fore.YELLOW}[*] Testing unauthenticated token polling...{Style.RESET_ALL}"
    )

    dummy_id = "test123"
    for template in scanner.polling_endpoints:
        url = urljoin(scanner.target_url, template.format(dummy_id))
        try:
            response = scanner.session.get(url, timeout=scanner.timeout)
            if response.status_code == 200:
                data = response.json()
                if (
                    "token" in str(data)
                    or "jwt" in str(data)
                    or "accessToken" in str(data)
                ):
                    vuln = jq_vuln_list(
                        type=_kurtVuln_list.UNAUTH_TOKEN_POLLING,
                        severity="CRITICAL",
                        description=f"Unauthenticated token polling at {template}",
                        exploit_payload=url,
                        proof=f"HTTP 200 response containing token fields",
                        endpoint=url,
                        chainable_with=[_kurtVuln_list.WEBSOCKET_INFO_LEAK],
                        cve_reference="CVE-2025-68620",
                        cvss_score=9.1,
                    )
                    scanner.vulnerabilities.append(vuln)
                    print(
                        f"{Fore.RED}[!] Unauthenticated token polling endpoint: {template}{Style.RESET_ALL}"
                    )
                    return
        except Exception:
            continue

    print(f"{Fore.GREEN}[-] No unauthenticated polling found{Style.RESET_ALL}")


def test_cross_system_leakage(scanner) -> None:
    from colorama import Fore, Style

    print(f"\n{Fore.YELLOW}[*] Testing cross-system leakage...{Style.RESET_ALL}")

    try:
        response = scanner.session.get(scanner.target_url, timeout=scanner.timeout)
        text = response.text
        for pattern in CROSS_SYSTEM_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                for match in matches:
                    parts = match.split(".")
                    if len(parts) == 3:
                        vuln = jq_vuln_list(
                            type=_kurtVuln_list.CROSS_SYSTEM_LEAKAGE,
                            severity="HIGH",
                            description="JWT token leaked in response (possible cross-system exposure)",
                            exploit_payload=match[:50],
                            proof=f"Found in response body",
                            endpoint=scanner.target_url,
                            chainable_with=[],
                            cvss_score=7.0,
                        )
                        scanner.vulnerabilities.append(vuln)
                        print(
                            f"{Fore.RED}[!] JWT token leaked in response!{Style.RESET_ALL}"
                        )
                        return
    except Exception as e:
        if scanner.verbose:
            print(f"{Fore.RED}[ERROR] Cross-system test failed: {e}{Style.RESET_ALL}")
