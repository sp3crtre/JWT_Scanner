import sys
import argparse
from .scanner import Jquete
from .constants import BANNER


def main():
    parser = argparse.ArgumentParser(
        description="JWT jq_vuln_list jq_scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m jqute -u https://target.com/admin --jwt eyJhbGc... --level 3 --chains
  python -m jqute -u https://target.com/api --jwt YOUR_JWT --proxy http://127.0.0.1:8080 --verbose
        """,
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target URL (e.g., https://target.com/admin)"
    )
    parser.add_argument("--jwt", required=True, help="JWT token to test")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument(
        "--level",
        type=int,
        default=1,
        choices=[1, 2, 3, 4],
        help="Test level (1-4, default 1)",
    )
    parser.add_argument(
        "--risk",
        type=int,
        default=1,
        choices=[1, 2, 3],
        help="Risk level (1-3, default 1)",
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Number of threads (default 10)"
    )
    parser.add_argument(
        "--delay", type=float, default=0, help="Delay between requests (seconds)"
    )
    parser.add_argument(
        "--timeout", type=int, default=15, help="Request timeout (seconds)"
    )
    parser.add_argument(
        "--cookie-name",
        default="session",
        help="Cookie name for JWT (default: session)",
    )
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument(
        "--chains", action="store_true", help="Enable attack chain detection"
    )
    parser.add_argument(
        "--cross-domain", action="store_true", help="Enable cross-domain leakage tests"
    )
    parser.add_argument(
        "--websocket", action="store_true", default=True, help="Enable WebSocket tests"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--batch", action="store_true", help="Batch mode (never ask for user input)"
    )
    parser.add_argument("--wordlist", "-w", help="Directory containing wordlist files")

    parser.add_argument(
        "--exploit",
        action="store_true",
        help="Attempt exploitation of found vulnerabilities",
    )
    parser.add_argument(
        "--target-endpoint", help="URL to test exploitation (default: same as --url)"
    )
    parser.add_argument(
        "--impersonate",
        default="sub=admin",
        help='Claims to impersonate, e.g., "sub=admin,admin=true" or JSON',
    )

    args = parser.parse_args()

    try:
        scanner = Jquete(
            target_url=args.url,
            jwt_token=args.jwt,
            proxy=args.proxy,
            level=args.level,
            risk=args.risk,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            cookie_name=args.cookie_name,
            output=args.output,
            chains=args.chains,
            cross_domain=args.cross_domain,
            websocket=args.websocket,
            verbose=args.verbose,
            batch=args.batch,
            wordlist_dir=args.wordlist,
            exploit=args.exploit,
            target_endpoint=args.target_endpoint,
            impersonate=args.impersonate,
        )
        scanner.scan_all()

    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
