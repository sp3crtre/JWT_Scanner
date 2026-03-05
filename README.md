# JWT Scanner

A comprehensive JWT vulnerability scanner with attack chain detection and exploitation capabilities.

## Installation

```bash
pip install pyjwt requests colorama cryptography websocket-client
```

## Basic Usage

```bash
python python -m jwtscanner -u <target_url> --jwt <jwt_token>
```

## Usage
```bash
python python -m jwtscanner -h
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL (e.g., `https://target.com/admin`) | Required |
| `--jwt` | JWT token to test | Required |
| `-p, --proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | None |
| `--level` | Test level (1-4) | 1 |
| `--risk` | Risk level (1-3) | 1 |
| `--threads` | Number of threads | 10 |
| `--delay` | Delay between requests (seconds) | 0 |
| `--timeout` | Request timeout (seconds) | 15 |
| `--cookie-name` | Cookie name for JWT | session |
| `-o, --output` | Output file for results (JSON) | None |
| `--chains` | Enable attack chain detection | False |
| `--cross-domain` | Enable cross-domain leakage tests | False |
| `--websocket` | Enable WebSocket tests | True |
| `-v, --verbose` | Verbose output | False |
| `--batch` | Batch mode (no user prompts) | False |
| `--wordlist-dir` | Directory with wordlist files | None |
| `--exploit` | Attempt exploitation | False |
| `--target-endpoint` | URL to test exploitation | Same as --url |
| `--impersonate` | Claims to impersonate | sub=admin |

## Test Levels

- **Level 1**: None algorithm, signature removal, expiration, audience/issuer, unknown algorithm tests
- **Level 2**: + Weak secret, algorithm confusion, JKU/JWK injection tests
- **Level 3**: + KID injection, JWKS cache poisoning, WebSocket, token polling, claim type confusion tests
- **Level 4**: All tests (currently same as Level 3)

## Detected Vulnerabilities

- None Algorithm (CVE-2015-9235)
- Weak Secret
- Algorithm Confusion (CVE-2016-10555, CVE-2024-54150)
- JKU Injection (CVE-2018-0114)
- JWK Injection
- KID Path Traversal
- KID SQL Injection
- KID Command Injection
- Signature Removal
- Public Key Exposure
- JWKS Cache Poisoning (CVE-2025-59936)
- WebSocket Info Leak (CVE-2025-68620)
- Unauthenticated Token Polling (CVE-2025-68620)
- Cross-System Leakage
- Unknown Algorithm Bypass (CVE-2026-23993)
- Expiration Missing/Too Long
- Audience/Issuer Validation Bypass
- Claim Type Confusion (CVE-2026-25537)
- JWK Missing Alg Confusion (CVE-2026-22818)

## Examples

### Basic Scan

```bash
python python -m jwtscanner -u https://target.com/api --jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Full Scan with Attack Chains

```bash
python python -m jwtscanner -u https://target.com/admin --jwt <token> --level 3 --risk 3 --chains
```

### Scan with Exploitation

```bash
python python -m jwtscanner -u https://target.com/admin --jwt <token> --exploit --impersonate "sub=admin,role=admin"
```

### Scan with Proxy

```bash
python python -m jwtscanner -u https://target.com/api --jwt <token> --proxy http://127.0.0.1:8080 --verbose
```

### Output to JSON

```bash
python python -m jwtscanner -u https://target.com/api --jwt <token> -o results.json
```

## Wordlist Support

Custom wordlists can be used via `--wordlist-dir`. Expected files:

- `weak_secrets.txt` - HMAC secrets to test
- `jwks_endpoints.txt` - JWKS endpoint paths
- `kid_traversal.txt` - KID path traversal payloads
- `kid_sql.txt` - KID SQL injection payloads
- `kid_cmd.txt` - KID command injection payloads
- `websocket_endpoints.txt` - WebSocket endpoints
- `polling_endpoints.txt` - Token polling endpoints
