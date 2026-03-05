from enum import Enum


class Level(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    INSANE = 4


class Risk(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class _kurtVuln_list(Enum):
    NONE_ALGORITHM = "none_algorithm"
    WEAK_SECRET = "weak_secret"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    JKU_INJECTION = "jku_injection"
    JWK_INJECTION = "jwk_injection"
    KID_PATH_TRAVERSAL = "kid_path_traversal"
    KID_SQL_INJECTION = "kid_sql_injection"
    KID_COMMAND_INJECTION = "kid_command_injection"
    SIGNATURE_REMOVAL = "signature_removal"
    PUBLIC_KEY_EXPOSURE = "public_key_exposure"
    JWKS_CACHE_POISONING = "jwks_cache_poisoning"
    WEBSOCKET_INFO_LEAK = "websocket_info_leak"
    UNAUTH_TOKEN_POLLING = "unauth_token_polling"
    CROSS_SYSTEM_LEAKAGE = "cross_system_leakage"
    UNKNOWN_ALG_BYPASS = "unknown_alg_bypass"
    EXPIRATION_MISSING = "expiration_missing"
    EXPIRATION_LONG = "expiration_too_long"
    AUDIENCE_VALIDATION_BYPASS = "audience_validation_bypass"
    ISSUER_VALIDATION_BYPASS = "issuer_validation_bypass"
    TYP_HEADER_MISSING = "typ_header_missing"
    KID_MISSING = "kid_missing"
    CLAIM_TYPE_CONFUSION = "claim_type_confusion"
    JWK_MISSING_ALG_CONFUSION = "jwk_missing_alg_confusion"
    DISABLED_IDP_TOKEN_ACCEPTED = "disabled_idp_token_accepted"
    CVE_2025_30144 = "cve_2025_30144"
    CVE_2024_54150 = "cve_2024_54150"
    CVE_2025_68620 = "cve_2025_68620"
    CVE_2024_51498 = "cve_2024_51498"
    CVE_2024_29371 = "cve_2024_29371"


class chain_attack(Enum):
    TOKEN_THEFT_CHAIN = "JWT Token Theft Chain (CVE-2025-68620)"
    ALGORITHM_CONFUSION_CHAIN = "Algorithm Confusion Chain (CVE-2024-54150)"
    JWKS_POISONING_CHAIN = "JWKS Cache Poisoning Chain"
    KID_INJECTION_CHAIN = "KID Multi-Vector Injection Chain"
    CROSS_SYSTEM_CHAIN = "Cross-System Lateral Movement Chain"
    UNKNOWN_ALG_CHAIN = "Unknown Algorithm Bypass Chain"
    EXPIRATION_CHAIN = "Token Lifetime Abuse Chain"
    TYPE_CONFUSION_CHAIN = "Claim Type Confusion Chain (CVE-2026-25537)"
