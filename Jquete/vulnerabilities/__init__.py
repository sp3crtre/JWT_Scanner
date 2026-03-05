from .algorithm import (
    test_none_algorithm,
    test_weak_secret,
    test_algorithm_confusion,
    test_signature_removal,
    test_unknown_algorithm,
)
from .injection import (
    test_jku_injection,
    test_jwk_injection,
    test_kid_injection,
    test_jwks_cache_poisoning,
    test_jwk_missing_alg,
)
from .validation import test_expiration, test_audience_issuer, test_claim_type_confusion
from .leakage import (
    test_websocket_event_leak,
    test_unauth_token_polling,
    test_cross_system_leakage,
)

__all__ = [
    "test_none_algorithm",
    "test_weak_secret",
    "test_algorithm_confusion",
    "test_signature_removal",
    "test_unknown_algorithm",
    "test_jku_injection",
    "test_jwk_injection",
    "test_kid_injection",
    "test_jwks_cache_poisoning",
    "test_jwk_missing_alg",
    "test_expiration",
    "test_audience_issuer",
    "test_claim_type_confusion",
    "test_websocket_event_leak",
    "test_unauth_token_polling",
    "test_cross_system_leakage",
]
