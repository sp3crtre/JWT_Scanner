from dataclasses import dataclass, field
from typing import List, Optional
from .enums import _kurtVuln_list, chain_attack


@dataclass
class jq_vuln_list:
    type: _kurtVuln_list
    severity: str
    description: str
    exploit_payload: Optional[str] = None
    proof: Optional[str] = None
    endpoint: Optional[str] = None
    chainable_with: List[_kurtVuln_list] = field(default_factory=list)
    cve_reference: Optional[str] = None
    cvss_score: float = 0.0
    _exploit_payload_token: Optional[str] = None

    @property
    def exploitable(self) -> bool:
        return self.type in [
            _kurtVuln_list.NONE_ALGORITHM,
            _kurtVuln_list.WEAK_SECRET,
            _kurtVuln_list.ALGORITHM_CONFUSION,
            _kurtVuln_list.JKU_INJECTION,
            _kurtVuln_list.JWK_INJECTION,
            _kurtVuln_list.KID_PATH_TRAVERSAL,
            _kurtVuln_list.KID_SQL_INJECTION,
            _kurtVuln_list.KID_COMMAND_INJECTION,
            _kurtVuln_list.SIGNATURE_REMOVAL,
            _kurtVuln_list.UNKNOWN_ALG_BYPASS,
            _kurtVuln_list.EXPIRATION_MISSING,
            _kurtVuln_list.EXPIRATION_LONG,
            _kurtVuln_list.CLAIM_TYPE_CONFUSION,
            _kurtVuln_list.JWK_MISSING_ALG_CONFUSION,
            _kurtVuln_list.DISABLED_IDP_TOKEN_ACCEPTED,
        ]


@dataclass
class chain_vuln_quete_attack:
    chain_type: chain_attack
    vulnerabilities: List[jq_vuln_list]
    impact: str
    exploit_steps: List[str]
    poc_code: Optional[str] = None
    cvss_score: float = 0.0
