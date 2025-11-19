import os
import jwt
import time
import uuid
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

KEY_DIR = "keys"

class TokenAuthority:
    """
    Dual-Key Credential Authority (DKCA).
    Issues JWTs signed by either the PRIME (Production) key or SHADOW (Honeypot) key.
    """
    
    def __init__(self):
        self.sk_prime = self._load_key("private_prime.pem")
        self.sk_shadow = self._load_key("private_shadow.pem")
        # We don't need public keys here, only private for signing

    def _load_key(self, filename: str) -> bytes:
        path = os.path.join(KEY_DIR, filename)
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Key file not found: {path}")
            raise RuntimeError(f"Critical Security Error: Missing Key {filename}")

    def issue_warrant(self, session_id: str, risk_score: float, scope: str = "full_access") -> str:
        """
        Issues a 'Shadow Warrant' (JWT).
        
        Decision Logic:
        - If risk_score > 0.8: Sign with SHADOW Key.
        - Else: Sign with PRIME Key.
        """
        
        now = int(time.time())
        payload = {
            "iss": "CHIMERA_AUTHORITY",
            "sub": session_id,
            "iat": now,
            "exp": now + 3600, # 1 hour expiration
            "jti": str(uuid.uuid4()),
            "scope": scope,
            "risk_score": risk_score # In production, we might hide this, but useful for debugging
        }

        if risk_score > 0.8:
            # THREAT DETECTED -> SHADOW WARRANT
            logger.warning(f"Issuing SHADOW WARRANT for session {session_id} (Risk: {risk_score})")
            token = jwt.encode(payload, self.sk_shadow, algorithm="RS256", headers={"kid": "shadow_key_1"})
        else:
            # SAFE -> PRIME CREDENTIAL
            logger.info(f"Issuing PRIME CREDENTIAL for session {session_id}")
            token = jwt.encode(payload, self.sk_prime, algorithm="RS256", headers={"kid": "prime_key_1"})
            
        return token

