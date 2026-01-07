# CORS Attack Scripts

Educational attack scripts demonstrating CORS vulnerabilities.

⚠️ **WARNING**: These scripts are for educational purposes only. Use only in isolated environments with explicit permission.

## Quick Start

### Import and Use

```python
import asyncio
from attacks import BruteForceAttack, ReflectionAttack, NullOriginAttack, PermissiveAttack, VaryAttack

async def main():
    # Example: Brute force attack
    attack = BruteForceAttack(target_url="http://localhost:8000")
    result = await attack.run()
    
    print(f"Success: {result.success}")
    print(f"Stolen data: {result.stolen_data}")
    print(f"Educational notes: {result.educational_notes}")

asyncio.run(main())
```

### Command Line Usage

Each attack script can be run standalone:

```bash
# Brute force attack
python attacks/brute_force.py http://localhost:8000

# Origin reflection attack
python attacks/reflection.py http://localhost:8000 http://evil.com

# Null origin attack
python attacks/null_origin.py http://localhost:8000

# Permissive filtering attack
python attacks/permissive.py http://localhost:8000 trusted.com

# Cache poisoning attack
python attacks/vary_attack.py http://localhost:8000 http://evil.com http://legitimate.com
```

## Attack Scripts

### 1. Brute Force Attack (`brute_force.py`)

Exploits wildcard CORS vulnerability to perform brute force authentication attacks.

**Vulnerability**: `Access-Control-Allow-Origin: *` with credentials enabled

**Usage**:
```python
attack = BruteForceAttack(
    target_url="http://localhost:8000",
    credentials_list=[("admin", "admin123"), ("user", "user123")],
    malicious_origin="http://evil.com"
)
result = await attack.run()
```

### 2. Origin Reflection Attack (`reflection.py`)

Exploits origin reflection to bypass CORS protections.

**Vulnerability**: Server reflects Origin header without validation

**Usage**:
```python
attack = ReflectionAttack(
    target_url="http://localhost:8000",
    malicious_origin="http://attacker-site.com"
)
result = await attack.run()
```

### 3. Null Origin Attack (`null_origin.py`)

Exploits acceptance of null origin via sandboxed iframes.

**Vulnerability**: Server accepts `Origin: null`

**Usage**:
```python
attack = NullOriginAttack(target_url="http://localhost:8000")
result = await attack.run()

# Get generated attack HTML
html = attack.generate_attack_html()
```

### 4. Permissive Filtering Attack (`permissive.py`)

Exploits substring matching in origin validation.

**Vulnerability**: Server uses substring matching (e.g., `if "trusted.com" in origin`)

**Usage**:
```python
attack = PermissiveAttack(
    target_url="http://localhost:8000",
    target_substring="trusted.com"
)
result = await attack.run()
```

### 5. Cache Poisoning Attack (`vary_attack.py`)

Exploits missing Vary header to poison caches.

**Vulnerability**: Server omits `Vary: Origin` header

**Usage**:
```python
attack = VaryAttack(
    target_url="http://localhost:8000",
    malicious_origin="http://evil.com",
    legitimate_origin="http://legitimate-app.com"
)
result = await attack.run()
```

## Attack Result Structure

All attacks return an `AttackResult` object:

```python
class AttackResult:
    attack_type: str              # Type of attack
    success: bool                 # Whether attack succeeded
    duration_seconds: float       # Execution time
    requests_sent: int            # Number of requests
    stolen_data: dict            # Extracted sensitive data
    vulnerable_endpoints: list    # Vulnerable endpoints found
    request_details: list         # Request information
    response_details: list        # Response information
    educational_notes: str        # Educational content
    error: str                    # Error message if failed
```

## Creating Custom Attacks

Extend the `BaseAttack` class:

```python
from attacks.base_attack import BaseAttack
from attacks.models import AttackResult

class CustomAttack(BaseAttack):
    async def execute(self) -> AttackResult:
        # Your attack logic here
        
        # Use rate limiter before each request
        await self.rate_limiter.acquire()
        
        # Track requests
        self.increment_requests()
        
        # Return result
        return AttackResult(
            attack_type="custom",
            success=True,
            duration_seconds=self.get_duration(),
            requests_sent=self.get_requests_sent(),
            educational_notes="Your educational content"
        )
```

## Safety Features

- **Rate Limiting**: All attacks respect 5 req/sec limit
- **Warning Banners**: Displayed before execution
- **No Persistence**: No data written to disk
- **Timeout Support**: Prevents infinite execution
- **Error Handling**: Graceful failure handling

## Educational Content

Each attack includes:
- Vulnerability explanation
- Attack scenario walkthrough
- Impact assessment
- References to MISC publications
- Mitigation strategies
- Secure configuration examples

## References

- **MISC 98**: "Comprendre le fonctionnement des CORS"
- **MISC 99**: "Cross Origin Resource Sharing: défauts de configurations, vulnérabilités et exploitations"
- **MISC HS 4**: "Architectures web sécurisées"

## Testing

Run the test suite:

```bash
pytest test_attack_scripts.py -v
```

## License

Educational use only. Not for use against systems without explicit permission.
