# CORS Vulnerability Demonstration Project

⚠️ **EDUCATIONAL PURPOSE ONLY** ⚠️

**WARNING**: This application contains intentionally vulnerable endpoints for educational purposes only. Never deploy this application in a production environment or on a publicly accessible network.

## Overview

The CORS Vulnerability Demonstration Project is an educational FastAPI application that demonstrates real-world CORS (Cross-Origin Resource Sharing) misconfigurations and their security implications. This project showcases both vulnerable and secure implementations with corresponding Python attack scripts that prove the vulnerabilities.

This demonstration tool is designed for security education, training, and research. It helps developers and security professionals understand CORS vulnerabilities and learn how to implement secure CORS configurations.

### Key Features

- **Vulnerable Endpoints**: Intentionally misconfigured CORS implementations demonstrating common security issues
- **Secure Endpoints**: Properly configured CORS implementations showing best practices
- **Attack Scripts**: Automated Python scripts that exploit each vulnerability type
- **Interactive Demo Interface**: Web-based dashboard for visualizing and executing attacks in real-time
- **Educational Content**: Detailed explanations with references to MISC publications 98, 99, and HS 4
- **Safety Mechanisms**: Rate limiting, timeouts, and sanitization to ensure safe demonstration

## Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd cors_project

# Copy environment variables
cp .env.example .env

# Build and run with Docker Compose
docker-compose up --build

# Access the application
# Open http://localhost:8000 in your browser
```

### Local Development

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env

# Run the application
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Access the application
# Open http://localhost:8000 in your browser
```

### Default Test Accounts

The application initializes with three test accounts for demonstration:

- **Admin**: `admin` / `admin123` (full privileges)
- **User**: `user` / `user123` (limited privileges)
- **Victim**: `victim` / `victim123` (standard user for demonstrations)

## Vulnerability Types

This project demonstrates five major CORS misconfigurations based on MISC publications:

### 1. Wildcard Origin with Credentials (`/api/vuln/wildcard`)

**Vulnerability**: Using `Access-Control-Allow-Origin: *` with credentials enabled

**Reference**: MISC 99, §2.1

**Impact**: Enables brute force attacks against authentication endpoints and allows any malicious website to steal user credentials and session tokens.

**Expected Output**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "username": "victim",
  "email": "victim@example.com",
  "role": "user"
}
```

**Sample curl command**:
```bash
curl -X GET 'http://localhost:8000/api/vuln/wildcard' \
  -H 'Origin: https://evil.com' \
  -H 'Cookie: session_id=your_session_id' \
  -v
```

**Secure Alternative** (`/api/sec/wildcard`): Uses specific origin whitelist with exact matching

---

### 2. Origin Reflection Without Validation (`/api/vuln/reflection`)

**Vulnerability**: Reflecting the Origin header value directly in `Access-Control-Allow-Origin` without validation

**Reference**: MISC 99, §2.2

**Impact**: Allows attackers to steal sensitive data by making authenticated cross-origin requests from malicious websites. This is one of the most common CORS misconfigurations.

**Expected Output**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "transactions": [
    {"id": 1, "amount": 1000, "recipient": "account123"}
  ]
}
```

**Sample curl command**:
```bash
curl -X POST 'http://localhost:8000/api/vuln/reflection' \
  -H 'Origin: https://attacker.com' \
  -H 'Cookie: session_id=your_session_id' \
  -H 'Content-Type: application/json' \
  -d '{}' \
  -v
```

**Secure Alternative** (`/api/sec/reflection`): Validates origins against predefined whitelist with exact matching

---

### 3. Null Origin Acceptance (`/api/vuln/null-origin`)

**Vulnerability**: Accepting `Origin: null` from sandboxed iframes or local files

**Reference**: MISC 99, §2.3

**Impact**: Allows attackers to bypass CORS protections using sandboxed iframes or local HTML files. Null origins are easy to generate and exploit.

**Expected Output**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "api_keys": [
    {"key": "sk_live_abc123", "name": "Production API Key"}
  ]
}
```

**Sample curl command**:
```bash
curl -X GET 'http://localhost:8000/api/vuln/null-origin' \
  -H 'Origin: null' \
  -H 'Cookie: session_id=your_session_id' \
  -v
```

**Secure Alternative** (`/api/sec/null-origin`): Explicitly rejects null origins with 403 Forbidden

---

### 4. Permissive Substring Filtering (`/api/vuln/permissive`)

**Vulnerability**: Using substring matching (e.g., checking if origin contains "trusted.com") instead of exact matching

**Reference**: MISC 99, §2.4

**Impact**: Allows attackers to register malicious domains like `attacker-trusted.com` or `trusted.com.evil.com` to bypass validation.

**Expected Output**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker-trusted.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
  "admin_settings": {
    "debug_mode": true,
    "secret_key": "super_secret_key_123"
  }
}
```

**Sample curl command**:
```bash
curl -X GET 'http://localhost:8000/api/vuln/permissive' \
  -H 'Origin: https://attacker-trusted.com' \
  -H 'Cookie: session_id=your_session_id' \
  -v
```

**Secure Alternative** (`/api/sec/permissive`): Uses exact string matching including protocol and port

---

### 5. Missing Vary Header - Cache Poisoning (`/api/vuln/vary`)

**Vulnerability**: Serving different CORS headers based on Origin without including `Vary: Origin` header

**Reference**: MISC 99, §3.1

**Impact**: Allows attackers to poison caches with malicious CORS headers, causing legitimate users to receive responses with attacker's origin.

**Expected Output**:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Content-Type: application/json
(Missing Vary: Origin header)

{
  "cached_content": "This response may be cached with wrong CORS headers"
}
```

**Sample curl command**:
```bash
curl -X GET 'http://localhost:8000/api/vuln/vary' \
  -H 'Origin: https://attacker.com' \
  -H 'Cookie: session_id=your_session_id' \
  -v
```

**Secure Alternative** (`/api/sec/vary`): Includes `Vary: Origin` and proper cache control headers

---

## Attack Scripts

The project includes automated attack scripts that demonstrate exploitation of each vulnerability:

### 1. Brute Force Attack (`attacks/brute_force.py`)

Exploits the wildcard origin vulnerability to perform brute force authentication attacks.

**Expected Output**:
```json
{
  "attack_type": "brute_force",
  "success": true,
  "duration_seconds": 2.5,
  "requests_sent": 10,
  "stolen_data": {
    "valid_credentials": [
      {"username": "admin", "password": "admin123"}
    ]
  },
  "vulnerable_endpoints": ["/api/vuln/wildcard"]
}
```

### 2. Origin Reflection Attack (`attacks/reflection.py`)

Uses browser automation to exploit origin reflection vulnerability.

**Expected Output**:
```json
{
  "attack_type": "reflection",
  "success": true,
  "duration_seconds": 5.2,
  "requests_sent": 3,
  "stolen_data": {
    "transactions": [
      {"id": 1, "amount": 1000, "recipient": "account123"}
    ]
  },
  "vulnerable_endpoints": ["/api/vuln/reflection"]
}
```

### 3. Null Origin Attack (`attacks/null_origin.py`)

Creates sandboxed iframe context to exploit null origin acceptance.

**Expected Output**:
```json
{
  "attack_type": "null_origin",
  "success": true,
  "duration_seconds": 3.1,
  "requests_sent": 2,
  "stolen_data": {
    "api_keys": [
      {"key": "sk_live_abc123", "name": "Production API Key"}
    ]
  },
  "vulnerable_endpoints": ["/api/vuln/null-origin"]
}
```

### 4. Permissive Filtering Attack (`attacks/permissive.py`)

Tests multiple malicious origin variations to bypass substring filtering.

**Expected Output**:
```json
{
  "attack_type": "permissive",
  "success": true,
  "duration_seconds": 1.8,
  "requests_sent": 5,
  "stolen_data": {
    "accepted_origins": [
      "https://attacker-trusted.com",
      "https://trusted.com.evil.com"
    ],
    "admin_settings": {
      "debug_mode": true,
      "secret_key": "super_secret_key_123"
    }
  },
  "vulnerable_endpoints": ["/api/vuln/permissive"]
}
```

### 5. Cache Poisoning Attack (`attacks/vary_attack.py`)

Demonstrates cache poisoning via missing Vary header.

**Expected Output**:
```json
{
  "attack_type": "vary_attack",
  "success": true,
  "duration_seconds": 2.3,
  "requests_sent": 4,
  "stolen_data": {
    "cache_poisoned": true,
    "malicious_origin_cached": "https://attacker.com"
  },
  "vulnerable_endpoints": ["/api/vuln/vary"]
}
```

## Project Structure

```
.
├── app/
│   ├── auth/                    # Authentication and session management
│   │   ├── middleware.py        # Authentication middleware
│   │   ├── models.py            # User and session models
│   │   └── session_manager.py   # Session store implementation
│   ├── middleware/              # Custom CORS middleware
│   │   ├── cors_config.py       # CORS configuration per route
│   │   ├── cors_middleware.py   # Custom CORS middleware
│   │   └── origin_validation.py # Origin validation utilities
│   ├── models/                  # Data models
│   │   └── errors.py            # Error response models
│   ├── routers/                 # API endpoints
│   │   ├── auth.py              # Authentication endpoints
│   │   ├── demo.py              # Demo interface routes
│   │   ├── secure.py            # Secure CORS endpoints
│   │   └── vulnerable.py        # Vulnerable CORS endpoints
│   ├── utils/                   # Utility functions
│   │   └── sanitization.py      # Output sanitization
│   ├── error_handlers.py        # Error handling
│   └── rate_limiter.py          # Rate limiting implementation
├── attacks/                     # Attack scripts
│   ├── base_attack.py           # Base attack class
│   ├── brute_force.py           # Brute force attack
│   ├── models.py                # Attack result models
│   ├── null_origin.py           # Null origin attack
│   ├── permissive.py            # Permissive filtering attack
│   ├── reflection.py            # Origin reflection attack
│   └── vary_attack.py           # Cache poisoning attack
├── static/                      # Static files
│   ├── css/
│   │   └── styles.css           # Styling with color coding
│   └── js/
│       └── attack_executor.js   # Client-side attack execution
├── templates/                   # HTML templates
│   ├── attack_result.html       # Attack result display
│   └── dashboard.html           # Main dashboard
├── tests/                       # Test files
├── .env.example                 # Environment variable template
├── Dockerfile                   # Container configuration
├── docker-compose.yml           # Docker Compose configuration
├── educational_content.json     # Educational content and references
├── main.py                      # Application entry point
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Security Recommendations

### For Developers

1. **Never use wildcard origin with credentials**: Always use specific origin whitelists
2. **Validate origins strictly**: Use exact string matching including protocol and port
3. **Reject null origins**: Explicitly reject `Origin: null` with 403 status
4. **Include Vary header**: Always include `Vary: Origin` when CORS headers depend on origin
5. **Use proper cache control**: Prevent caching of sensitive data with appropriate headers
6. **Test your CORS configuration**: Use tools like this project to verify your implementation

### For Security Professionals

1. **Test for CORS misconfigurations**: Include CORS testing in security assessments
2. **Look for origin reflection**: Check if applications reflect Origin header without validation
3. **Test with null origins**: Verify that applications properly reject null origins
4. **Check for substring matching**: Test with malicious domains containing trusted substrings
5. **Verify Vary headers**: Ensure applications include proper Vary headers for cached responses

## Deployment Warnings

⚠️ **CRITICAL SECURITY WARNINGS** ⚠️

This application is designed for **educational purposes only** and should **NEVER** be deployed in:

- Production environments
- Publicly accessible networks
- Any environment with real user data
- Any environment connected to the internet

### Recommended Deployment Environments

✅ **Safe Environments**:
- Isolated local development environment
- Classroom or training lab with network isolation
- Docker container with no external network access
- Virtual machines on isolated networks
- Localhost-only access

### Safety Mechanisms

The application includes several safety mechanisms:

1. **Rate Limiting**: Maximum 5 requests per second to prevent resource exhaustion
2. **Execution Timeout**: All attack scripts timeout after 60 seconds
3. **Input Sanitization**: All user input is sanitized before rendering to prevent XSS
4. **No Persistent Storage**: Attack scripts don't persist data beyond execution context
5. **Warning Banners**: Clear warnings displayed before attack execution
6. **Session Isolation**: Sessions are isolated between users
7. **In-Memory Storage**: All data stored in memory, cleared on restart

## Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest test_cors_middleware.py

# Run with coverage
pytest --cov=app --cov-report=html

# Run property-based tests
pytest test_attack_scripts.py -v
```

## API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## References

This project is based on research and publications from the French security magazine MISC:

### Primary References

- **MISC 98**: "Comprendre le fonctionnement des CORS" - Fundamental CORS concepts and how the Cross-Origin Resource Sharing mechanism works in modern browsers.

- **MISC 99**: "Cross Origin Resource Sharing: défauts de configurations, vulnérabilités et exploitations" - Comprehensive guide to CORS misconfigurations, vulnerabilities, and exploitation techniques. This is the primary reference for understanding CORS security issues.

- **MISC HS 4**: "Architectures web sécurisées" - Secure web architecture principles including proper CORS configuration in modern web applications.

### Additional Resources

- **MDN Web Docs - CORS**: Official documentation for Cross-Origin Resource Sharing specification and best practices
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

- **OWASP - CORS**: Security guidelines for implementing CORS correctly and avoiding common pitfalls
  - https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny

## Contributing

This is an educational project. If you find issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is for educational purposes only. Use responsibly and only in authorized environments.

## Acknowledgments

Based on research from MISC publications 98, 99, and HS 4. Special thanks to the security research community for documenting these vulnerabilities and helping improve web security.

---

**Remember**: This application contains intentionally vulnerable code. Never use these patterns in production applications. Always implement secure CORS configurations following the secure examples provided in this project.

## 📚 Documentation

This project demonstrates 5 critical CORS vulnerabilities based on MISC 99:

1. **Wildcard with Credentials** - `Access-Control-Allow-Origin: *` with credentials enabled
2. **Origin Reflection** - Automatic reflection of Origin header without validation
3. **Null Origin** - Accepting `Origin: null` from sandboxed iframes
4. **Permissive Filtering** - Using substring matching instead of exact matching
5. **Missing Vary Header** - Cache poisoning due to missing `Vary: Origin`

Each vulnerability has:
- Vulnerable endpoint (`/api/vuln/*`)
- Secure endpoint (`/api/sec/*`)
- Attack script in `attacks/` directory
- Interactive demo in web interface

## 📁 Project Structure

```
cors_project/
├── app/                    # FastAPI application
│   ├── auth/              # Authentication module
│   ├── middleware/        # CORS middleware
│   ├── models/            # Data models
│   ├── routers/           # API routes (vulnerable & secure)
│   └── utils/             # Utilities (sanitization, etc.)
├── attacks/               # Attack scripts
│   ├── brute_force.py    # Wildcard attack
│   ├── reflection.py     # Origin reflection attack
│   ├── null_origin.py    # Null origin attack
│   ├── permissive.py     # Permissive filtering attack
│   └── vary_attack.py    # Vary header attack
├── static/                # Frontend assets (CSS, JS)
├── templates/             # HTML templates
├── educational_content.json  # Educational content
├── main.py               # Application entry point
├── run_attack_cli.py     # CLI for running attacks
└── requirements.txt      # Python dependencies
```
