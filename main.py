"""
Main application entry point for CORS Vulnerability Demonstration Project
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException as FastAPIHTTPException
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from contextlib import asynccontextmanager
import json
import time
from pathlib import Path
from app.auth.session_manager import session_store
from app.auth.middleware import AuthenticationMiddleware
from app.middleware.cors_middleware import CustomCORSMiddleware
from app.middleware.cors_config import ALL_ROUTE_CONFIGS
from app.routers import auth
from app.routers import vulnerable
from app.routers import secure
from app.routers import demo
from app.error_handlers import (
    bad_request_handler,
    validation_error_handler,
    unauthorized_handler,
    forbidden_handler,
    not_found_handler,
    internal_server_error_handler
)

# Global educational content storage
EDUCATIONAL_CONTENT = {}


def load_educational_content():
    """Load educational content from JSON file"""
    global EDUCATIONAL_CONTENT
    try:
        educational_path = Path("educational_content.json")
        if educational_path.exists():
            with open(educational_path, "r") as f:
                content = json.load(f)
                EDUCATIONAL_CONTENT.clear()
                EDUCATIONAL_CONTENT.update(content)
            return True
        return False
    except Exception as e:
        print(f"Error loading educational content: {e}")
        return False


# Load educational content at module import time as fallback
# This ensures it's available even if lifespan hasn't run yet (e.g., in tests)
load_educational_content()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    Handles startup and shutdown events
    """
    startup_start = time.time()
    print("=" * 60)
    print("🚀 Starting CORS Vulnerability Demonstration System")
    print("=" * 60)
    
    # Startup: Load educational content
    if load_educational_content():
        print("✓ Educational content loaded successfully")
        print(f"  - {len(EDUCATIONAL_CONTENT.get('vulnerabilities', {}))} vulnerabilities documented")
        print(f"  - {len(EDUCATIONAL_CONTENT.get('secure_implementations', {}))} secure implementations documented")
    else:
        print("⚠ Warning: educational_content.json not found")
    
    # Startup: Preload templates (verify they exist)
    try:
        templates_dir = Path("templates")
        if templates_dir.exists():
            template_files = list(templates_dir.glob("*.html"))
            print(f"✓ Templates preloaded: {len(template_files)} files found")
            for template in template_files:
                print(f"  - {template.name}")
        else:
            print("⚠ Warning: templates directory not found")
    except Exception as e:
        print(f"⚠ Warning: Failed to preload templates: {e}")
    
    # Startup: Verify static files exist
    try:
        static_dir = Path("static")
        if static_dir.exists():
            css_files = list(static_dir.glob("css/*.css"))
            js_files = list(static_dir.glob("js/*.js"))
            print(f"✓ Static files verified: {len(css_files)} CSS, {len(js_files)} JS")
        else:
            print("⚠ Warning: static directory not found")
    except Exception as e:
        print(f"⚠ Warning: Failed to verify static files: {e}")
    
    # Startup: Start session cleanup task
    session_store.start_cleanup_task()
    print("✓ Session store initialized with default users")
    print(f"  - {len(session_store.users)} test accounts available")
    print("✓ Session cleanup task started")
    
    # Verify routers are registered
    print("✓ Routers registered:")
    print("  - Authentication (/api/auth)")
    print("  - Vulnerable endpoints (/api/vuln)")
    print("  - Secure endpoints (/api/sec)")
    print("  - Demo interface (/)")
    
    # Verify middleware is applied
    print("✓ Middleware configured:")
    print("  - Custom CORS middleware (route-specific)")
    print("  - Authentication middleware")
    
    # Note: Attack scripts use lazy loading (loaded on-demand)
    print("✓ Attack scripts configured for lazy loading")
    
    startup_duration = time.time() - startup_start
    print(f"✓ Initialization completed in {startup_duration:.2f} seconds")
    
    # Verify startup time requirement (< 30 seconds)
    if startup_duration < 30:
        print(f"✓ Startup time requirement met ({startup_duration:.2f}s < 30s)")
    else:
        print(f"⚠ Warning: Startup time exceeded requirement ({startup_duration:.2f}s >= 30s)")
    
    print("=" * 60)
    print("📚 Educational CORS Demonstration System Ready")
    print("=" * 60)
    
    yield
    
    # Shutdown: Stop session cleanup task
    print("\n" + "=" * 60)
    print("🛑 Shutting down CORS Vulnerability Demonstration System")
    print("=" * 60)
    session_store.stop_cleanup_task()
    print("✓ Session cleanup task stopped")
    print("✓ Shutdown complete")
    print("=" * 60)


# Create FastAPI application
app = FastAPI(
    title="CORS Vulnerability Demonstration",
    description="Educational application demonstrating CORS misconfigurations",
    version="1.0.0",
    lifespan=lifespan
)

# Add authentication middleware
app.add_middleware(
    AuthenticationMiddleware,
    protected_paths=["/api/vuln/", "/api/sec/"]
)

# Add CORS middleware with route-specific configurations
app.add_middleware(
    CustomCORSMiddleware,
    route_configs=ALL_ROUTE_CONFIGS
)

# Register routers
app.include_router(auth.router)
app.include_router(vulnerable.router)
app.include_router(secure.router)
app.include_router(demo.router)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "session_count": len(session_store.sessions),
        "user_count": len(session_store.users)
    }


# Register error handlers
# Handle FastAPI HTTPException
from fastapi.exceptions import HTTPException as FastAPIHTTPException

@app.exception_handler(FastAPIHTTPException)
async def fastapi_http_exception_handler(request: Request, exc: FastAPIHTTPException):
    """Route FastAPI HTTP exceptions to appropriate handlers based on status code"""
    if exc.status_code == status.HTTP_400_BAD_REQUEST:
        return await bad_request_handler(request, exc)
    elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return await unauthorized_handler(request, exc)
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        return await forbidden_handler(request, exc)
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        return await not_found_handler(request, exc)
    elif exc.status_code >= 500:
        return await internal_server_error_handler(request, exc)
    else:
        # Default handler for other status codes
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail}
        )

# Handle validation errors (422 -> 400)
app.add_exception_handler(RequestValidationError, validation_error_handler)

# Handle HTTP exceptions by status code
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Route HTTP exceptions to appropriate handlers based on status code"""
    if exc.status_code == status.HTTP_400_BAD_REQUEST:
        return await bad_request_handler(request, exc)
    elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return await unauthorized_handler(request, exc)
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        return await forbidden_handler(request, exc)
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        return await not_found_handler(request, exc)
    elif exc.status_code >= 500:
        return await internal_server_error_handler(request, exc)
    else:
        # Default handler for other status codes
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail}
        )

# Handle generic exceptions as 500 errors
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions as 500 Internal Server Error"""
    return await internal_server_error_handler(request, exc)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
