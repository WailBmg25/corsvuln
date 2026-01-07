"""
Session management with in-memory storage
"""

import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional
from app.auth.models import User, Session


class InMemorySessionStore:
    """In-memory session store with TTL management"""
    
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize session store
        
        Args:
            session_timeout: Session timeout in seconds (default: 3600 = 1 hour)
        """
        self.sessions: Dict[str, Session] = {}
        self.users: Dict[str, User] = {}
        self.session_timeout = session_timeout
        self.cleanup_task: Optional[asyncio.Task] = None
        self._initialize_default_users()
    
    def _initialize_default_users(self):
        """Initialize three default test accounts"""
        default_accounts = [
            ("admin", "admin123", "admin"),
            ("user", "user123", "user"),
            ("victim", "victim123", "victim")
        ]
        
        for username, password, role in default_accounts:
            password_hash = self._hash_password(password)
            user = User(
                username=username,
                password_hash=password_hash,
                role=role,
                created_at=datetime.now()
            )
            self.users[username] = user
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _generate_session_id(self) -> str:
        """Generate a secure random session ID"""
        return secrets.token_urlsafe(32)
    
    def create_session(self, username: str, password: str) -> Optional[str]:
        """
        Create a new session for valid credentials
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            Session ID if credentials are valid, None otherwise
        """
        # Validate credentials
        user = self.users.get(username)
        if not user:
            return None
        
        password_hash = self._hash_password(password)
        if user.password_hash != password_hash:
            return None
        
        # Create session
        session_id = self._generate_session_id()
        expires_at = datetime.now() + timedelta(seconds=self.session_timeout)
        
        session = Session(
            session_id=session_id,
            username=username,
            created_at=datetime.now(),
            expires_at=expires_at
        )
        
        self.sessions[session_id] = session
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """
        Validate session and return user if valid
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            User object if session is valid, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        if not session.is_valid():
            # Remove expired session
            del self.sessions[session_id]
            return None
        
        # Return user object
        user = self.users.get(session.username)
        return user
    
    def destroy_session(self, session_id: str) -> bool:
        """
        Destroy a session
        
        Args:
            session_id: Session ID to destroy
            
        Returns:
            True if session was destroyed, False if session didn't exist
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    async def cleanup_expired_sessions(self):
        """Background task to periodically clean up expired sessions"""
        while True:
            await asyncio.sleep(60)  # Check every minute
            now = datetime.now()
            expired = [
                sid for sid, session in self.sessions.items()
                if session.expires_at < now
            ]
            for sid in expired:
                del self.sessions[sid]
    
    def start_cleanup_task(self):
        """Start the background cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self.cleanup_expired_sessions())
    
    def stop_cleanup_task(self):
        """Stop the background cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            self.cleanup_task = None


# Global session store instance
session_store = InMemorySessionStore()
