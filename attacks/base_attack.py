"""
Base attack script class for CORS vulnerability demonstrations.

This module provides the base class that all attack scripts inherit from,
ensuring consistent behavior, rate limiting, and safety mechanisms.
"""

import time
from abc import ABC, abstractmethod
from typing import Optional
import sys

from attacks.models import AttackResult
from app.rate_limiter import RateLimiter


class BaseAttack(ABC):
    """
    Base class for all attack scripts.
    
    This abstract class provides common functionality for attack scripts,
    including rate limiting, warning displays, and execution tracking.
    All attack scripts should inherit from this class and implement
    the execute() method.
    
    Attributes:
        target_url: Base URL of the target application
        rate_limiter: RateLimiter instance for controlling request rate
        start_time: Timestamp when attack execution started
    """
    
    def __init__(self, target_url: str, max_rate: int = 5):
        """
        Initialize the base attack.
        
        Args:
            target_url: Base URL of the target application (e.g., "http://localhost:8000")
            max_rate: Maximum requests per second (default: 5)
        """
        self.target_url = target_url.rstrip('/')
        self.rate_limiter = RateLimiter(max_rate=max_rate)
        self.start_time: Optional[float] = None
        self._requests_sent = 0
    
    def display_warning(self) -> None:
        """
        Display warning banner before attack execution.
        
        This method prints a clear warning to inform users that they are
        about to execute an attack script for educational purposes only.
        The warning emphasizes that this should only be used in isolated
        environments.
        """
        warning = """
╔═══════════════════════════════════════════════════════════════════════╗
║                          ⚠️  WARNING  ⚠️                               ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  You are about to execute an attack script that demonstrates         ║
║  CORS vulnerabilities for EDUCATIONAL PURPOSES ONLY.                 ║
║                                                                       ║
║  This script should ONLY be used in:                                 ║
║    • Isolated development environments                               ║
║    • Educational/training labs with network isolation                ║
║    • Systems you own or have explicit permission to test             ║
║                                                                       ║
║  NEVER use this against production systems or systems you do not     ║
║  have explicit authorization to test.                                ║
║                                                                       ║
║  The attack will be rate-limited to prevent resource exhaustion.     ║
║  No data will be persisted beyond the execution context.             ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
        """
        print(warning, file=sys.stderr)
        print(f"\nTarget: {self.target_url}", file=sys.stderr)
        print(f"Attack Type: {self.__class__.__name__}", file=sys.stderr)
        print("\nProceeding with attack execution...\n", file=sys.stderr)
    
    def get_duration(self) -> float:
        """
        Get the duration of the attack execution.
        
        Returns:
            Duration in seconds since start_time was set, or 0 if not started
        """
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time
    
    def increment_requests(self) -> None:
        """
        Increment the counter for requests sent.
        
        This should be called by subclasses each time they send a request.
        """
        self._requests_sent += 1
    
    def get_requests_sent(self) -> int:
        """
        Get the number of requests sent during this attack.
        
        Returns:
            Number of requests sent
        """
        return self._requests_sent
    
    @abstractmethod
    async def execute(self) -> AttackResult:
        """
        Execute the attack.
        
        This method must be implemented by all subclasses to perform
        the specific attack logic. The implementation should:
        
        1. Use self.rate_limiter.acquire() before each request
        2. Call self.increment_requests() after each request
        3. Return an AttackResult with all relevant information
        4. Not persist any data to disk or database
        
        Returns:
            AttackResult containing the results of the attack execution
        
        Raises:
            NotImplementedError: If not implemented by subclass
        """
        raise NotImplementedError("Subclasses must implement execute()")
    
    async def run(self) -> AttackResult:
        """
        Run the attack with warning display and timing.
        
        This method wraps the execute() method with common functionality:
        - Displays warning banner
        - Tracks execution time
        - Ensures isolated execution
        
        Returns:
            AttackResult from the execute() method
        """
        # Display warning before execution
        self.display_warning()
        
        # Start timing
        self.start_time = time.time()
        
        try:
            # Execute the attack (implemented by subclass)
            result = await self.execute()
            
            # Ensure duration is set
            if result.duration_seconds == 0:
                result.duration_seconds = self.get_duration()
            
            # Ensure requests_sent is set
            if result.requests_sent == 0:
                result.requests_sent = self.get_requests_sent()
            
            return result
            
        except Exception as e:
            # Return error result if execution fails
            return AttackResult(
                attack_type=self.__class__.__name__,
                success=False,
                duration_seconds=self.get_duration(),
                requests_sent=self.get_requests_sent(),
                error=str(e),
                educational_notes="Attack execution failed due to an error."
            )
