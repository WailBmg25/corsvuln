"""
Rate limiter implementation using token bucket algorithm.

This module provides rate limiting functionality for attack scripts
to prevent resource exhaustion and ensure controlled execution.
"""

import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.
    
    The token bucket algorithm maintains a bucket of tokens that refills
    at a constant rate. Each request consumes one token. If no tokens
    are available, the request must wait until tokens are refilled.
    
    Attributes:
        max_rate: Maximum number of requests per second
        tokens: Current number of available tokens
        last_update: Timestamp of last token refill
    """
    
    def __init__(self, max_rate: int = 5):
        """
        Initialize the rate limiter.
        
        Args:
            max_rate: Maximum number of requests per second (default: 5)
        """
        self.max_rate = max_rate
        self.tokens = float(max_rate)
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    def _refill_tokens(self) -> None:
        """
        Refill tokens based on elapsed time since last update.
        
        Tokens are added proportionally to the time elapsed, up to
        the maximum bucket capacity (max_rate).
        """
        now = time.time()
        elapsed = now - self.last_update
        
        # Add tokens based on elapsed time
        tokens_to_add = elapsed * self.max_rate
        self.tokens = min(self.max_rate, self.tokens + tokens_to_add)
        
        self.last_update = now
    
    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens from the bucket, waiting if necessary.
        
        This method will block until the requested number of tokens
        is available. It uses the token bucket algorithm to ensure
        the rate limit is respected.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
        
        Example:
            >>> limiter = RateLimiter(max_rate=5)
            >>> await limiter.acquire()  # Acquire 1 token
            >>> # Request can proceed
        """
        async with self._lock:
            while True:
                self._refill_tokens()
                
                if self.tokens >= tokens:
                    # Tokens available, consume them
                    self.tokens -= tokens
                    return
                
                # Not enough tokens, calculate wait time
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.max_rate
                
                # Release lock while waiting
                await asyncio.sleep(wait_time)
    
    def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without waiting.
        
        This is a non-blocking version of acquire() that returns
        immediately with a boolean indicating success.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
        
        Returns:
            True if tokens were acquired, False otherwise
        """
        self._refill_tokens()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def get_available_tokens(self) -> float:
        """
        Get the current number of available tokens.
        
        Returns:
            Current number of tokens in the bucket
        """
        self._refill_tokens()
        return self.tokens
    
    def reset(self) -> None:
        """
        Reset the rate limiter to initial state.
        
        This refills the bucket to maximum capacity and resets
        the last update timestamp.
        """
        self.tokens = float(self.max_rate)
        self.last_update = time.time()
