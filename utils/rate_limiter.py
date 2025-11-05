"""
In-memory rate limiting for bot usage
"""

import time
import threading
import sys
import os
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class RateLimiter:
    """
    In-memory rate limiter for tracking user and domain scan requests
    """
    
    def __init__(self):
        # Store timestamps of requests per user
        self.user_requests: Dict[int, deque] = defaultdict(lambda: deque(maxlen=config.RATE_LIMIT_SCANS * 2))
        
        # Store last scan time per domain per user
        self.domain_cooldowns: Dict[Tuple[int, str], float] = {}
        
        # Global request tracking
        self.global_requests: deque = deque(maxlen=config.GLOBAL_RATE_LIMIT * 2)
        
        # Track currently running scans
        self.active_scans: Dict[int, dict] = {}
        
        # Start auto-cleanup timer
        self.cleanup_timer = None
        self._start_auto_cleanup()
        
    def check_user_rate_limit(self, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Check if user has exceeded rate limit
        
        Args:
            user_id: Telegram user ID
            
        Returns:
            Tuple of (allowed, error_message)
        """
        now = time.time()
        window_start = now - config.RATE_LIMIT_WINDOW
        
        # Clean old requests
        requests = self.user_requests[user_id]
        while requests and requests[0] < window_start:
            requests.popleft()
        
        # Check limit
        if len(requests) >= config.RATE_LIMIT_SCANS:
            # Calculate when they can scan again
            oldest_request = requests[0]
            wait_time = int(oldest_request + config.RATE_LIMIT_WINDOW - now)
            minutes = wait_time // 60
            seconds = wait_time % 60
            
            error_msg = (
                f"⚠️ **Rate Limit Exceeded**\n\n"
                f"You've reached the limit of {config.RATE_LIMIT_SCANS} scans per hour.\n"
                f"Please wait {minutes}m {seconds}s before scanning again.\n\n"
                f"💡 Tip: Use `/quick` for faster scans!"
            )
            return False, error_msg
        
        return True, None
    
    def check_domain_cooldown(self, user_id: int, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if domain is in cooldown period for this user
        
        Args:
            user_id: Telegram user ID
            domain: Domain being scanned
            
        Returns:
            Tuple of (allowed, error_message)
        """
        key = (user_id, domain.lower())
        now = time.time()
        
        if key in self.domain_cooldowns:
            last_scan = self.domain_cooldowns[key]
            elapsed = now - last_scan
            
            if elapsed < config.DOMAIN_COOLDOWN:
                wait_time = int(config.DOMAIN_COOLDOWN - elapsed)
                error_msg = (
                    f"⏳ **Cooldown Active**\n\n"
                    f"You scanned `{domain}` recently.\n"
                    f"Please wait {wait_time} seconds before scanning it again.\n\n"
                    f"💡 You can scan different domains in the meantime!"
                )
                return False, error_msg
        
        return True, None
    
    def check_global_rate_limit(self) -> Tuple[bool, Optional[str]]:
        """
        Check global rate limit (all users combined)
        
        Returns:
            Tuple of (allowed, error_message)
        """
        now = time.time()
        window_start = now - config.GLOBAL_RATE_WINDOW
        
        # Clean old requests
        while self.global_requests and self.global_requests[0] < window_start:
            self.global_requests.popleft()
        
        if len(self.global_requests) >= config.GLOBAL_RATE_LIMIT:
            error_msg = (
                "⚠️ **System Busy**\n\n"
                "The bot is currently handling many requests.\n"
                "Please try again in a few minutes.\n\n"
                "We appreciate your patience! 🙏"
            )
            return False, error_msg
        
        return True, None
    
    def add_request(self, user_id: int, domain: str):
        """
        Record a new scan request
        
        Args:
            user_id: Telegram user ID
            domain: Domain being scanned
        """
        now = time.time()
        
        # Add to user requests
        self.user_requests[user_id].append(now)
        
        # Update domain cooldown
        key = (user_id, domain.lower())
        self.domain_cooldowns[key] = now
        
        # Add to global requests
        self.global_requests.append(now)
    
    def start_scan(self, user_id: int, domain: str, scan_type: str):
        """
        Mark a scan as started
        
        Args:
            user_id: Telegram user ID
            domain: Domain being scanned
            scan_type: Type of scan
        """
        self.active_scans[user_id] = {
            'domain': domain,
            'scan_type': scan_type,
            'start_time': time.time()
        }
    
    def end_scan(self, user_id: int):
        """
        Mark a scan as completed
        
        Args:
            user_id: Telegram user ID
        """
        if user_id in self.active_scans:
            del self.active_scans[user_id]
    
    def get_active_scan(self, user_id: int) -> Optional[dict]:
        """
        Get active scan info for user
        
        Args:
            user_id: Telegram user ID
            
        Returns:
            Active scan info or None
        """
        return self.active_scans.get(user_id)
    
    def is_scanning(self, user_id: int) -> bool:
        """
        Check if user has an active scan
        
        Args:
            user_id: Telegram user ID
            
        Returns:
            True if scanning, False otherwise
        """
        return user_id in self.active_scans
    
    def get_user_stats(self, user_id: int) -> dict:
        """
        Get user's rate limit statistics
        
        Args:
            user_id: Telegram user ID
            
        Returns:
            Dictionary with stats
        """
        now = time.time()
        window_start = now - config.RATE_LIMIT_WINDOW
        
        # Count requests in current window
        requests = self.user_requests[user_id]
        recent_requests = sum(1 for ts in requests if ts >= window_start)
        
        # Calculate remaining scans
        remaining = max(0, config.RATE_LIMIT_SCANS - recent_requests)
        
        # Calculate reset time
        if requests:
            oldest_in_window = min((ts for ts in requests if ts >= window_start), default=now)
            reset_time = int(oldest_in_window + config.RATE_LIMIT_WINDOW - now)
        else:
            reset_time = 0
        
        return {
            'used': recent_requests,
            'limit': config.RATE_LIMIT_SCANS,
            'remaining': remaining,
            'reset_seconds': max(0, reset_time),
            'is_scanning': self.is_scanning(user_id)
        }
    
    def cleanup_old_data(self):
        """
        Clean up old data to prevent memory leaks
        """
        now = time.time()
        cutoff = now - (config.RATE_LIMIT_WINDOW * 2)
        
        # Clean domain cooldowns
        to_remove = [
            key for key, timestamp in self.domain_cooldowns.items()
            if timestamp < cutoff
        ]
        for key in to_remove:
            del self.domain_cooldowns[key]
        
        # Clean inactive scans (older than 30 minutes)
        scan_cutoff = now - 1800
        to_remove = [
            user_id for user_id, scan_info in self.active_scans.items()
            if scan_info['start_time'] < scan_cutoff
        ]
        for user_id in to_remove:
            del self.active_scans[user_id]
    
    def _start_auto_cleanup(self):
        """Start automatic cleanup timer"""
        self.cleanup_old_data()
        # Schedule next cleanup in 1 hour
        self.cleanup_timer = threading.Timer(3600, self._start_auto_cleanup)
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()
    
    def check_all_limits(self, user_id: int, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check all rate limits at once
        
        Args:
            user_id: Telegram user ID
            domain: Domain to scan
            
        Returns:
            Tuple of (allowed, error_message)
        """
        # Check if already scanning
        if self.is_scanning(user_id):
            active = self.active_scans[user_id]
            error_msg = (
                f"⏳ **Scan in Progress**\n\n"
                f"You're already scanning `{active['domain']}`\n"
                f"Please wait for it to complete or use `/cancel` to stop it."
            )
            return False, error_msg
        
        # Check global rate limit
        allowed, error = self.check_global_rate_limit()
        if not allowed:
            return allowed, error
        
        # Check user rate limit
        allowed, error = self.check_user_rate_limit(user_id)
        if not allowed:
            return allowed, error
        
        # Check domain cooldown
        allowed, error = self.check_domain_cooldown(user_id, domain)
        if not allowed:
            return allowed, error
        
        return True, None
    
    def format_stats_message(self, user_id: int) -> str:
        """
        Format user statistics as a message
        
        Args:
            user_id: Telegram user ID
            
        Returns:
            Formatted statistics message
        """
        stats = self.get_user_stats(user_id)
        
        # Progress bar
        percentage = (stats['used'] / stats['limit']) * 100
        filled = int(percentage / 10)
        bar = '█' * filled + '░' * (10 - filled)
        
        message = (
            f"📊 **Your Usage Statistics**\n\n"
            f"**Rate Limit:** {stats['used']}/{stats['limit']} scans used\n"
            f"`{bar}` {percentage:.0f}%\n\n"
            f"**Remaining:** {stats['remaining']} scans\n"
        )
        
        if stats['reset_seconds'] > 0:
            minutes = stats['reset_seconds'] // 60
            seconds = stats['reset_seconds'] % 60
            message += f"**Resets in:** {minutes}m {seconds}s\n"
        
        if stats['is_scanning']:
            active = self.active_scans[user_id]
            elapsed = int(time.time() - active['start_time'])
            message += f"\n⏳ **Active Scan:** `{active['domain']}` ({elapsed}s elapsed)\n"
        
        message += f"\n💡 Limit resets every hour"
        
        return message


# Global rate limiter instance
rate_limiter = RateLimiter()
