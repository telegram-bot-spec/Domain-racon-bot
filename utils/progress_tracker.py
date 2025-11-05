"""
Real-time progress tracking for scan operations
"""

import time
import asyncio
import sys
import os
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class ModuleStatus(Enum):
    """Status of a scan module"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleProgress:
    """Progress information for a single module"""
    name: str
    status: ModuleStatus = ModuleStatus.PENDING
    progress: float = 0.0  # 0-100
    message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    
    def duration(self) -> float:
        """Get module execution duration"""
        if self.start_time:
            end = self.end_time or time.time()
            return end - self.start_time
        return 0.0


class ProgressTracker:
    """
    Track progress of multiple concurrent scan modules with real-time updates
    """
    
    def __init__(self, domain: str, scan_type: str, update_callback: Optional[Callable] = None):
        """
        Initialize progress tracker
        
        Args:
            domain: Domain being scanned
            scan_type: Type of scan (quick, smart, deep, ninja)
            update_callback: Async function to call when progress updates
        """
        self.domain = domain
        self.scan_type = scan_type
        self.update_callback = update_callback
        
        # Module tracking
        self.modules: Dict[str, ModuleProgress] = {}
        
        # Overall progress
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        
        # Update tracking
        self.last_update_time = 0
        self.update_interval = 2.0  # Minimum seconds between UI updates
        self.force_update = False
        
        # Results storage
        self.results: Dict[str, Any] = {}
        
        # Lock for thread-safe updates
        self._update_lock = asyncio.Lock()
        
    def add_module(self, module_name: str, display_name: Optional[str] = None):
        """
        Add a module to track
        
        Args:
            module_name: Internal module name
            display_name: User-friendly display name
        """
        self.modules[module_name] = ModuleProgress(
            name=display_name or module_name.replace('_', ' ').title()
        )
    
    def start_module(self, module_name: str, message: Optional[str] = None):
        """
        Mark module as started
        
        Args:
            module_name: Module name
            message: Optional status message
        """
        if module_name in self.modules:
            module = self.modules[module_name]
            module.status = ModuleStatus.RUNNING
            module.start_time = time.time()
            module.progress = 0.0
            if message:
                module.message = message
            
            self.force_update = True
            try:
                asyncio.create_task(self._trigger_update())
            except RuntimeError:
                pass  # No event loop running, skip update
    
    def update_module(self, module_name: str, progress: float, message: Optional[str] = None):
        """
        Update module progress
        
        Args:
            module_name: Module name
            progress: Progress percentage (0-100)
            message: Optional status message
        """
        if module_name in self.modules:
            module = self.modules[module_name]
            module.progress = min(100.0, max(0.0, progress))
            if message:
                module.message = message
            
            try:
                asyncio.create_task(self._trigger_update())
            except RuntimeError:
                pass  # No event loop running, skip update
    
    def complete_module(self, module_name: str, result: Any = None, message: Optional[str] = None):
        """
        Mark module as completed
        
        Args:
            module_name: Module name
            result: Module result data
            message: Optional completion message
        """
        if module_name in self.modules:
            module = self.modules[module_name]
            module.status = ModuleStatus.COMPLETED
            module.progress = 100.0
            module.end_time = time.time()
            module.result = result
            if message:
                module.message = message
            
            # Store result
            if result is not None:
                self.results[module_name] = result
            
            self.force_update = True
            try:
                asyncio.create_task(self._trigger_update())
            except RuntimeError:
                pass  # No event loop running, skip update
    
    def fail_module(self, module_name: str, error: str):
        """
        Mark module as failed
        
        Args:
            module_name: Module name
            error: Error message
        """
        if module_name in self.modules:
            module = self.modules[module_name]
            module.status = ModuleStatus.FAILED
            module.end_time = time.time()
            module.error = error
            module.message = f"Failed: {error}"
            
            self.force_update = True
            try:
                asyncio.create_task(self._trigger_update())
            except RuntimeError:
                pass  # No event loop running, skip update
    
    def skip_module(self, module_name: str, reason: str):
        """
        Mark module as skipped
        
        Args:
            module_name: Module name
            reason: Reason for skipping
        """
        if module_name in self.modules:
            module = self.modules[module_name]
            module.status = ModuleStatus.SKIPPED
            module.message = f"Skipped: {reason}"
            
            try:
                asyncio.create_task(self._trigger_update())
            except RuntimeError:
                pass  # No event loop running, skip update
    
    async def _trigger_update(self):
        """Trigger UI update if callback is set and enough time has passed"""
        if not self.update_callback:
            return
        
        async with self._update_lock:
            now = time.time()
            
            # Only update if enough time passed or force update
            if self.force_update or (now - self.last_update_time) >= self.update_interval:
                self.last_update_time = now
                self.force_update = False
                
                try:
                    await self.update_callback(self.format_progress())
                except Exception as e:
                    pass  # Ignore update errors
    
    def format_progress(self) -> str:
        """
        Format current progress as a message
        
        Returns:
            Formatted progress message
        """
        separator = "━" * 30
        
        # Header
        scan_mode = config.SCAN_MODES.get(self.scan_type, {})
        emoji = scan_mode.get('emoji', '🔍')
        
        message = f"{emoji} **SCANNING: {self.domain}**\n{separator}\n\n"
        
        # Overall progress
        total_modules = len(self.modules)
        completed = sum(1 for m in self.modules.values() 
                       if m.status in [ModuleStatus.COMPLETED, ModuleStatus.FAILED, ModuleStatus.SKIPPED])
        
        overall_percentage = (completed / total_modules * 100) if total_modules > 0 else 0
        
        message += f"**Progress:** {completed}/{total_modules} modules\n"
        message += self._create_progress_bar(overall_percentage) + "\n\n"
        
        # Elapsed time
        elapsed = time.time() - self.start_time
        message += f"⏱️ **Elapsed:** {self._format_duration(elapsed)}\n\n"
        
        # Module statuses
        message += "**Status:**\n"
        
        for module_name, module in self.modules.items():
            status_emoji = self._get_status_emoji(module.status)
            
            line = f"{status_emoji} {module.name}"
            
            if module.status == ModuleStatus.RUNNING:
                if module.progress > 0:
                    line += f" ({module.progress:.0f}%)"
                else:
                    line += " ..."
            elif module.status == ModuleStatus.COMPLETED:
                duration = module.duration()
                line += f" ✓ ({duration:.1f}s)"
            elif module.status == ModuleStatus.FAILED:
                line += " ✗"
            
            message += line + "\n"
            
            # Add module message if present
            if module.message and module.status == ModuleStatus.RUNNING:
                message += f"  └─ {module.message}\n"
        
        message += f"\n{separator}"
        
        return message
    
    def format_summary(self) -> str:
        """
        Format final summary after scan completes
        
        Returns:
            Formatted summary message
        """
        self.end_time = time.time()
        total_duration = self.end_time - self.start_time
        
        separator = "━" * 30
        
        # Header
        message = f"✅ **SCAN COMPLETE**\n{separator}\n\n"
        message += f"🌐 **Domain:** {self.domain}\n"
        message += f"⏱️ **Duration:** {self._format_duration(total_duration)}\n\n"
        
        # Results summary
        completed = sum(1 for m in self.modules.values() if m.status == ModuleStatus.COMPLETED)
        failed = sum(1 for m in self.modules.values() if m.status == ModuleStatus.FAILED)
        skipped = sum(1 for m in self.modules.values() if m.status == ModuleStatus.SKIPPED)
        
        message += f"**Results:**\n"
        message += f"├─ {config.EMOJI['success']} Completed: {completed}\n"
        
        if failed > 0:
            message += f"├─ {config.EMOJI['error']} Failed: {failed}\n"
        
        if skipped > 0:
            message += f"├─ {config.EMOJI['warning']} Skipped: {skipped}\n"
        
        message += f"└─ **Total:** {len(self.modules)}\n\n"
        
        # Failed modules details
        if failed > 0:
            message += "**Failed Modules:**\n"
            for module_name, module in self.modules.items():
                if module.status == ModuleStatus.FAILED:
                    message += f"├─ {module.name}: {module.error}\n"
            message += "\n"
        
        message += f"{separator}\n"
        message += "📊 Generating detailed report...\n"
        
        return message
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get all module results
        
        Returns:
            Dictionary of module results
        """
        return self.results
    
    def is_complete(self) -> bool:
        """
        Check if all modules are complete
        
        Returns:
            True if all modules finished
        """
        return all(
            m.status in [ModuleStatus.COMPLETED, ModuleStatus.FAILED, ModuleStatus.SKIPPED]
            for m in self.modules.values()
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get scan statistics
        
        Returns:
            Dictionary of statistics
        """
        total_duration = (self.end_time or time.time()) - self.start_time
        
        return {
            'domain': self.domain,
            'scan_type': self.scan_type,
            'total_duration': total_duration,
            'modules_total': len(self.modules),
            'modules_completed': sum(1 for m in self.modules.values() if m.status == ModuleStatus.COMPLETED),
            'modules_failed': sum(1 for m in self.modules.values() if m.status == ModuleStatus.FAILED),
            'modules_skipped': sum(1 for m in self.modules.values() if m.status == ModuleStatus.SKIPPED),
            'fastest_module': self._get_fastest_module(),
            'slowest_module': self._get_slowest_module(),
        }
    
    def _get_fastest_module(self) -> Optional[tuple]:
        """Get fastest completed module"""
        completed = [m for m in self.modules.values() if m.status == ModuleStatus.COMPLETED and m.duration() > 0]
        if completed:
            fastest = min(completed, key=lambda m: m.duration())
            return (fastest.name, fastest.duration())
        return None
    
    def _get_slowest_module(self) -> Optional[tuple]:
        """Get slowest completed module"""
        completed = [m for m in self.modules.values() if m.status == ModuleStatus.COMPLETED]
        if completed:
            slowest = max(completed, key=lambda m: m.duration())
            return (slowest.name, slowest.duration())
        return None
    
    def _create_progress_bar(self, percentage: float, length: int = 15) -> str:
        """Create ASCII progress bar"""
        filled = int((percentage / 100) * length)
        empty = length - filled
        bar = '█' * filled + '░' * empty
        return f"[{bar}] {percentage:.0f}%"
    
    def _get_status_emoji(self, status: ModuleStatus) -> str:
        """Get emoji for module status"""
        emoji_map = {
            ModuleStatus.PENDING: '⏳',
            ModuleStatus.RUNNING: '🔄',
            ModuleStatus.COMPLETED: '✅',
            ModuleStatus.FAILED: '❌',
            ModuleStatus.SKIPPED: '⏭️',
        }
        return emoji_map.get(status, '❓')
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
    
    def export_progress_data(self) -> Dict[str, Any]:
        """
        Export progress data for debugging or logging
        
        Returns:
            Dictionary with complete progress data
        """
        return {
            'domain': self.domain,
            'scan_type': self.scan_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'modules': {
                name: {
                    'status': module.status.value,
                    'progress': module.progress,
                    'message': module.message,
                    'duration': module.duration(),
                    'error': module.error,
                }
                for name, module in self.modules.items()
            },
            'statistics': self.get_statistics(),
        }


# Helper function to create tracker for scan modes
def create_tracker_for_scan(domain: str, scan_type: str, update_callback: Optional[Callable] = None) -> ProgressTracker:
    """
    Create a progress tracker configured for a specific scan type
    
    Args:
        domain: Domain to scan
        scan_type: Type of scan (quick, smart, deep, ninja)
        update_callback: Callback for progress updates
        
    Returns:
        Configured ProgressTracker instance
    """
    tracker = ProgressTracker(domain, scan_type, update_callback)
    
    # Add modules based on scan type
    scan_config = config.SCAN_MODES.get(scan_type, config.SCAN_MODES['smart'])
    modules = scan_config.get('modules', [])
    
    # Module display names
    module_names = {
        'dns_basic': 'DNS Lookup',
        'dns': 'DNS Analysis',
        'dns_full': 'DNS Deep Scan',
        'subdomains_basic': 'Subdomain Discovery',
        'subdomains': 'Subdomain Enumeration',
        'subdomains_full': 'Subdomain Deep Scan',
        'whois': 'WHOIS Lookup',
        'tech_basic': 'Tech Detection',
        'tech': 'Technology Stack',
        'tech_full': 'Full Tech Analysis',
        'security_headers': 'Security Headers',
        'security': 'Security Analysis',
        'security_full': 'Deep Security Audit',
        'ip_geo': 'IP Geolocation',
        'ip': 'IP Intelligence',
        'ip_full': 'Full IP Analysis',
        'social_basic': 'Social Media Check',
        'social_full': 'Social Media Deep Scan',
        'ports_quick': 'Port Scan (Quick)',
        'ports_full': 'Port Scan (Full)',
        'ports_stealth': 'Port Scan (Stealth)',
        'emails': 'Email Harvesting',
        'github_secrets': 'GitHub Secret Scan',
        'reputation': 'Reputation Check',
        'content': 'Content Analysis',
        'api_discovery': 'API Discovery',
    }
    
    for module in modules:
        display_name = module_names.get(module, module.replace('_', ' ').title())
        tracker.add_module(module, display_name)
    
    return tracker
