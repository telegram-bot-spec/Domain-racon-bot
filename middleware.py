"""
Access control middleware and decorators
"""

from functools import wraps
from datetime import datetime
from typing import List, Optional
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from database import db


def is_admin(user_id: int) -> bool:
    """Check if user is admin"""
    return user_id == config.MAIN_ADMIN_ID or user_id in config.ADMIN_USER_IDS


def admin_only(func):
    """Decorator to restrict command to admins only"""
    @wraps(func)
    async def wrapper(update, context):
        user_id = update.effective_user.id
        
        if not is_admin(user_id):
            await update.message.reply_text(
                "🔒 **Access Denied**\n\n"
                "This command is only available to administrators.",
                parse_mode='Markdown'
            )
            return
        
        return await func(update, context)
    return wrapper


def require_plan(minimum_plan: str = 'free', allow_commands: Optional[List[str]] = None):
    """
    Decorator to check if user has required plan
    
    Args:
        minimum_plan: Minimum plan required ('free', 'trial', 'basic', 'standard', 'pro', 'lifetime')
        allow_commands: Specific commands this plan can access
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(update, context):
            user_id = update.effective_user.id
            username = update.effective_user.username
            first_name = update.effective_user.first_name
            
            # Get or create user
            user = db.get_or_create_user(user_id, username, first_name)
            
            # Check if banned
            if user.get('is_banned'):
                await update.message.reply_text(
                    f"🚫 **Account Suspended**\n\n"
                    f"Your account has been banned.\n"
                    f"Reason: {user.get('ban_reason', 'Violation of terms')}\n\n"
                    f"Contact: @{config.SUPPORT_USERNAME}",
                    parse_mode='Markdown'
                )
                return
            
            # Check if plan expired
            if user.get('expires_at'):
                expires_at = user['expires_at']
                
                # Parse datetime if string
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                
                if datetime.now() > expires_at:
                    # Downgrade to free
                    db.update_user_plan(user_id, 'free', None)
                    
                    await update.message.reply_text(
                        "⏰ **Subscription Expired**\n\n"
                        f"Your {user['plan'].upper()} plan has expired.\n"
                        f"You've been downgraded to FREE tier.\n\n"
                        "Renew now: /shop",
                        parse_mode='Markdown'
                    )
                    return
            
            # Plan hierarchy
            plan_hierarchy = ['free', 'trial', 'basic', 'standard', 'pro', 'lifetime']
            user_plan_level = plan_hierarchy.index(user['plan'])
            required_plan_level = plan_hierarchy.index(minimum_plan)
            
            # Check if user has required plan
            if user_plan_level < required_plan_level:
                plan_names = {
                    'trial': 'TRIAL',
                    'basic': 'BASIC',
                    'standard': 'STANDARD',
                    'pro': 'PRO',
                    'lifetime': 'LIFETIME'
                }
                
                await update.message.reply_text(
                    f"🔒 **Premium Feature**\n\n"
                    f"This command requires **{plan_names.get(minimum_plan, minimum_plan.upper())}** plan or higher.\n\n"
                    f"Your current plan: **{user['plan'].upper()}**\n\n"
                    "Upgrade to unlock:\n"
                    "• All scan modes\n"
                    "• Full OSINT features\n"
                    "• Export results\n"
                    "• And more!\n\n"
                    "[View Plans 💎](/shop)",
                    parse_mode='Markdown'
                )
                return
            
            # Check daily scan limit for free users
            if user['plan'] == 'free':
                scans_today = user.get('scans_today', 0)
                scans_limit = user.get('scans_limit', config.FREE_TIER['daily_scan_limit'])
                
                if scans_today >= scans_limit:
                    await update.message.reply_text(
                        f"⚠️ **Daily Limit Reached**\n\n"
                        f"Free tier: {scans_today}/{scans_limit} scans used today\n\n"
                        "Upgrade for more scans:\n"
                        "• Trial: 15 scans (₹29)\n"
                        "• Basic: 50 scans (₹79)\n"
                        "• Standard: 200 scans (₹199)\n\n"
                        "[Upgrade Now 💎](/shop)",
                        parse_mode='Markdown'
                    )
                    return
            
            # Check total scan limit for paid plans
            if user['plan'] not in ['free', 'lifetime']:
                scans_limit = user.get('scans_limit', 999999)
                total_scans = user.get('total_scans', 0)
                
                # Calculate scans since subscription started
                # For simplicity, we track total_scans
                # In production, track scans per subscription period
                
                if total_scans >= scans_limit:
                    await update.message.reply_text(
                        f"⚠️ **Scan Limit Reached**\n\n"
                        f"Your {user['plan'].upper()} plan limit: {scans_limit} scans\n"
                        f"You've used: {total_scans} scans\n\n"
                        "Options:\n"
                        "• Wait for subscription renewal\n"
                        "• Upgrade to higher plan\n\n"
                        "[Upgrade Now 💎](/shop)",
                        parse_mode='Markdown'
                    )
                    return
            
            # Increment scan count
            db.increment_scan_count(user_id)
            
            # Store user info in context for use in command
            context.user_data['db_user'] = user
            
            return await func(update, context)
        return wrapper
    return decorator


def check_rate_limit(func):
    """Decorator to check rate limiting"""
    @wraps(func)
    async def wrapper(update, context):
        user_id = update.effective_user.id
        
        # Import rate limiter
        from utils.rate_limiter import rate_limiter
        
        # Check rate limits
        allowed, error_msg = rate_limiter.check_all_limits(user_id, "command")
        
        if not allowed:
            await update.message.reply_text(error_msg, parse_mode='Markdown')
            return
        
        # Add request
        rate_limiter.add_request(user_id, "command")
        
        return await func(update, context)
    return wrapper


def track_command(command_name: str):
    """Decorator to track command usage"""
    def decorator(func):
        @wraps(func)
        async def wrapper(update, context):
            user_id = update.effective_user.id
            
            # Log command usage (optional)
            # Can be used for analytics
            
            return await func(update, context)
        return wrapper
    return decorator


# Helper functions for command handlers

def get_user_info(user_id: int) -> Optional[dict]:
    """Get user information from database"""
    return db.get_user(user_id)


def format_plan_info(user: dict) -> str:
    """Format user's plan information"""
    plan = user['plan']
    plan_config = config.PRICING_PLANS.get(plan, {})
    
    message = f"**Your Plan:** {plan.upper()}\n\n"
    
    if plan == 'free':
        message += f"📊 **Usage Today:** {user.get('scans_today', 0)}/{config.FREE_TIER['daily_scan_limit']} scans\n"
        message += f"✨ **Features:** Basic scanning only\n\n"
        message += "Upgrade for more features: /shop"
    else:
        if user.get('expires_at'):
            expires_at = user['expires_at']
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            
            days_left = (expires_at - datetime.now()).days
            
            message += f"📅 **Expires:** {expires_at.strftime('%Y-%m-%d %H:%M')}\n"
            message += f"⏰ **Time Left:** {days_left} days\n"
        else:
            message += f"♾️ **Expires:** Never (Lifetime)\n"
        
        scans_limit = user.get('scans_limit')
        if scans_limit and scans_limit < 999999:
            message += f"📊 **Scans Used:** {user.get('total_scans', 0)}/{scans_limit}\n"
        else:
            message += f"📊 **Scans Used:** {user.get('total_scans', 0)} (Unlimited)\n"
        
        message += f"\n✨ **Features:**\n"
        features = plan_config.get('features', [])
        for feature in features:
            message += f"  • {feature}\n"
    
    return message


def can_use_command(user: dict, command: str) -> bool:
    """Check if user's plan allows this command"""
    plan = user['plan']
    plan_features = config.PLAN_FEATURES.get(plan, {})
    allowed_commands = plan_features.get('commands', [])
    
    if '*' in allowed_commands:
        return True
    
    return command in allowed_commands
