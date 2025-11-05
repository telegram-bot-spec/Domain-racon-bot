"""
Admin commands and management panel
"""

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from database import db
from middleware import admin_only, is_admin


@admin_only
async def adminpanel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show admin dashboard"""
    stats = db.get_statistics()
    
    message = (
        "👨‍💼 **ADMIN DASHBOARD**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📊 **STATISTICS:**\n"
        f"├─ Total Users: {stats['total_users']:,}\n"
        f"├─ Active Subscriptions: {stats['active_subscriptions']}\n"
        f"├─ Pending Verifications: {stats['pending_verifications']}\n"
        f"├─ Revenue (Month): ₹{stats['revenue_month']:,.2f}\n"
        f"└─ Revenue (All Time): ₹{stats['revenue_all_time']:,.2f}\n\n"
        "💰 **PLAN BREAKDOWN:**\n"
    )
    
    plan_breakdown = stats.get('plan_breakdown', {})
    total = stats['total_users']
    
    for plan, count in plan_breakdown.items():
        percentage = (count / total * 100) if total > 0 else 0
        emoji = config.PRICING_PLANS.get(plan, {}).get('emoji', '📦')
        if plan == 'free':
            emoji = '🆓'
        message += f"├─ {emoji} {plan.title()}: {count} ({percentage:.1f}%)\n"
    
    message += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += "⚡ **QUICK ACTIONS:**\n"
    
    keyboard = [
        [
            InlineKeyboardButton("📋 Pending", callback_data="admin_pending"),
            InlineKeyboardButton("👥 Users", callback_data="admin_users")
        ],
        [
            InlineKeyboardButton("💰 Revenue", callback_data="admin_revenue"),
            InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast")
        ],
        [
            InlineKeyboardButton("📊 Stats", callback_data="admin_stats"),
            InlineKeyboardButton("❓ Help", callback_data="admin_help")
        ]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, parse_mode='Markdown', reply_markup=reply_markup)


@admin_only
async def grant_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Grant plan to user: /grant <user_id> <plan>"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ **Usage:** `/grant <user_id> <plan>`\n\n"
            "**Plans:** trial, basic, standard, pro, lifetime\n\n"
            "**Example:** `/grant 123456789 pro`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        plan = context.args[1].lower()
        
        if plan not in config.PRICING_PLANS:
            await update.message.reply_text(
                f"❌ Invalid plan: {plan}\n\n"
                f"Available: {', '.join(config.PRICING_PLANS.keys())}"
            )
            return
        
        # Get plan info
        plan_info = config.PRICING_PLANS[plan]
        
        # Update user plan
        success = db.update_user_plan(
            target_user_id,
            plan,
            plan_info.get('duration_hours')
        )
        
        if success:
            # Log action
            admin_id = update.effective_user.id
            db.log_admin_action(
                admin_id,
                'grant_plan',
                target_user_id,
                f"Granted {plan} plan"
            )
            
            # Calculate expiry
            if plan_info.get('duration_hours'):
                from datetime import timedelta
                expires = datetime.now() + timedelta(hours=plan_info['duration_hours'])
                expires_str = expires.strftime('%Y-%m-%d %H:%M')
            else:
                expires_str = "Never (Lifetime)"
            
            await update.message.reply_text(
                f"✅ **Plan Granted**\n\n"
                f"User: `{target_user_id}`\n"
                f"Plan: **{plan.upper()}**\n"
                f"Expires: {expires_str}\n\n"
                f"User has been notified.",
                parse_mode='Markdown'
            )
            
            # Notify user
            try:
                await context.bot.send_message(
                    chat_id=target_user_id,
                    text=(
                        f"🎉 **Plan Activated!**\n\n"
                        f"You've been granted **{plan.upper()}** plan!\n"
                        f"Expires: {expires_str}\n\n"
                        f"Start scanning: /scan example.com\n"
                        f"View plan: /myplan"
                    ),
                    parse_mode='Markdown'
                )
            except:
                pass
        else:
            await update.message.reply_text("❌ Failed to grant plan. User not found?")
    
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")


@admin_only
async def revoke_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Revoke premium access: /revoke <user_id>"""
    if len(context.args) < 1:
        await update.message.reply_text(
            "❌ **Usage:** `/revoke <user_id>`\n\n"
            "**Example:** `/revoke 123456789`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        
        # Downgrade to free
        success = db.update_user_plan(target_user_id, 'free', None)
        
        if success:
            admin_id = update.effective_user.id
            db.log_admin_action(admin_id, 'revoke_plan', target_user_id, "Revoked premium access")
            
            await update.message.reply_text(
                f"✅ **Access Revoked**\n\n"
                f"User: `{target_user_id}`\n"
                f"Downgraded to: **FREE**\n\n"
                f"User has been notified.",
                parse_mode='Markdown'
            )
            
            # Notify user
            try:
                await context.bot.send_message(
                    chat_id=target_user_id,
                    text=(
                        f"⚠️ **Subscription Revoked**\n\n"
                        f"Your premium access has been revoked.\n"
                        f"You've been downgraded to FREE tier.\n\n"
                        f"Contact: @{config.SUPPORT_USERNAME}"
                    ),
                    parse_mode='Markdown'
                )
            except:
                pass
        else:
            await update.message.reply_text("❌ User not found.")
    
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")


@admin_only
async def pending_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show pending payment verifications"""
    pending = db.get_pending_transactions()
    
    if not pending:
        await update.message.reply_text(
            "✅ **No Pending Verifications**\n\n"
            "All payments are verified!",
            parse_mode='Markdown'
        )
        return
    
    message = f"📋 **PENDING VERIFICATIONS** ({len(pending)})\n"
    message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    for i, transaction in enumerate(pending[:5], 1):  # Show first 5
        username = transaction.get('username', 'Unknown')
        user_id = transaction['user_id']
        plan = transaction['plan']
        amount = transaction['amount']
        reference = transaction['reference']
        created_at = transaction['created_at']
        
        # Calculate time ago
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
        
        time_ago = datetime.now() - created_at
        if time_ago.seconds < 60:
            time_str = f"{time_ago.seconds}s ago"
        elif time_ago.seconds < 3600:
            time_str = f"{time_ago.seconds // 60}m ago"
        else:
            time_str = f"{time_ago.seconds // 3600}h ago"
        
        plan_info = config.PRICING_PLANS.get(plan, {})
        emoji = plan_info.get('emoji', '📦')
        
        message += (
            f"{i}️⃣ @{username} (ID: `{user_id}`)\n"
            f"├─ Plan: {emoji} {plan.upper()}\n"
            f"├─ Amount: ₹{amount}\n"
            f"├─ Reference: `{reference}`\n"
            f"└─ Time: {time_str}\n\n"
        )
    
    if len(pending) > 5:
        message += f"... and {len(pending) - 5} more\n\n"
    
    message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += "**Verify:** `/verify <reference>`\n"
    message += "**Reject:** `/reject <reference> <reason>`"
    
    await update.message.reply_text(message, parse_mode='Markdown')


@admin_only
async def verify_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Verify payment: /verify <reference>"""
    if len(context.args) < 1:
        await update.message.reply_text(
            "❌ **Usage:** `/verify <reference>`\n\n"
            "**Example:** `/verify RB123456789`",
            parse_mode='Markdown'
        )
        return
    
    reference = context.args[0]
    admin_id = update.effective_user.id
    
    # Get transaction
    transaction = db.get_transaction_by_reference(reference)
    
    if not transaction:
        await update.message.reply_text(f"❌ Transaction not found: `{reference}`", parse_mode='Markdown')
        return
    
    if transaction['status'] != 'pending':
        await update.message.reply_text(
            f"⚠️ Transaction already {transaction['status']}",
            parse_mode='Markdown'
        )
        return
    
    # Verify transaction
    success = db.verify_transaction(reference, admin_id, "Manually verified")
    
    if success:
        user_id = transaction['user_id']
        plan = transaction['plan']
        amount = transaction['amount']
        
        # Get plan info
        plan_info = config.PRICING_PLANS.get(plan, {})
        
        # Calculate expiry
        if plan_info.get('duration_hours'):
            from datetime import timedelta
            expires = datetime.now() + timedelta(hours=plan_info['duration_hours'])
            expires_str = expires.strftime('%Y-%m-%d %H:%M')
        else:
            expires_str = "Never (Lifetime)"
        
        # Log action
        db.log_admin_action(admin_id, 'verify_payment', user_id, f"Verified {plan} - ₹{amount}")
        
        await update.message.reply_text(
            f"✅ **PAYMENT VERIFIED**\n\n"
            f"User: `{user_id}`\n"
            f"Plan: **{plan.upper()}**\n"
            f"Amount: ₹{amount}\n"
            f"Expires: {expires_str}\n\n"
            f"✓ User notified\n"
            f"✓ Access activated\n"
            f"✓ Transaction logged",
            parse_mode='Markdown'
        )
        
        # Notify user
        try:
            await context.bot.send_message(
                chat_id=user_id,
                text=(
                    f"✅ **PAYMENT VERIFIED!**\n\n"
                    f"🎉 Welcome to **{plan.upper()} PLAN**!\n\n"
                    f"Your subscription:\n"
                    f"├─ Plan: {plan.upper()}\n"
                    f"├─ Expires: {expires_str}\n"
                    f"├─ Scans: {plan_info.get('scans_limit', 'Unlimited')}\n"
                    f"└─ Features: All unlocked\n\n"
                    f"Start scanning: /scan example.com\n\n"
                    f"Thank you for supporting Recon Bot! 💎"
                ),
                parse_mode='Markdown'
            )
        except:
            pass
    else:
        await update.message.reply_text("❌ Failed to verify transaction.")


@admin_only
async def reject_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reject payment: /reject <reference> <reason>"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ **Usage:** `/reject <reference> <reason>`\n\n"
            "**Example:** `/reject RB123456789 Invalid payment proof`",
            parse_mode='Markdown'
        )
        return
    
    reference = context.args[0]
    reason = ' '.join(context.args[1:])
    admin_id = update.effective_user.id
    
    # Get transaction
    transaction = db.get_transaction_by_reference(reference)
    
    if not transaction:
        await update.message.reply_text(f"❌ Transaction not found: `{reference}`", parse_mode='Markdown')
        return
    
    # Reject transaction
    success = db.reject_transaction(reference, admin_id, reason)
    
    if success:
        user_id = transaction['user_id']
        
        db.log_admin_action(admin_id, 'reject_payment', user_id, f"Rejected: {reason}")
        
        await update.message.reply_text(
            f"❌ **PAYMENT REJECTED**\n\n"
            f"User: `{user_id}`\n"
            f"Reference: `{reference}`\n"
            f"Reason: {reason}\n\n"
            f"✓ User notified",
            parse_mode='Markdown'
        )
        
        # Notify user
        try:
            await context.bot.send_message(
                chat_id=user_id,
                text=(
                    f"❌ **Payment Rejected**\n\n"
                    f"Reference: `{reference}`\n"
                    f"Reason: {reason}\n\n"
                    f"If you believe this is an error, please contact:\n"
                    f"@{config.SUPPORT_USERNAME}"
                ),
                parse_mode='Markdown'
            )
        except:
            pass
    else:
        await update.message.reply_text("❌ Failed to reject transaction.")


@admin_only
async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ban user: /ban <user_id> <reason>"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ **Usage:** `/ban <user_id> <reason>`\n\n"
            "**Example:** `/ban 123456789 Abuse`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        reason = ' '.join(context.args[1:])
        
        success = db.ban_user(target_user_id, reason)
        
        if success:
            admin_id = update.effective_user.id
            db.log_admin_action(admin_id, 'ban_user', target_user_id, reason)
            
            await update.message.reply_text(
                f"🚫 **User Banned**\n\n"
                f"User: `{target_user_id}`\n"
                f"Reason: {reason}\n\n"
                f"User cannot use the bot anymore.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text("❌ User not found.")
    
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")


@admin_only
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unban user: /unban <user_id>"""
    if len(context.args) < 1:
        await update.message.reply_text(
            "❌ **Usage:** `/unban <user_id>`\n\n"
            "**Example:** `/unban 123456789`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        
        success = db.unban_user(target_user_id)
        
        if success:
            admin_id = update.effective_user.id
            db.log_admin_action(admin_id, 'unban_user', target_user_id, "Unbanned")
            
            await update.message.reply_text(
                f"✅ **User Unbanned**\n\n"
                f"User: `{target_user_id}`\n\n"
                f"User can now use the bot again.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text("❌ User not found.")
    
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")


@admin_only
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show detailed statistics"""
    stats = db.get_statistics()
    
    message = (
        "📊 **DETAILED STATISTICS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "👥 **USERS:**\n"
        f"Total: {stats['total_users']:,}\n"
        f"Active Paid: {stats['active_subscriptions']}\n"
        f"Free Users: {stats['plan_breakdown'].get('free', 0):,}\n\n"
        "💰 **REVENUE:**\n"
        f"All Time: ₹{stats['revenue_all_time']:,.2f}\n"
        f"This Month: ₹{stats['revenue_month']:,.2f}\n\n"
        "📋 **PENDING:**\n"
        f"Verifications: {stats['pending_verifications']}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    
    await update.message.reply_text(message, parse_mode='Markdown')


@admin_only
async def adminhelp_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show admin commands help"""
    message = (
        "🔐 **ADMIN COMMANDS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "**USER MANAGEMENT:**\n"
        "`/grant <user_id> <plan>` - Grant plan\n"
        "`/revoke <user_id>` - Revoke access\n"
        "`/ban <user_id> <reason>` - Ban user\n"
        "`/unban <user_id>` - Unban user\n\n"
        "**PAYMENT VERIFICATION:**\n"
        "`/pending` - Show pending payments\n"
        "`/verify <reference>` - Verify payment\n"
        "`/reject <reference> <reason>` - Reject\n\n"
        "**ANALYTICS:**\n"
        "`/stats` - Detailed statistics\n"
        "`/adminpanel` - Admin dashboard\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    
    await update.message.reply_text(message, parse_mode='Markdown')
