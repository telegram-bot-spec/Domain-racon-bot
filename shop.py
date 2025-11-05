"""
Shop system and payment handling
"""

import time
import qrcode
from io import BytesIO
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from database import db
from middleware import get_user_info


async def shop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display pricing plans"""
    user_id = update.effective_user.id
    user = db.get_or_create_user(user_id, update.effective_user.username, update.effective_user.first_name)
    
    message = (
        "💎 **RECON BOT - PREMIUM PLANS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🆓 **FREE TIER** (Your Current Plan)\n"
        f"{'━' * 30}\n"
        "✓ 5 scans per day\n"
        "✓ Basic features only\n"
        "✓ /quick scan only\n"
        f"{'━' * 30}\n\n"
    )
    
    keyboard = []
    
    # Add each plan
    for plan_id, plan_info in config.PRICING_PLANS.items():
        emoji = plan_info.get('emoji', '📦')
        name = plan_info['name']
        price = plan_info['price_inr']
        
        # Plan description
        if plan_id == 'standard':
            message += f"{emoji} **{name.upper()}** (1 Week) - ₹{price} 🔥 **POPULAR**\n"
        elif plan_id == 'lifetime':
            message += f"{emoji} **{name.upper()}** - ₹{price} 💎 **BEST VALUE**\n"
        else:
            duration = plan_info.get('duration_hours', 0)
            if duration < 24:
                duration_str = f"{duration}h"
            elif duration < 168:
                duration_str = f"{duration // 24}d"
            else:
                duration_str = f"{duration // 168}w"
            message += f"{emoji} **{name.upper()}** ({duration_str}) - ₹{price}\n"
        
        # Features
        features = plan_info.get('features', [])
        for feature in features[:3]:  # Show first 3 features
            message += f"  • {feature}\n"
        
        message += f"\n"
        
        # Add button
        keyboard.append([
            InlineKeyboardButton(
                f"{emoji} Buy {name} - ₹{price}",
                callback_data=f"buy_{plan_id}"
            )
        ])
    
    # Add utility buttons
    keyboard.append([
        InlineKeyboardButton("📊 Compare Plans", callback_data="compare_plans"),
        InlineKeyboardButton("❓ FAQ", callback_data="faq")
    ])
    
    message += (
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💬 Support: @{config.SUPPORT_USERNAME}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, parse_mode='Markdown', reply_markup=reply_markup)


async def buy_plan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle buy plan button click"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    plan_id = query.data.replace('buy_', '')
    
    # Get plan info
    plan_info = config.PRICING_PLANS.get(plan_id)
    if not plan_info:
        await query.edit_message_text("❌ Invalid plan selected.")
        return
    
    # Generate reference code
    reference = f"RB{user_id}{int(time.time())}"
    
    # Create transaction in database
    db.create_transaction(
        user_id=user_id,
        plan=plan_id,
        amount=plan_info['price_inr'],
        reference=reference
    )
    
    # Generate payment details
    await send_payment_details(query, plan_id, plan_info, reference)


async def send_payment_details(query, plan_id: str, plan_info: dict, reference: str):
    """Send payment QR code and instructions"""
    user_id = query.from_user.id
    
    # Plan details
    plan_name = plan_info['name']
    amount = plan_info['price_inr']
    emoji = plan_info.get('emoji', '💎')
    
    # Duration string
    duration_hours = plan_info.get('duration_hours')
    if duration_hours is None:
        duration_str = "Lifetime"
    elif duration_hours < 24:
        duration_str = f"{duration_hours} Hour"
    elif duration_hours < 168:
        duration_str = f"{duration_hours // 24} Day"
    else:
        duration_str = f"{duration_hours // 168} Week"
    
    # Generate UPI payment string
    upi_string = (
        f"upi://pay"
        f"?pa={config.UPI_ID}"
        f"&pn={config.UPI_NAME}"
        f"&am={amount}"
        f"&cu=INR"
        f"&tn=ReconBot-{reference}"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(upi_string)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to bytes
    bio = BytesIO()
    bio.name = 'payment_qr.png'
    img.save(bio, 'PNG')
    bio.seek(0)
    
    # Payment message
    message = (
        f"✅ **{plan_name.upper()} PLAN** ({duration_str})\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"💰 **Amount:** ₹{amount}\n\n"
        f"📱 **SCAN THIS QR CODE TO PAY:**\n"
        f"(QR code sent below)\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💳 **MANUAL PAYMENT:**\n"
        f"UPI ID: `{config.UPI_ID}`\n"
        f"Name: {config.UPI_NAME}\n"
        f"Amount: ₹{amount}\n"
        f"Message: `{reference}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📸 **AFTER PAYMENT:**\n"
        f"1. Take screenshot of payment success\n"
        f"2. Send to: @{config.SUPPORT_USERNAME}\n"
        f"3. Include this code: `{reference}`\n"
        f"4. Wait for activation (~30 min)\n\n"
        f"⚠️ **IMPORTANT:**\n"
        f"• Manual verification by admin\n"
        f"• Keep payment proof\n"
        f"• No refunds after activation\n\n"
        f"Need help? Contact: @{config.SUPPORT_USERNAME}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    
    # Send QR code
    await query.message.reply_photo(
        photo=bio,
        caption=message,
        parse_mode='Markdown'
    )


async def myplan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show user's current plan"""
    user_id = update.effective_user.id
    user = db.get_or_create_user(user_id, update.effective_user.username, update.effective_user.first_name)
    
    from middleware import format_plan_info
    
    message = "📊 **MY SUBSCRIPTION**\n"
    message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    message += format_plan_info(user)
    message += "\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    
    keyboard = []
    
    if user['plan'] == 'free':
        keyboard.append([InlineKeyboardButton("💎 Upgrade Now", callback_data="shop")])
    else:
        keyboard.append([
            InlineKeyboardButton("⬆️ Upgrade", callback_data="shop"),
            InlineKeyboardButton("📜 History", callback_data="history")
        ])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, parse_mode='Markdown', reply_markup=reply_markup)


async def compare_plans_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show detailed plan comparison"""
    query = update.callback_query
    await query.answer()
    
    message = (
        "📊 **PLAN COMPARISON**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    )
    
    comparison = {
        '🆓 FREE': {
            'price': 'Free',
            'scans': '5/day',
            'modes': 'Quick only',
            'osint': '❌',
            'export': '❌',
        },
        '⏰ TRIAL': {
            'price': '₹29',
            'scans': '15 total',
            'modes': 'All basic',
            'osint': '⚠️ Limited',
            'export': '❌',
        },
        '📦 BASIC': {
            'price': '₹79',
            'scans': '50 total',
            'modes': 'All scans',
            'osint': '✅ Basic',
            'export': '⚠️ Limited',
        },
        '⭐ STANDARD': {
            'price': '₹199',
            'scans': '200 total',
            'modes': 'All + Deep',
            'osint': '✅ Full',
            'export': '✅ Yes',
        },
        '🚀 PRO': {
            'price': '₹499',
            'scans': '1000 total',
            'modes': 'All + Ninja',
            'osint': '✅ Full',
            'export': '✅ Yes',
        },
        '♾️ LIFETIME': {
            'price': '₹1999',
            'scans': '♾️ Unlimited',
            'modes': 'All modes',
            'osint': '✅ Full',
            'export': '✅ Yes',
        },
    }
    
    for plan, features in comparison.items():
        message += f"**{plan}** - {features['price']}\n"
        message += f"  Scans: {features['scans']}\n"
        message += f"  Modes: {features['modes']}\n"
        message += f"  OSINT: {features['osint']}\n"
        message += f"  Export: {features['export']}\n\n"
    
    message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += "💡 **Recommendation:**\n"
    message += "• Trial: Test features\n"
    message += "• Standard: Most popular\n"
    message += "• Lifetime: Best value\n\n"
    
    keyboard = [[InlineKeyboardButton("🛒 View Shop", callback_data="shop")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)


async def faq_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show FAQ"""
    query = update.callback_query
    await query.answer()
    
    message = (
        "❓ **FREQUENTLY ASKED QUESTIONS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "**Q: How do I pay?**\n"
        "A: Use UPI (Google Pay, PhonePe, Paytm, etc.) to scan QR code or send to UPI ID.\n\n"
        "**Q: How long for activation?**\n"
        "A: Usually within 30 minutes. Admin verifies manually.\n\n"
        "**Q: Can I get refund?**\n"
        "A: No refunds after activation. Test with Trial plan first!\n\n"
        "**Q: What if payment fails?**\n"
        f"A: Contact @{config.SUPPORT_USERNAME} with proof.\n\n"
        "**Q: Does plan auto-renew?**\n"
        "A: No, manual payment required each time.\n\n"
        "**Q: Lifetime means forever?**\n"
        "A: Yes! One-time payment, access forever.\n\n"
        "**Q: Can I upgrade mid-plan?**\n"
        "A: Yes! Contact admin for upgrade.\n\n"
        "**Q: Is my payment secure?**\n"
        "A: Yes! Direct UPI to admin, no bot access.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"More questions? Ask @{config.SUPPORT_USERNAME}"
    )
    
    keyboard = [[InlineKeyboardButton("🛒 View Shop", callback_data="shop")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)


async def shop_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Callback to show shop (from inline button)"""
    query = update.callback_query
    await query.answer()
    
    # Simulate shop command but edit message
    user_id = query.from_user.id
    user = db.get_or_create_user(user_id, query.from_user.username, query.from_user.first_name)
    
    message = (
        "💎 **RECON BOT - PREMIUM PLANS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    )
    
    keyboard = []
    
    for plan_id, plan_info in config.PRICING_PLANS.items():
        emoji = plan_info.get('emoji', '📦')
        name = plan_info['name']
        price = plan_info['price_inr']
        
        keyboard.append([
            InlineKeyboardButton(
                f"{emoji} {name} - ₹{price}",
                callback_data=f"buy_{plan_id}"
            )
        ])
    
    keyboard.append([
        InlineKeyboardButton("📊 Compare", callback_data="compare_plans"),
        InlineKeyboardButton("❓ FAQ", callback_data="faq")
    ])
    
    message += (
        "Choose a plan to see payment details.\n\n"
        f"Current plan: **{user['plan'].upper()}**\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)
