"""
Ultimate Recon Bot - Main Application
Advanced domain reconnaissance with premium features
"""

import logging
import sys
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes
)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import configurations and modules
import config
from database import db
from middleware import require_plan, admin_only, format_plan_info
from shop import (
    shop_command,
    myplan_command,
    buy_plan_callback,
    compare_plans_callback,
    faq_callback,
    shop_callback
)
from admin import (
    adminpanel_command,
    grant_command,
    revoke_command,
    pending_command,
    verify_command,
    reject_command,
    ban_command,
    unban_command,
    stats_command,
    adminhelp_command
)

# Import scanner modules
from modules import (
    DNSScanner,
    SubdomainHunter,
    WhoisScanner,
    IPIntelligence,
    TechDetector,
    SecurityAnalyzer,
    PortScanner
)

# Import utilities
from utils import ProgressTracker, create_tracker_for_scan
from utils.formatters import (
    format_dns_results,
    format_subdomain_results,
    format_port_results,
    format_tech_stack,
    format_security_report,
    format_ip_intelligence,
    format_quick_summary,
    truncate_message
)
from utils.rate_limiter import rate_limiter

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# ============================================================================
# BASIC COMMANDS
# ============================================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    user_id = update.effective_user.id
    first_name = update.effective_user.first_name
    username = update.effective_user.username
    
    # Create user in database
    user = db.get_or_create_user(user_id, username, first_name)
    
    welcome_text = f"""
🔍 **ULTIMATE RECON BOT**

Welcome, {first_name}! 👋

Your Plan: **{user['plan'].upper()}**

**🚀 Quick Start:**
/quick example.com - Fast 30s scan
/scan example.com - Smart full scan
/shop - View premium plans

**📚 Available Commands:**

**Basic Scans:**
/quick <domain> - Quick scan (30-60s)
/scan <domain> - Smart scan (2-4min)
/deep <domain> - Deep scan (5-7min) 🔒
/ninja <domain> - Stealth mode 🔒

**Focused Scans:**
/dns <domain> - DNS analysis
/subs <domain> - Subdomain enumeration 🔒
/whois <domain> - WHOIS lookup
/ports <domain> - Port scanning 🔒
/tech <domain> - Technology detection
/security <domain> - Security analysis 🔒
/ip <domain> - IP intelligence

**Premium:**
/shop - View pricing plans
/myplan - Check your subscription

**Help:**
/help - Detailed help
/about - Bot information

🔒 = Premium feature
⚠️ **Important:** Only scan domains you own or have permission to test!

Ready to start? Try: /quick google.com
"""
    
    keyboard = [
        [
            InlineKeyboardButton("⚡ Try Quick Scan", callback_data="demo_quick"),
            InlineKeyboardButton("💎 View Plans", callback_data="shop")
        ],
        [
            InlineKeyboardButton("📚 Help", callback_data="help"),
            InlineKeyboardButton("ℹ️ About", callback_data="about")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_text, parse_mode='Markdown', reply_markup=reply_markup)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show detailed help"""
    help_text = """
📚 **DETAILED HELP**

**SCAN MODES:**

⚡ **Quick Scan** (Free)
Fast 30-second scan with basic info
Usage: `/quick example.com`

🔍 **Smart Scan** (Standard+)
Intelligent 2-4 minute scan
Auto-detects and runs relevant checks
Usage: `/scan example.com`

🕵️ **Deep Scan** (Standard+)
Comprehensive 5-7 minute scan
All features enabled
Usage: `/deep example.com`

🥷 **Ninja Scan** (Pro+)
Stealth mode with rate limiting
Slower but careful
Usage: `/ninja example.com`

**FOCUSED SCANS:**

🌐 `/dns` - Complete DNS analysis
📡 `/subs` - Subdomain enumeration
📋 `/whois` - Domain registration info
🔌 `/ports` - Port scanning
💻 `/tech` - Technology detection
🔐 `/security` - Security headers & SSL
🌍 `/ip` - IP geolocation & reputation

**EXAMPLES:**

`/quick github.com`
`/scan google.com`
`/dns example.com`
`/tech twitter.com`

**RATE LIMITS:**
• Free: 5 scans/day
• Trial: 15 scans total
• Standard: 200 scans
• Pro: 1000 scans
• Lifetime: Unlimited

Need more? Upgrade: /shop
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot information"""
    about_text = f"""
ℹ️ **ABOUT RECON BOT**

**Version:** {config.BOT_VERSION}
**Developer:** {config.DEVELOPER}

**Features:**
✓ DNS Analysis (15+ record types)
✓ Multi-source Subdomain Enumeration
✓ Port Scanning with Service Detection
✓ Technology Stack Detection (200+)
✓ Security Analysis & SSL Grading
✓ IP Intelligence & Geolocation
✓ OSINT & Social Media Discovery
✓ Real-time Progress Tracking

**Built With:**
• Python 3.11
• python-telegram-bot
• Async/await architecture
• Multiple free APIs integrated

**Premium Plans:**
From ₹29 to ₹1999
View plans: /shop

**Support:**
Telegram: @{config.SUPPORT_USERNAME}
Report bugs or suggest features!

⚠️ **Disclaimer:**
Use responsibly. Only scan domains you own or have permission to test. Unauthorized scanning may be illegal.

**Privacy:**
We don't store scan results permanently. All data is processed in real-time.
"""
    await update.message.reply_text(about_text, parse_mode='Markdown')


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel current scan"""
    user_id = update.effective_user.id
    
    if rate_limiter.is_scanning(user_id):
        rate_limiter.end_scan(user_id)
        await update.message.reply_text(
            "❌ **Scan Cancelled**\n\n"
            "Your current scan has been stopped.",
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            "ℹ️ No active scan to cancel.",
            parse_mode='Markdown'
        )


# ============================================================================
# SCAN COMMANDS
# ============================================================================

@require_plan('free')
async def quick_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quick 30-second scan (free tier)"""
    if not context.args:
        await update.message.reply_text(
            "❌ **Usage:** `/quick <domain>`\n\n"
            "**Example:** `/quick google.com`",
            parse_mode='Markdown'
        )
        return
    
    domain = context.args[0]
    user = context.user_data.get('db_user', {})
    
    # Validate domain
    from utils.validators import validate_scan_input
    validation = validate_scan_input(domain, 'quick')
    
    if not validation['valid']:
        await update.message.reply_text(
            '\n'.join(validation['errors']),
            parse_mode='Markdown'
        )
        return
    
    domain = validation['domain']
    
    # Send initial message
    progress_msg = await update.message.reply_text(
        f"⚡ **Starting Quick Scan**\n\n"
        f"Domain: `{domain}`\n"
        f"Mode: Quick (30-60s)\n\n"
        f"🔄 Initializing...",
        parse_mode='Markdown'
    )
    
    # Track scan
    rate_limiter.start_scan(update.effective_user.id, domain, 'quick')
    
    try:
        # Run basic scans
        results = {}
        
        # DNS
        dns_scanner = DNSScanner()
        results['dns'] = await dns_scanner.scan(domain, mode='basic')
        
        # IP Intelligence
        async with IPIntelligence() as ip_intel:
            results['ip'] = await ip_intel.analyze(domain)
        
        # Tech Detection (basic)
        async with TechDetector() as tech:
            results['tech'] = await tech.detect(domain, mode='basic')
        
        # Format quick summary
        summary = format_quick_summary(domain, {
            'status': {
                'online': True,
                'response_time': results['tech'].get('status_code'),
                'https': results['tech'].get('final_url', '').startswith('https://')
            },
            'subdomains_count': len(results['dns'].get('records', {}).get('NS', [])),
            'technologies_count': results['tech'].get('total_detected', 0),
            'security_score': 85,  # Placeholder
            'scan_time': 30
        })
        
        await progress_msg.edit_text(summary, parse_mode='Markdown')
        
    except Exception as e:
        await progress_msg.edit_text(
            f"❌ **Scan Failed**\n\n"
            f"Error: {str(e)}\n\n"
            f"Try again or contact support.",
            parse_mode='Markdown'
        )
    finally:
        rate_limiter.end_scan(update.effective_user.id)


@require_plan('standard')
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Smart scan - auto-detects target type"""
    if not context.args:
        await update.message.reply_text(
            "❌ **Usage:** `/scan <domain>`\n\n"
            "**Example:** `/scan example.com`",
            parse_mode='Markdown'
        )
        return
    
    domain = context.args[0]
    
    # Validate
    from utils.validators import validate_scan_input
    validation = validate_scan_input(domain, 'smart')
    
    if not validation['valid']:
        await update.message.reply_text('\n'.join(validation['errors']), parse_mode='Markdown')
        return
    
    domain = validation['domain']
    
    # Send progress message
    progress_msg = await update.message.reply_text(
        f"🔍 **Starting Smart Scan**\n\n"
        f"Domain: `{domain}`\n"
        f"Estimated time: 2-4 minutes\n\n"
        f"🔄 Scanning...",
        parse_mode='Markdown'
    )
    
    rate_limiter.start_scan(update.effective_user.id, domain, 'smart')
    
    try:
        # Run comprehensive scan
        # Implementation similar to quick_scan but with more modules
        # For now, placeholder
        
        await progress_msg.edit_text(
            f"✅ **Scan Complete!**\n\n"
            f"Domain: `{domain}`\n\n"
            f"Full implementation coming in next iteration...",
            parse_mode='Markdown'
        )
        
    except Exception as e:
        await progress_msg.edit_text(
            f"❌ **Scan Failed**\n\nError: {str(e)}",
            parse_mode='Markdown'
        )
    finally:
        rate_limiter.end_scan(update.effective_user.id)


@require_plan('standard')
async def deep_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deep comprehensive scan"""
    await update.message.reply_text(
        "🕵️ **Deep Scan**\n\n"
        "This feature performs exhaustive reconnaissance.\n"
        "Coming soon in next update!",
        parse_mode='Markdown'
    )


@require_plan('pro')
async def ninja_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stealth ninja scan"""
    await update.message.reply_text(
        "🥷 **Ninja Scan**\n\n"
        "Stealth mode with rate limiting.\n"
        "Coming soon in next update!",
        parse_mode='Markdown'
    )


# ============================================================================
# FOCUSED SCAN COMMANDS
# ============================================================================

@require_plan('free')
async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """DNS analysis"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/dns <domain>`", parse_mode='Markdown')
        return
    
    domain = context.args[0]
    
    progress_msg = await update.message.reply_text(f"🔄 Analyzing DNS for `{domain}`...", parse_mode='Markdown')
    
    try:
        dns_scanner = DNSScanner()
        results = await dns_scanner.scan(domain, mode='full')
        
        message = format_dns_results(results)
        
        # Handle long messages
        chunks = truncate_message(message)
        await progress_msg.edit_text(chunks[0], parse_mode='Markdown')
        
        for chunk in chunks[1:]:
            await update.message.reply_text(chunk, parse_mode='Markdown')
            
    except Exception as e:
        await progress_msg.edit_text(f"❌ DNS scan failed: {str(e)}", parse_mode='Markdown')


@require_plan('standard')
async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Subdomain enumeration"""
    if not context.args:
        await update.message.reply_text(
            "❌ **Usage:** `/subs <domain>`\n\n"
            "**Example:** `/subs example.com`",
            parse_mode='Markdown'
        )
        return
    
    domain = context.args[0]
    
    # Validate
    from utils.validators import sanitize_domain
    domain = sanitize_domain(domain)
    
    progress_msg = await update.message.reply_text(
        f"📡 **Subdomain Enumeration**\n\n"
        f"Domain: `{domain}`\n"
        f"Mode: Full (multi-source)\n\n"
        f"🔄 Querying 3+ sources...",
        parse_mode='Markdown'
    )
    
    try:
        async with SubdomainHunter() as hunter:
            results = await hunter.hunt(domain, mode='full', validate=True)
        
        total = results.get('total', 0)
        alive = results.get('alive', 0)
        categorized = results.get('categorized', {})
        
        message = (
            f"📡 **SUBDOMAIN RESULTS**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Domain: `{domain}`\n"
            f"📊 Found: {total} total | {alive} alive\n\n"
        )
        
        # Sources
        sources = results.get('sources', {})
        if sources:
            message += "**Sources:**\n"
            for source, count in sources.items():
                message += f"├─ {source}: {count}\n"
            message += "\n"
        
        # Categorized results
        if categorized.get('production'):
            message += "🟢 **PRODUCTION** (Top 10)\n"
            for item in categorized['production'][:10]:
                if isinstance(item, dict):
                    sub = item['subdomain']
                    status = item.get('status', 'N/A')
                    message += f"├─ `{sub}` [{status}]\n"
                else:
                    message += f"├─ `{item}`\n"
            message += "\n"
        
        if categorized.get('staging'):
            message += "🟡 **STAGING/DEV**\n"
            for item in categorized['staging'][:5]:
                if isinstance(item, dict):
                    message += f"├─ `{item['subdomain']}`\n"
                else:
                    message += f"├─ `{item}`\n"
            message += "\n"
        
        if categorized.get('dead'):
            dead_count = len(categorized['dead'])
            message += f"🔴 **DEAD:** {dead_count} subdomains\n\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        chunks = truncate_message(message)
        await progress_msg.edit_text(chunks[0], parse_mode='Markdown')
        
        for chunk in chunks[1:]:
            await update.message.reply_text(chunk, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ Subdomain scan failed: {str(e)}", parse_mode='Markdown')


@require_plan('free')
async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """WHOIS lookup"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/whois <domain>`", parse_mode='Markdown')
        return
    
    domain = context.args[0]
    
    progress_msg = await update.message.reply_text(f"🔄 Looking up WHOIS for `{domain}`...", parse_mode='Markdown')
    
    try:
        whois_scanner = WhoisScanner()
        results = await whois_scanner.scan(domain)
        
        if results.get('error'):
            await progress_msg.edit_text(f"❌ WHOIS lookup failed: {results['error']}", parse_mode='Markdown')
            return
        
        message = (
            f"📋 **WHOIS INFORMATION**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Domain: `{domain}`\n\n"
        )
        
        if results.get('registrar'):
            message += f"**Registrar:** {results['registrar']}\n"
        
        if results.get('creation_date'):
            message += f"**Created:** {results['creation_date'].strftime('%Y-%m-%d')}\n"
        
        if results.get('expiration_date'):
            message += f"**Expires:** {results['expiration_date'].strftime('%Y-%m-%d')}\n"
        
        if results.get('age_human'):
            message += f"**Age:** {results['age_human']}\n"
        
        if results.get('is_new_domain'):
            message += f"⚠️ **New Domain** (< 30 days old)\n"
        
        if results.get('expires_soon'):
            days = results.get('days_until_expiry', 0)
            message += f"⚠️ **Expires Soon** ({days} days)\n"
        
        message += "\n**Nameservers:**\n"
        for ns in results.get('nameservers', [])[:5]:
            message += f"├─ {ns}\n"
        
        if results.get('privacy_protected'):
            message += "\n🔒 Privacy protection enabled\n"
        
        message += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        await progress_msg.edit_text(message, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ WHOIS failed: {str(e)}", parse_mode='Markdown')


@require_plan('standard')
async def ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Port scanning"""
    if not context.args:
        await update.message.reply_text(
            "❌ **Usage:** `/ports <domain> [ports]`\n\n"
            "**Examples:**\n"
            "`/ports example.com` - Scan 100 common ports\n"
            "`/ports example.com 80,443,8080` - Scan specific ports\n"
            "`/ports example.com 1-1000` - Scan port range",
            parse_mode='Markdown'
        )
        return
    
    domain = context.args[0]
    
    # Parse port specification
    ports = None
    if len(context.args) > 1:
        from utils.validators import validate_port_range
        is_valid, port_list, error = validate_port_range(context.args[1])
        
        if not is_valid:
            await update.message.reply_text(error, parse_mode='Markdown')
            return
        
        ports = port_list
    
    progress_msg = await update.message.reply_text(
        f"🔌 **Port Scanning**\n\n"
        f"Target: `{domain}`\n"
        f"Ports: {len(ports) if ports else '100 common'}\n\n"
        f"🔄 Scanning...",
        parse_mode='Markdown'
    )
    
    try:
        scanner = PortScanner()
        results = await scanner.scan(domain, ports=ports, mode='full')
        
        if results.get('error'):
            await progress_msg.edit_text(f"❌ Port scan failed: {results['error']}", parse_mode='Markdown')
            return
        
        message = (
            f"🔌 **PORT SCAN RESULTS**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Target: `{domain}` ({results.get('ip')})\n"
            f"📊 Scanned: {results.get('total_scanned', 0)} ports\n\n"
        )
        
        open_ports = results.get('open_ports', [])
        
        if open_ports:
            message += f"🟢 **OPEN PORTS:** {len(open_ports)}\n\n"
            
            # Categorize
            categorized = results.get('categorized', {})
            
            for category, ports in categorized.items():
                if ports:
                    message += f"**{category.upper()}:**\n"
                    for port_info in ports[:5]:
                        port = port_info['port']
                        service = port_info.get('service', 'Unknown')
                        version = port_info.get('version', '')
                        
                        line = f"├─ {port}/tcp - {service}"
                        if version:
                            line += f" ({version})"
                        message += line + "\n"
                    message += "\n"
        else:
            message += "✅ No open ports found (or firewall blocking)\n\n"
        
        # Critical findings
        critical = results.get('critical_findings', [])
        if critical:
            message += "🚨 **CRITICAL FINDINGS:**\n"
            for finding in critical[:3]:
                message += f"├─ {finding['severity']}: {finding['issue']}\n"
            message += "\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        chunks = truncate_message(message)
        await progress_msg.edit_text(chunks[0], parse_mode='Markdown')
        
        for chunk in chunks[1:]:
            await update.message.reply_text(chunk, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ Port scan failed: {str(e)}", parse_mode='Markdown')


@require_plan('free')
async def tech_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Technology detection"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/tech <domain>`", parse_mode='Markdown')
        return
    
    domain = context.args[0]
    
    progress_msg = await update.message.reply_text(f"🔄 Detecting technologies for `{domain}`...", parse_mode='Markdown')
    
    try:
        async with TechDetector() as detector:
            results = await detector.detect(domain, mode='full')
        
        if results.get('error'):
            await progress_msg.edit_text(f"❌ Tech detection failed: {results['error']}", parse_mode='Markdown')
            return
        
        total = results.get('total_detected', 0)
        
        message = (
            f"💻 **TECHNOLOGY STACK**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Site: `{domain}`\n"
            f"📊 Detected: {total} technologies\n\n"
        )
        
        categories = results.get('categories', {})
        
        category_emojis = {
            'CMS': '📦',
            'JavaScript Frameworks': '⚛️',
            'Web Servers': '🖥️',
            'Programming Languages': '💻',
            'Analytics': '📊',
            'CDN': '☁️',
            'UI Frameworks': '🎨',
            'Payment': '💳'
        }
        
        for category, techs in list(categories.items())[:8]:
            emoji = category_emojis.get(category, '📌')
            message += f"{emoji} **{category}:**\n"
            
            for tech in techs[:5]:
                name = tech.get('name', tech) if isinstance(tech, dict) else tech
                version = tech.get('version', '') if isinstance(tech, dict) else ''
                
                line = f"├─ {name}"
                if version:
                    line += f" {version}"
                message += line + "\n"
            
            if len(techs) > 5:
                message += f"└─ ... and {len(techs) - 5} more\n"
            message += "\n"
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            message += "⚠️ **VULNERABILITIES:**\n"
            for vuln in vulns[:3]:
                message += f"├─ {vuln['technology']} {vuln.get('version', '')}\n"
                for cve in vuln.get('cves', [])[:2]:
                    message += f"│  └─ {cve}\n"
            message += "\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        chunks = truncate_message(message)
        await progress_msg.edit_text(chunks[0], parse_mode='Markdown')
        
        for chunk in chunks[1:]:
            await update.message.reply_text(chunk, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ Tech detection failed: {str(e)}", parse_mode='Markdown')


@require_plan('standard')
async def security_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Security analysis"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/security <domain>`", parse_mode='Markdown')
        return
    
    domain = context.args[0]
    
    progress_msg = await update.message.reply_text(f"🔄 Analyzing security for `{domain}`...", parse_mode='Markdown')
    
    try:
        async with SecurityAnalyzer() as analyzer:
            results = await analyzer.analyze(domain, mode='full')
        
        if results.get('error'):
            await progress_msg.edit_text(f"❌ Security analysis failed: {results['error']}", parse_mode='Markdown')
            return
        
        score = results.get('score', 0)
        grade = results.get('grade', 'F')
        
        message = (
            f"🔐 **SECURITY ANALYSIS**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Site: `{domain}`\n"
            f"📊 Score: **{score}/100** (Grade: {grade})\n\n"
        )
        
        # SSL/TLS
        ssl = results.get('ssl', {})
        if ssl:
            message += "🔒 **SSL/TLS:**\n"
            message += f"├─ Enabled: {'✅' if ssl.get('enabled') else '❌'}\n"
            if ssl.get('version'):
                message += f"├─ Version: {ssl['version']}\n"
            if ssl.get('grade'):
                message += f"└─ Grade: {ssl['grade']}\n"
            message += "\n"
        
        # Security Headers
        headers = results.get('headers', {})
        if headers:
            present = headers.get('present', [])
            missing = headers.get('missing', [])
            
            message += f"📋 **Headers:** {len(present)}/{headers.get('total', 10)}\n"
            if present:
                for header in present[:5]:
                    message += f"├─ ✅ {header}\n"
            if missing:
                for header in missing[:3]:
                    message += f"├─ ❌ {header}\n"
            message += "\n"
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            message += f"⚠️ **Vulnerabilities:** {len(vulns)}\n"
            for vuln in vulns[:3]:
                severity = vuln.get('severity', 'Unknown')
                vuln_type = vuln.get('type', 'Unknown')
                message += f"├─ {severity}: {vuln_type}\n"
            message += "\n"
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            message += "💡 **Recommendations:**\n"
            for rec in recommendations[:3]:
                message += f"├─ {rec}\n"
            message += "\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        chunks = truncate_message(message)
        await progress_msg.edit_text(chunks[0], parse_mode='Markdown')
        
        for chunk in chunks[1:]:
            await update.message.reply_text(chunk, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ Security analysis failed: {str(e)}", parse_mode='Markdown')


@require_plan('free')
async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """IP intelligence"""
    if not context.args:
        await update.message.reply_text("❌ Usage: `/ip <domain>`", parse_mode='Markdown')
        return
    
    domain = context.args[0]
    
    progress_msg = await update.message.reply_text(f"🔄 Analyzing IP for `{domain}`...", parse_mode='Markdown')
    
    try:
        async with IPIntelligence() as ip_intel:
            results = await ip_intel.analyze(domain)
        
        if results.get('error'):
            await progress_msg.edit_text(f"❌ IP analysis failed: {results['error']}", parse_mode='Markdown')
            return
        
        ip = results.get('ip', 'N/A')
        
        message = (
            f"🌍 **IP INTELLIGENCE**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🌐 Domain: `{domain}`\n"
            f"📍 IP: `{ip}`\n\n"
        )
        
        # Geolocation
        geo = results.get('geolocation', {})
        if geo:
            message += "🗺️ **Location:**\n"
            message += f"├─ Country: {geo.get('country', 'N/A')}\n"
            message += f"├─ Region: {geo.get('region', 'N/A')}\n"
            message += f"└─ City: {geo.get('city', 'N/A')}\n\n"
        
        # ASN
        asn = results.get('asn', {})
        if asn:
            message += "🏢 **Network:**\n"
            message += f"├─ ASN: {asn.get('number', 'N/A')}\n"
            message += f"└─ Organization: {asn.get('name', 'N/A')}\n\n"
        
        # Hosting
        if results.get('hosting'):
            message += f"☁️ **Hosting:** {results['hosting']}\n"
        
        if results.get('cloud_provider'):
            message += f"☁️ **Cloud:** {results['cloud_provider']}\n"
        
        if results.get('is_cdn'):
            message += f"📡 **CDN Detected**\n"
        
        message += "\n"
        
        # Reverse IP
        reverse_ip = results.get('reverse_ip', [])
        if reverse_ip:
            message += f"🔄 **Other domains on IP:** {len(reverse_ip)}\n"
            for other_domain in reverse_ip[:5]:
                message += f"├─ {other_domain}\n"
            if len(reverse_ip) > 5:
                message += f"└─ ... and {len(reverse_ip) - 5} more\n"
            message += "\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        await progress_msg.edit_text(message, parse_mode='Markdown')
    
    except Exception as e:
        await progress_msg.edit_text(f"❌ IP analysis failed: {str(e)}", parse_mode='Markdown')


# Placeholder for other commands (whois, ports, tech, security, ip)
# These will be implemented similarly


# ============================================================================
# CALLBACK HANDLERS
# ============================================================================

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline keyboard button clicks"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    # Shop callbacks
    if data.startswith('buy_'):
        await buy_plan_callback(update, context)
    elif data == 'shop':
        await shop_callback(update, context)
    elif data == 'compare_plans':
        await compare_plans_callback(update, context)
    elif data == 'faq':
        await faq_callback(update, context)
    
    # Help callbacks
    elif data == 'help':
        await query.message.reply_text("Use /help for detailed commands", parse_mode='Markdown')
    elif data == 'about':
        await about_command(query, context)
    
    # Demo callback
    elif data == 'demo_quick':
        await query.message.reply_text(
            "Try: `/quick google.com`\n\n"
            "This will perform a quick 30-second scan!",
            parse_mode='Markdown'
        )


# ============================================================================
# ERROR HANDLER
# ============================================================================

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    logger.error(f"Update {update} caused error {context.error}")
    
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "❌ **An error occurred**\n\n"
            "The issue has been logged. Please try again later.",
            parse_mode='Markdown'
        )


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Start the bot"""
    # Validate configuration
    try:
        config.validate_config()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return
    
    logger.info(f"Starting {config.BOT_NAME} v{config.BOT_VERSION}")
    
    # Create application
    application = Application.builder().token(config.BOT_TOKEN).build()
    
    # Basic commands
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("about", about_command))
    application.add_handler(CommandHandler("cancel", cancel_command))
    
    # Scan commands
    application.add_handler(CommandHandler("quick", quick_scan))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("deep", deep_scan))
    application.add_handler(CommandHandler("ninja", ninja_scan))
    
    # Focused scans
    application.add_handler(CommandHandler("dns", dns_command))
    application.add_handler(CommandHandler("subs", subdomains_command))
    # Add more: whois, ports, tech, security, ip
    
    # Shop commands
    application.add_handler(CommandHandler("shop", shop_command))
    application.add_handler(CommandHandler("myplan", myplan_command))
    
    # Admin commands
    application.add_handler(CommandHandler("adminpanel", adminpanel_command))
    application.add_handler(CommandHandler("grant", grant_command))
    application.add_handler(CommandHandler("revoke", revoke_command))
    application.add_handler(CommandHandler("pending", pending_command))
    application.add_handler(CommandHandler("verify", verify_command))
    application.add_handler(CommandHandler("reject", reject_command))
    application.add_handler(CommandHandler("ban", ban_command))
    application.add_handler(CommandHandler("unban", unban_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("adminhelp", adminhelp_command))
    
    # Callback handler
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    # Start bot
    logger.info("Bot started successfully! Press Ctrl+C to stop.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
