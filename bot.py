import os
import logging
import socket
import requests
import dns.resolver
import whois
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot token from environment variable
BOT_TOKEN = os.environ.get('BOT_TOKEN')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /start is issued."""
    welcome_text = """
🔍 *Domain Reconnaissance Bot*

Available commands:
/whois <domain> - Get WHOIS information
/dns <domain> - Get DNS records
/subdomains <domain> - Find subdomains (using crt.sh)
/ports <domain> - Scan common ports
/tech <domain> - Detect technologies used
/all <domain> - Run all checks

Example: `/whois google.com`

⚠️ *Important*: Only use on domains you own or have permission to test!
"""
    await update.message.reply_text(welcome_text, parse_mode='Markdown')

async def whois_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Perform WHOIS lookup"""
    if not context.args:
        await update.message.reply_text("Usage: /whois <domain>")
        return
    
    domain = context.args[0].replace('http://', '').replace('https://', '').split('/')[0]
    await update.message.reply_text(f"🔍 Looking up WHOIS for {domain}...")
    
    try:
        w = whois.whois(domain)
        result = f"📋 *WHOIS Information for {domain}*\n\n"
        result += f"*Registrar:* {w.registrar}\n"
        result += f"*Creation Date:* {w.creation_date}\n"
        result += f"*Expiration Date:* {w.expiration_date}\n"
        result += f"*Name Servers:* {', '.join(w.name_servers) if w.name_servers else 'N/A'}\n"
        await update.message.reply_text(result, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def dns_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Perform DNS lookup"""
    if not context.args:
        await update.message.reply_text("Usage: /dns <domain>")
        return
    
    domain = context.args[0].replace('http://', '').replace('https://', '').split('/')[0]
    await update.message.reply_text(f"🔍 Looking up DNS records for {domain}...")
    
    result = f"📋 *DNS Records for {domain}*\n\n"
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result += f"*{record_type} Records:*\n"
            for rdata in answers:
                result += f"  • {rdata}\n"
            result += "\n"
        except:
            pass
    
    await update.message.reply_text(result, parse_mode='Markdown')

async def find_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Find subdomains using crt.sh"""
    if not context.args:
        await update.message.reply_text("Usage: /subdomains <domain>")
        return
    
    domain = context.args[0].replace('http://', '').replace('https://', '').split('/')[0]
    await update.message.reply_text(f"🔍 Searching for subdomains of {domain}...")
    
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name = entry.get('name_value', '')
                if '\n' in name:
                    subdomains.update(name.split('\n'))
                else:
                    subdomains.add(name)
            
            subdomains = sorted([s for s in subdomains if '*' not in s])[:50]  # Limit to 50
            
            result = f"📋 *Subdomains found for {domain}* (max 50)\n\n"
            for subdomain in subdomains:
                result += f"• `{subdomain}`\n"
            
            await update.message.reply_text(result, parse_mode='Markdown')
        else:
            await update.message.reply_text("❌ Could not fetch subdomains")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def scan_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan common ports"""
    if not context.args:
        await update.message.reply_text("Usage: /ports <domain>")
        return
    
    domain = context.args[0].replace('http://', '').replace('https://', '').split('/')[0]
    await update.message.reply_text(f"🔍 Scanning common ports on {domain}...")
    
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    open_ports = []
    
    try:
        ip = socket.gethostbyname(domain)
        result = f"📋 *Port Scan for {domain}* ({ip})\n\n"
        
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_code = sock.connect_ex((ip, port))
            if result_code == 0:
                open_ports.append(f"✅ Port {port} ({service}) - OPEN")
            sock.close()
        
        if open_ports:
            result += "\n".join(open_ports)
        else:
            result += "No common ports open or firewall is blocking"
        
        await update.message.reply_text(result, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def detect_tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Detect technologies used"""
    if not context.args:
        await update.message.reply_text("Usage: /tech <domain>")
        return
    
    domain = context.args[0]
    if not domain.startswith('http'):
        domain = 'https://' + domain
    
    await update.message.reply_text(f"🔍 Detecting technologies for {domain}...")
    
    try:
        response = requests.get(domain, timeout=10, allow_redirects=True)
        headers = response.headers
        
        result = f"📋 *Technology Detection for {domain}*\n\n"
        
        # Server header
        if 'Server' in headers:
            result += f"*Server:* {headers['Server']}\n"
        
        # Powered by
        if 'X-Powered-By' in headers:
            result += f"*Powered By:* {headers['X-Powered-By']}\n"
        
        # Check for common frameworks in HTML
        html = response.text.lower()
        
        frameworks = {
            'wordpress': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'react': 'React',
            'vue.js': 'Vue.js',
            'angular': 'Angular',
            'bootstrap': 'Bootstrap',
            'jquery': 'jQuery'
        }
        
        detected = []
        for key, name in frameworks.items():
            if key in html:
                detected.append(name)
        
        if detected:
            result += f"*Detected Frameworks:* {', '.join(detected)}\n"
        
        result += f"\n*Status Code:* {response.status_code}"
        
        await update.message.reply_text(result, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def run_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Run all reconnaissance checks"""
    if not context.args:
        await update.message.reply_text("Usage: /all <domain>")
        return
    
    await update.message.reply_text("🔍 Running full reconnaissance... This may take a minute.")
    
    # Run all checks
    await whois_lookup(update, context)
    await dns_lookup(update, context)
    await find_subdomains(update, context)
    await scan_ports(update, context)
    await detect_tech(update, context)

def main():
    """Start the bot."""
    if not BOT_TOKEN:
        print("ERROR: BOT_TOKEN environment variable not set!")
        return
    
    # Create the Application
    application = Application.builder().token(BOT_TOKEN).build()

    # Register handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("whois", whois_lookup))
    application.add_handler(CommandHandler("dns", dns_lookup))
    application.add_handler(CommandHandler("subdomains", find_subdomains))
    application.add_handler(CommandHandler("ports", scan_ports))
    application.add_handler(CommandHandler("tech", detect_tech))
    application.add_handler(CommandHandler("all", run_all))

    # Start the Bot
    print("Bot is starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
