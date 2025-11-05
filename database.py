"""
Database operations for user management and transactions
Supports both Supabase (PostgreSQL) and SQLite
"""

import os
import sys
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

logger = logging.getLogger(__name__)


class Database:
    """Database manager supporting both SQLite and PostgreSQL"""
    
    def __init__(self):
        self.use_sqlite = config.USE_SQLITE
        
        if self.use_sqlite:
            self._init_sqlite()
        else:
            self._init_postgres()
    
    def _init_sqlite(self):
        """Initialize SQLite database"""
        # Create data directory if not exists
        os.makedirs('data', exist_ok=True)
        
        self.conn = sqlite3.connect(config.SQLITE_DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        # Create tables
        self._create_sqlite_tables()
        
        logger.info("SQLite database initialized")
    
    def _init_postgres(self):
        """Initialize PostgreSQL (Supabase) connection"""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            self.conn = psycopg2.connect(
                config.DATABASE_URL,
                cursor_factory=RealDictCursor
            )
            self.conn.autocommit = True
            
            # Create tables
            self._create_postgres_tables()
            
            logger.info("PostgreSQL (Supabase) database initialized")
        except ImportError:
            logger.error("psycopg2 not installed! Install with: pip install psycopg2-binary")
            raise
    
    def _get_placeholder(self):
        """Get SQL placeholder based on database type"""
        return "?" if self.use_sqlite else "%s"
    
    def _execute(self, cursor, query: str, params: tuple = None):
        """Execute query with correct placeholder syntax"""
        if params:
            # Replace ? with %s for PostgreSQL
            if not self.use_sqlite:
                query = query.replace("?", "%s")
            cursor.execute(query, params)
        else:
            cursor.execute(query)
    
    def _create_sqlite_tables(self):
        """Create SQLite tables"""
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                plan TEXT DEFAULT 'free',
                expires_at TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                scans_today INTEGER DEFAULT 0,
                scans_limit INTEGER DEFAULT 5,
                last_scan_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_banned BOOLEAN DEFAULT 0,
                ban_reason TEXT
            )
        """)
        
        # Transactions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                plan TEXT,
                amount REAL,
                currency TEXT DEFAULT 'INR',
                reference TEXT UNIQUE,
                status TEXT DEFAULT 'pending',
                payment_method TEXT DEFAULT 'upi',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP,
                verified_by INTEGER,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        # Admin logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT,
                target_user_id INTEGER,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scan history table (optional)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                domain TEXT,
                scan_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        self.conn.commit()
    
    def _create_postgres_tables(self):
        """Create PostgreSQL tables"""
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username VARCHAR(255),
                first_name VARCHAR(255),
                plan VARCHAR(50) DEFAULT 'free',
                expires_at TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                scans_today INTEGER DEFAULT 0,
                scans_limit INTEGER DEFAULT 5,
                last_scan_date DATE,
                created_at TIMESTAMP DEFAULT NOW(),
                is_banned BOOLEAN DEFAULT FALSE,
                ban_reason TEXT
            )
        """)
        
        # Transactions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(user_id),
                plan VARCHAR(50),
                amount DECIMAL(10, 2),
                currency VARCHAR(3) DEFAULT 'INR',
                reference VARCHAR(255) UNIQUE,
                status VARCHAR(50) DEFAULT 'pending',
                payment_method VARCHAR(50) DEFAULT 'upi',
                created_at TIMESTAMP DEFAULT NOW(),
                verified_at TIMESTAMP,
                verified_by BIGINT,
                notes TEXT
            )
        """)
        
        # Admin logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY,
                admin_id BIGINT,
                action VARCHAR(100),
                target_user_id BIGINT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """)
        
        # Scan history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(user_id),
                domain VARCHAR(255),
                scan_type VARCHAR(50),
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_plan ON users(plan)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_expires ON users(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference)")
    
    # ========================================================================
    # USER OPERATIONS
    # ========================================================================
    
    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        cursor = self.conn.cursor()
        self._execute(cursor, "SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        
        if row:
            return dict(row) if self.use_sqlite else row
        return None
    
    def create_user(self, user_id: int, username: str, first_name: str) -> Dict[str, Any]:
        """Create new user with free plan"""
        cursor = self.conn.cursor()
        
        self._execute(cursor, """
            INSERT INTO users (user_id, username, first_name, plan, scans_limit)
            VALUES (?, ?, ?, 'free', 5)
        """, (user_id, username, first_name))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return self.get_user(user_id)
    
    def get_or_create_user(self, user_id: int, username: str, first_name: str) -> Dict[str, Any]:
        """Get existing user or create new one"""
        user = self.get_user(user_id)
        if not user:
            user = self.create_user(user_id, username, first_name)
        return user
    
    def update_user_plan(self, user_id: int, plan: str, duration_hours: Optional[int] = None) -> bool:
        """Update user's plan and set expiry"""
        cursor = self.conn.cursor()
        
        # Calculate expiry
        if duration_hours is None:  # Lifetime
            expires_at = None
        else:
            expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        # Get scan limit for plan
        plan_info = config.PRICING_PLANS.get(plan, {})
        scans_limit = plan_info.get('scans_limit') or 999999  # Unlimited if None
        
        self._execute(cursor, """
            UPDATE users 
            SET plan = ?, expires_at = ?, scans_limit = ?
            WHERE user_id = ?
        """, (plan, expires_at, scans_limit, user_id))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return cursor.rowcount > 0
    
    def increment_scan_count(self, user_id: int) -> bool:
        """Increment user's scan count"""
        cursor = self.conn.cursor()
        today = datetime.now().date()
        
        # Get user's last scan date
        user = self.get_user(user_id)
        last_scan_date = user.get('last_scan_date')
        
        # Reset daily count if new day
        if last_scan_date and str(last_scan_date) != str(today):
            self._execute(cursor, """
                UPDATE users 
                SET scans_today = 1, total_scans = total_scans + 1, last_scan_date = ?
                WHERE user_id = ?
            """, (today, user_id))
        else:
            self._execute(cursor, """
                UPDATE users 
                SET scans_today = scans_today + 1, total_scans = total_scans + 1, last_scan_date = ?
                WHERE user_id = ?
            """, (today, user_id))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return True
    
    def ban_user(self, user_id: int, reason: str) -> bool:
        """Ban a user"""
        cursor = self.conn.cursor()
        self._execute(cursor, """
            UPDATE users 
            SET is_banned = 1, ban_reason = ?
            WHERE user_id = ?
        """, (reason, user_id))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return cursor.rowcount > 0
    
    def unban_user(self, user_id: int) -> bool:
        """Unban a user"""
        cursor = self.conn.cursor()
        self._execute(cursor, """
            UPDATE users 
            SET is_banned = 0, ban_reason = NULL
            WHERE user_id = ?
        """, (user_id,))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return cursor.rowcount > 0
    
    def get_expired_users(self) -> List[Dict[str, Any]]:
        """Get users with expired subscriptions"""
        cursor = self.conn.cursor()
        self._execute(cursor, """
            SELECT * FROM users 
            WHERE expires_at IS NOT NULL 
            AND expires_at < ? 
            AND plan != 'free'
        """, (datetime.now(),))
        
        return [dict(row) if self.use_sqlite else row for row in cursor.fetchall()]
    
    # ========================================================================
    # TRANSACTION OPERATIONS
    # ========================================================================
    
    def create_transaction(self, user_id: int, plan: str, amount: float, reference: str) -> Dict[str, Any]:
        """Create new transaction"""
        cursor = self.conn.cursor()
        
        self._execute(cursor, """
            INSERT INTO transactions (user_id, plan, amount, reference)
            VALUES (?, ?, ?, ?)
        """, (user_id, plan, amount, reference))
        
        if self.use_sqlite:
            self.conn.commit()
            transaction_id = cursor.lastrowid
        else:
            transaction_id = cursor.fetchone()['id']
        
        return self.get_transaction(transaction_id)
    
    def get_transaction(self, transaction_id: int) -> Optional[Dict[str, Any]]:
        """Get transaction by ID"""
        cursor = self.conn.cursor()
        self._execute(cursor, "SELECT * FROM transactions WHERE id = ?", (transaction_id,))
        row = cursor.fetchone()
        
        if row:
            return dict(row) if self.use_sqlite else row
        return None
    
    def get_transaction_by_reference(self, reference: str) -> Optional[Dict[str, Any]]:
        """Get transaction by reference code"""
        cursor = self.conn.cursor()
        self._execute(cursor, "SELECT * FROM transactions WHERE reference = ?", (reference,))
        row = cursor.fetchone()
        
        if row:
            return dict(row) if self.use_sqlite else row
        return None
    
    def get_pending_transactions(self) -> List[Dict[str, Any]]:
        """Get all pending transactions"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT t.*, u.username, u.first_name 
            FROM transactions t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.status = 'pending'
            ORDER BY t.created_at DESC
        """)
        
        return [dict(row) if self.use_sqlite else row for row in cursor.fetchall()]
    
    def verify_transaction(self, reference: str, admin_id: int, notes: str = None) -> bool:
        """Verify and approve transaction"""
        cursor = self.conn.cursor()
        
        # Get transaction
        transaction = self.get_transaction_by_reference(reference)
        if not transaction:
            return False
        
        # Update transaction status
        self._execute(cursor, """
            UPDATE transactions 
            SET status = 'verified', verified_at = ?, verified_by = ?, notes = ?
            WHERE reference = ?
        """, (datetime.now(), admin_id, notes, reference))
        
        # Update user plan
        plan_info = config.PRICING_PLANS.get(transaction['plan'])
        if plan_info:
            self.update_user_plan(
                transaction['user_id'],
                transaction['plan'],
                plan_info.get('duration_hours')
            )
        
        if self.use_sqlite:
            self.conn.commit()
        
        return True
    
    def reject_transaction(self, reference: str, admin_id: int, reason: str) -> bool:
        """Reject transaction"""
        cursor = self.conn.cursor()
        
        self._execute(cursor, """
            UPDATE transactions 
            SET status = 'rejected', verified_at = ?, verified_by = ?, notes = ?
            WHERE reference = ?
        """, (datetime.now(), admin_id, reason, reference))
        
        if self.use_sqlite:
            self.conn.commit()
        
        return cursor.rowcount > 0
    
    # ========================================================================
    # ADMIN LOG OPERATIONS
    # ========================================================================
    
    def log_admin_action(self, admin_id: int, action: str, target_user_id: int = None, details: str = None):
        """Log admin action"""
        cursor = self.conn.cursor()
        
        self._execute(cursor, """
            INSERT INTO admin_logs (admin_id, action, target_user_id, details)
            VALUES (?, ?, ?, ?)
        """, (admin_id, action, target_user_id, details))
        
        if self.use_sqlite:
            self.conn.commit()
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall bot statistics"""
        cursor = self.conn.cursor()
        
        # Total users
        cursor.execute("SELECT COUNT(*) as count FROM users")
        total_users = cursor.fetchone()['count']
        
        # Active subscriptions
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE plan != 'free' 
            AND (expires_at IS NULL OR expires_at > ?)
        """, (datetime.now(),))
        active_subscriptions = cursor.fetchone()['count']
        
        # Pending verifications
        cursor.execute("SELECT COUNT(*) as count FROM transactions WHERE status = 'pending'")
        pending_verifications = cursor.fetchone()['count']
        
        # Revenue (all time)
        cursor.execute("SELECT SUM(amount) as total FROM transactions WHERE status = 'verified'")
        result = cursor.fetchone()
        revenue_all_time = result['total'] if result['total'] else 0
        
        # Revenue (this month)
        cursor.execute("""
            SELECT SUM(amount) as total FROM transactions 
            WHERE status = 'verified' 
            AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        """)
        result = cursor.fetchone()
        revenue_month = result['total'] if result['total'] else 0
        
        # Plan breakdown
        cursor.execute("""
            SELECT plan, COUNT(*) as count 
            FROM users 
            GROUP BY plan
        """)
        plan_breakdown = {row['plan']: row['count'] for row in cursor.fetchall()}
        
        return {
            'total_users': total_users,
            'active_subscriptions': active_subscriptions,
            'pending_verifications': pending_verifications,
            'revenue_all_time': revenue_all_time,
            'revenue_month': revenue_month,
            'plan_breakdown': plan_breakdown
        }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# Global database instance
db = Database()
