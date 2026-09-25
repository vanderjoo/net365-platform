# database.py - Complete working version with ALL functions and webhook fixes
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
import time
import threading
import logging
import uuid  # ← ADD THIS LINE

# ============ SETUP LOGGING ============
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("net365.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Use absolute path for database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.getenv("DATABASE_URL", os.path.join(BASE_DIR, "reloadly.db"))

# Database lock timeout (in seconds)
DB_TIMEOUT = 30


def get_db():
    """Get database connection with timeout"""
    try:
        conn = sqlite3.connect(DATABASE, timeout=DB_TIMEOUT)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn
    except Exception as e:
        print(f"ERROR: {e}")
        raise


# Thread-local storage for database connections
# _db_local = threading.local()


def get_db_connection():
    """
    Return a fresh SQLite connection.

    A new connection is created for each database operation.
    This prevents reuse of connections that may have already
    been closed by another function or request.
    """
    conn = sqlite3.connect(
        DATABASE,
        timeout=DB_TIMEOUT,
        check_same_thread=False,
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")

    return conn


def close_db_connection():
    """
    Retained for backward compatibility.

    Connections are now closed by the individual database
    functions that create them.
    """
    return None


from functools import wraps


# ============ CANONICAL TRANSACTION STATUS ============
# The `transactions` table has accumulated two overlapping "this succeeded" values
# over time — 'fulfilled' (set by mark_fulfilled(), originally written for
# Reloadly-fulfilled airtime/data/giftcard transactions) and 'completed' (set inline
# by utility-payment and wallet-funding/transfer code paths). Renaming historical rows
# is riskier than it's worth (breaks anything joining/exporting on the old value), so
# instead every place in the codebase that needs to ask "did this succeed?" should
# import and use TxStatus.SUCCESS / is_successful_status() below rather than writing
# its own `status IN (...)` or `status ==` check. New code should write
# TxStatus.FULFILLED for new terminal-success rows; TxStatus.COMPLETED is kept only
# for backward compatibility with existing data and older code paths.
class TxStatus:
    PENDING = "pending"                    # created, awaiting payment
    PAID = "paid"                          # payment confirmed, not yet fulfilled
    PROCESSING = "processing"              # fulfillment in progress
    FULFILLED = "fulfilled"                # terminal success (preferred going forward)
    COMPLETED = "completed"                # terminal success (legacy alias — do not use for new writes)
    FAILED = "failed"                      # payment failed
    FULFILLMENT_FAILED = "fulfillment_failed"  # payment succeeded, delivery failed
    CANCELLED = "cancelled"
    REFUNDED = "refunded"

    # Every value that means "the customer got what they paid for."
    SUCCESS = frozenset({FULFILLED, COMPLETED})
    # Every value that means the transaction is finished and will not change again.
    TERMINAL = frozenset({FULFILLED, COMPLETED, FAILED, FULFILLMENT_FAILED, CANCELLED, REFUNDED})


def is_successful_status(status: Optional[str]) -> bool:
    return (status or "").lower() in TxStatus.SUCCESS


def is_terminal_status(status: Optional[str]) -> bool:
    return (status or "").lower() in TxStatus.TERMINAL


# SQL fragment for the common "count/filter successful transactions" case, so every
# call site interpolates the same tuple instead of hand-typing status lists that can
# drift out of sync with each other (this is exactly how the earlier bug happened —
# some queries checked only 'fulfilled' and silently missed 'completed' rows).
_SUCCESS_STATUS_SQL = "('" + "', '".join(sorted(TxStatus.SUCCESS)) + "')"


def retry_on_lock(func):
    """
    Retry SQLite operations when the database is temporarily locked.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        max_retries = 5

        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)

            except sqlite3.OperationalError as error:
                error_message = str(error).lower()

                is_lock_error = (
                    "database is locked" in error_message
                    or "database table is locked" in error_message
                    or "database schema is locked" in error_message
                )

                if not is_lock_error:
                    raise

                if attempt >= max_retries - 1:
                    raise

                wait_time = 0.2 * (attempt + 1)

                logger.warning(
                    "Database locked. Retry %s/%s in %.1f seconds",
                    attempt + 1,
                    max_retries,
                    wait_time,
                )

                time.sleep(wait_time)

        return None

    return wrapper


# get_transaction_by_reference: removed — it was a dead stub that imported a
# non-existent `models` (SQLAlchemy) module and always returned None. It was never
# called anywhere; get_transaction(reference) below is the real, working equivalent.


def get_user_by_id(user_id):
    """Get user by ID. Thin wrapper around get_user() so there's exactly one
    implementation of "fetch a user row" — this used to be its own fragile
    raw-sqlite3 connection (hardcoded relative path, no retry-on-lock, no row
    factory) that bypassed the shared connection helper every other query uses."""
    return get_user(user_id)


def get_user_by_email(email):
    """Get user by email"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, phone, full_name, referred_by, referral_code FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'email': user[1],
                'phone': user[2],
                'full_name': user[3],
                'referred_by': user[4],
                'referral_code': user[5]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def get_referral_code_by_user_id(user_id):
    """Get referral code created by user"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT referral_code FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Error getting referral code: {e}")
        return None

def get_referral_code_owner(referral_code):
    """Get user who owns a referral code"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name FROM users WHERE referral_code = ?", (referral_code,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'email': user[1],
                'full_name': user[2]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting referral code owner: {e}")
        return None



@retry_on_lock
def sync_contacts(user_id: int, contacts: List[Dict]) -> Dict:
    """
    Sync contacts - updates existing ones, adds new ones.
    Uses phone number as unique identifier per user.
    """
    added = 0
    updated = 0
    skipped = 0
    
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        for contact in contacts:
            name = contact.get("name", "").strip()
            phone = contact.get("phone", "").strip()
            network = contact.get("network", "")
            
            if not phone:
                skipped += 1
                continue
            
            # Check if contact exists for this user
            existing = c.execute(
                "SELECT id FROM contacts WHERE user_id = ? AND phone = ?",
                (user_id, phone),
            ).fetchone()
            
            if existing:
                # Update existing contact
                c.execute(
                    """
                    UPDATE contacts 
                    SET name = ?, network = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (name or "Unknown", network, existing["id"]),
                )
                updated += 1
            else:
                # Insert new contact
                c.execute(
                    """
                    INSERT INTO contacts (user_id, name, phone, network)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, name or "Unknown", phone, network),
                )
                added += 1
        
        conn.commit()
        return {"success": True, "added": added, "updated": updated, "skipped": skipped}
        
    except Exception as e:
        logger.error(f"Error syncing contacts: {e}")
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        conn.close()
        
        
@retry_on_lock
def remove_duplicate_contacts(user_id: int) -> Dict:
    """
    Remove duplicate contacts for a user.
    Keeps the first (oldest) contact for each phone number.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Find duplicate phone numbers
        duplicates = c.execute("""
            SELECT phone, COUNT(*) as count, MIN(id) as keep_id
            FROM contacts 
            WHERE user_id = ?
            GROUP BY phone 
            HAVING COUNT(*) > 1
        """, (user_id,)).fetchall()
        
        if not duplicates:
            return {"success": True, "removed": 0, "message": "No duplicates found"}
        
        removed_count = 0
        for dup in duplicates:
            # Delete all but the oldest (keep_id)
            deleted = c.execute("""
                DELETE FROM contacts 
                WHERE user_id = ? AND phone = ? AND id != ?
            """, (user_id, dup["phone"], dup["keep_id"]))
            removed_count += deleted.rowcount
        
        conn.commit()
        
        return {
            "success": True, 
            "removed": removed_count,
            "message": f"Removed {removed_count} duplicate contacts"
        }
        
    except Exception as e:
        logger.error(f"Error removing duplicate contacts: {e}")
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def get_contact_count(user_id: int) -> int:
    """Get total contact count for a user."""
    conn = get_db_connection()
    c = conn.cursor()
    count = c.execute(
        "SELECT COUNT(*) FROM contacts WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return count

# ============ CONTACT FUNCTIONS - COMPLETE FIX ============
# ============ CONTACT IMPORT FUNCTIONS - WITH DEDUPLICATION ============

# ============ CONTACT IMPORT FUNCTIONS - WITH DEDUPLICATION ============

@retry_on_lock
def import_contacts_unique(
    user_id: int,
    contacts: List[Dict],
    phone_field: str = "phone",
    name_field: str = "name"
) -> Dict:
    """
    Import contacts - skips duplicates, updates existing ones.
    Returns: {success, added, updated, skipped, errors}
    """
    if not contacts:
        return {"success": True, "added": 0, "updated": 0, "skipped": 0, "errors": []}

    conn = get_db_connection()
    c = conn.cursor()

    added = 0
    updated = 0
    skipped = 0
    errors = []

    # Ensure contacts table has all required columns
    columns = {row[1] for row in c.execute("PRAGMA table_info(contacts)").fetchall()}
    required_cols = ["country", "email", "updated_at"]
    for col in required_cols:
        if col not in columns:
            try:
                if col == "updated_at":
                    c.execute(f"ALTER TABLE contacts ADD COLUMN {col} TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                else:
                    c.execute(f"ALTER TABLE contacts ADD COLUMN {col} TEXT")
                conn.commit()
                logger.info(f"Added column '{col}' to contacts table")
            except sqlite3.OperationalError as e:
                logger.warning(f"Could not add column {col}: {e}")

    try:
        # Get existing phone numbers for this user for quick lookup
        existing_phones = {}
        for row in c.execute("SELECT phone, id, name FROM contacts WHERE user_id = ?", (user_id,)).fetchall():
            existing_phones[row["phone"]] = {"id": row["id"], "name": row["name"]}

        logger.info(f"Found {len(existing_phones)} existing contacts for user {user_id}")

        for idx, contact in enumerate(contacts):
            # Get phone from the correct field
            phone = contact.get(phone_field, "").strip()
            if not phone:
                phone = contact.get("phone", "").strip()

            name = contact.get(name_field, "").strip()
            if not name:
                name = contact.get("name", "").strip()

            email = contact.get("email", "").strip()
            country = contact.get("country", "").strip()
            network = contact.get("network", "")

            if not phone:
                skipped += 1
                errors.append(f"Skipped: missing phone number for {name}")
                logger.debug(f"Contact #{idx} skipped – no phone")
                continue

            logger.debug(f"Processing contact #{idx}: phone={phone}, name={name}")

            # Check if phone already exists for this user
            if phone in existing_phones:
                # Update existing contact
                try:
                    c.execute(
                        """
                        UPDATE contacts
                        SET name = ?, network = ?, country = ?, email = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND user_id = ?
                        """,
                        (name or existing_phones[phone]["name"], network, country, email,
                         existing_phones[phone]["id"], user_id)
                    )
                    updated += 1
                    logger.debug(f"Updated contact: {phone} -> {name}")
                except Exception as e:
                    logger.warning(f"Failed to update contact {phone}: {e}")
                    errors.append(f"Update error for {phone}: {str(e)}")
                continue

            # Insert new contact
            try:
                c.execute(
                    """
                    INSERT INTO contacts (user_id, name, phone, network, country, email)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, name or "Unknown Contact", phone, network, country, email)
                )
                added += 1
                existing_phones[phone] = {"id": c.lastrowid, "name": name or "Unknown Contact"}
                logger.debug(f"Added contact: {phone} -> {name}")
            except sqlite3.IntegrityError as e:
                if "UNIQUE" in str(e):
                    skipped += 1
                    errors.append(f"Duplicate skipped: {phone}")
                else:
                    errors.append(f"Integrity error for {phone}: {str(e)}")
                logger.warning(f"Integrity error for {phone}: {e}")
            except Exception as e:
                errors.append(f"Error inserting {phone}: {str(e)}")
                logger.error(f"Error inserting {phone}: {e}")

        conn.commit()

        logger.info(f"Contact import completed: added={added}, updated={updated}, skipped={skipped}")
        return {
            "success": True,
            "added": added,
            "updated": updated,
            "skipped": skipped,
            "errors": errors[:10]
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error importing contacts: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
    finally:
        conn.close()
  
def process_bulk_recharge(user_id, records):
    """Create a bulk job and process records. Returns job info."""
    import uuid as _uuid
    job_id = str(_uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Ensure bulk_jobs table exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS bulk_jobs (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                total INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                successful INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        c.execute("""
            INSERT INTO bulk_jobs (id, user_id, total, status)
            VALUES (?, ?, ?, 'processing')
        """, (job_id, user_id, len(records)))
        conn.commit()
        
        return jsonify({
            "success": True,
            "job_id": job_id,
            "total": len(records),
            "message": f"Bulk job created with {len(records)} records"
        })
    except Exception as e:
        logger.error(f"Failed to create bulk job: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()  
        
        
@retry_on_lock
def upsert_contact_from_transaction(
    user_id: int, phone: str, name: str = None, network: str = None
) -> bool:
    """
    Ensure a contact exists for a phone used in a transaction, and bump usage.
    Safe to call repeatedly — it will not create duplicates.
    """
    if not phone:
        return False

    normalized = re.sub(r"[^\d+]", "", phone)
    if not normalized or len(normalized) < 7:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    try:
        existing = c.execute(
            """
            SELECT id FROM contacts
            WHERE user_id = ? AND (phone = ? OR phone_normalized = ?)
            LIMIT 1
            """,
            (user_id, phone, normalized),
        ).fetchone()

        if existing:
            c.execute(
                """
                UPDATE contacts
                SET last_used_at = CURRENT_TIMESTAMP,
                    use_count = COALESCE(use_count, 0) + 1,
                    network = COALESCE(NULLIF(?, ''), network),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (network or "", existing["id"]),
            )
        else:
            c.execute(
                """
                INSERT INTO contacts
                    (user_id, name, phone, phone_normalized, network,
                     use_count, last_used_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    name or "Unknown",
                    phone,
                    normalized,
                    network,
                ),
            )

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"upsert_contact_from_transaction failed: {e}")
        return False
    finally:
        conn.close()

        
# ============================================================
# CONTACT DATABASE MIGRATION
# ============================================================

@retry_on_lock
def ensure_contact_unique_indexes():
    """
    Ensure contacts cannot have duplicate phone numbers or emails
    for the same user.

    Existing duplicate records are cleaned first.
    """
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Remove duplicate phone numbers, keeping the oldest record.
        c.execute("""
            DELETE FROM contacts
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM contacts
                WHERE phone IS NOT NULL
                  AND TRIM(phone) != ''
                GROUP BY user_id, phone
            )
            AND phone IS NOT NULL
            AND TRIM(phone) != ''
        """)

        # Remove duplicate emails, keeping the oldest record.
        c.execute("""
            DELETE FROM contacts
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM contacts
                WHERE email IS NOT NULL
                  AND TRIM(email) != ''
                GROUP BY user_id, LOWER(TRIM(email))
            )
            AND email IS NOT NULL
            AND TRIM(email) != ''
        """)

        # Unique phone number per user.
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_contacts_user_phone_unique
            ON contacts(user_id, phone)
        """)

        # Unique email per user, ignoring case.
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_contacts_user_email_unique
            ON contacts(user_id, LOWER(TRIM(email)))
            WHERE email IS NOT NULL
              AND TRIM(email) != ''
        """)

        conn.commit()

        logger.info("Contact uniqueness indexes verified successfully.")
        return {"success": True}

    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating contact uniqueness indexes: {e}")
        return {"success": False, "error": str(e)}

    finally:
        conn.close()

# ============================================================
# SINGLE CONTACT IMPORT
# ============================================================

@retry_on_lock
def import_single_contact(
    user_id: int,
    name: str = "",
    phone: str = "",
    email: str = "",
    network: str = None,
    country: str = None
) -> Dict:
    """
    Import exactly ONE contact.

    Matching priority:
        1. Phone number
        2. Email address

    If a matching contact exists, update it.
    Otherwise, create a new contact.

    No duplicate contacts are created.
    """

    conn = get_db_connection()
    c = conn.cursor()

    try:
        name = (name or "").strip()
        phone = (phone or "").strip()
        email = (email or "").strip().lower()
        network = (network or "").strip()
        country = (country or "").strip()

        if not phone and not email:
            return {
                "success": False,
                "error": "Phone number or email is required"
            }

        # ----------------------------------------------------
        # FIND EXISTING CONTACT
        # ----------------------------------------------------

        existing = None

        if phone:
            existing = c.execute("""
                SELECT *
                FROM contacts
                WHERE user_id = ?
                  AND phone = ?
                LIMIT 1
            """, (user_id, phone)).fetchone()

        if not existing and email:
            existing = c.execute("""
                SELECT *
                FROM contacts
                WHERE user_id = ?
                  AND LOWER(TRIM(email)) = ?
                LIMIT 1
            """, (user_id, email)).fetchone()

        # ----------------------------------------------------
        # UPDATE EXISTING CONTACT
        # ----------------------------------------------------

        if existing:
            existing_id = existing["id"]

            c.execute("""
                UPDATE contacts
                SET
                    name = COALESCE(NULLIF(?, ''), name),
                    phone = COALESCE(NULLIF(?, ''), phone),
                    email = COALESCE(NULLIF(?, ''), email),
                    network = COALESCE(NULLIF(?, ''), network),
                    country = COALESCE(NULLIF(?, ''), country),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND user_id = ?
            """, (
                name,
                phone,
                email,
                network,
                country,
                existing_id,
                user_id
            ))

            conn.commit()

            return {
                "success": True,
                "id": existing_id,
                "created": False,
                "updated": True,
                "message": "Contact updated successfully"
            }

        # ----------------------------------------------------
        # INSERT NEW CONTACT
        # ----------------------------------------------------

        c.execute("""
            INSERT INTO contacts
                (user_id, name, phone, email, network, country)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            name or "Unknown Contact",
            phone or None,
            email or None,
            network or None,
            country or None
        ))

        contact_id = c.lastrowid

        conn.commit()

        return {
            "success": True,
            "id": contact_id,
            "created": True,
            "updated": False,
            "message": "Contact added successfully"
        }

    except sqlite3.IntegrityError:
        conn.rollback()

        return {
            "success": False,
            "error": "A contact with this phone number or email already exists"
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Error importing single contact: {e}")

        return {
            "success": False,
            "error": str(e)
        }

    finally:
        conn.close()        


@retry_on_lock
def sync_contacts(user_id: int, contacts: List[Dict]) -> Dict:
    """
    Sync contacts - updates existing ones, adds new ones.
    Uses phone number as unique identifier per user.
    This is a wrapper around import_contacts_unique for backward compatibility.
    """
    return import_contacts_unique(user_id, contacts)


@retry_on_lock
def add_contact(user_id: int, name: str, phone: str, network: str = None) -> Dict:
    """
    Add a single contact with duplicate checking.
    Returns: {success, id, updated, message}
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Check if contact already exists
        existing = c.execute(
            "SELECT id FROM contacts WHERE user_id = ? AND phone = ?",
            (user_id, phone),
        ).fetchone()
        
        if existing:
            # Update existing contact instead of creating duplicate
            c.execute(
                """
                UPDATE contacts 
                SET name = ?, network = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (name, network, existing["id"]),
            )
            conn.commit()
            return {"success": True, "id": existing["id"], "updated": True, "message": "Contact updated"}
        
        # Insert new contact
        c.execute(
            """
            INSERT INTO contacts (user_id, name, phone, network)
            VALUES (?, ?, ?, ?)
        """,
            (user_id, name, phone, network),
        )
        conn.commit()
        contact_id = c.lastrowid
        return {"success": True, "id": contact_id, "updated": False, "message": "Contact added"}
        
    except sqlite3.IntegrityError:
        conn.rollback()
        return {"success": False, "error": "Contact already exists", "updated": False}
    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding contact: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def remove_duplicate_contacts(user_id: int) -> Dict:
    """
    Remove duplicate contacts for a user.
    Keeps the first (oldest) contact for each phone number.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Find duplicate phone numbers
        duplicates = c.execute("""
            SELECT phone, COUNT(*) as count, MIN(id) as keep_id
            FROM contacts 
            WHERE user_id = ?
            GROUP BY phone 
            HAVING COUNT(*) > 1
        """, (user_id,)).fetchall()
        
        if not duplicates:
            return {"success": True, "removed": 0, "message": "No duplicates found"}
        
        removed_count = 0
        for dup in duplicates:
            # Delete all but the oldest (keep_id)
            deleted = c.execute("""
                DELETE FROM contacts 
                WHERE user_id = ? AND phone = ? AND id != ?
            """, (user_id, dup["phone"], dup["keep_id"]))
            removed_count += deleted.rowcount
        
        conn.commit()
        
        return {
            "success": True, 
            "removed": removed_count,
            "message": f"Removed {removed_count} duplicate contacts"
        }
        
    except Exception as e:
        logger.error(f"Error removing duplicate contacts: {e}")
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def get_contact_count(user_id: int) -> int:
    """Get total contact count for a user."""
    conn = get_db_connection()
    c = conn.cursor()
    count = c.execute(
        "SELECT COUNT(*) FROM contacts WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return count






def create_notification(user_id, title, message, notification_type):
    """Create a notification for a user"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (user_id, title, message, notification_type, 0))
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        logger.error(f"Error creating notification: {e}")
        return {'success': False, 'message': str(e)}
    
    # ============================================
    # ✅ CREDIT THE REFERRER'S BONUS
    # ============================================
    
    if referrer_id:
        try:
            # Calculate bonus (5% of the transaction amount)
            bonus_amount = amount * 0.05
            bonus_currency = "NGN"
            
            logger.info(f"💰 Crediting referral bonus: {bonus_currency} {bonus_amount:,.2f} to referrer {referrer_id}")
            
            # ✅ Credit the referrer's wallet
            if hasattr(db, 'credit_wallet'):
                credit_result = db.credit_wallet(
                    referrer_id, 
                    bonus_amount, 
                    "referral_bonus", 
                    f"Referral bonus from user {user_id}'s transaction"
                )
                
                if credit_result.get('success'):
                    logger.info(f"✅ Referral bonus of {bonus_currency} {bonus_amount:,.2f} credited to referrer {referrer_id}")
                    
                    # Create notification for referrer
                    if hasattr(db, 'create_notification'):
                        db.create_notification(
                            referrer_id,
                            "🎉 Referral Bonus Earned!",
                            f"You earned {bonus_currency} {bonus_amount:,.2f} (5% of your referral's transaction)!",
                            "success"
                        )
                        logger.info(f"✅ Notification sent to referrer {referrer_id}")
                else:
                    logger.error(f"❌ Failed to credit referral bonus: {credit_result}")
            else:
                logger.warning("credit_wallet function not found in database module")
                
        except Exception as e:
            logger.error(f"❌ Error giving referral bonus: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Don't fail the payment
    
    # ============================================
    # NOTIFY THE USER WHO FUNDED THEIR WALLET
    # ============================================
    
    if hasattr(db, 'create_notification'):
        db.create_notification(
            user_id,
            "💰 Wallet Funded Successfully!",
            f"Your wallet has been credited with NGN {amount:,.2f}",
            "success"
        )
    
    logger.info(f"Transaction {reference} completed successfully")

def process_pending_referrals() -> Dict:
    """
    Process all pending referrals where the referred user has made a transaction.
    This can be called manually or via a scheduled job.
    """
    conn = get_db_connection()
    c = conn.cursor()

    # Get all pending referrals where the referred user has made at least one transaction
    pending = c.execute("""
        SELECT 
            r.id,
            r.referrer_id,
            r.referred_id,
            u.full_name as referred_name,
            u.email as referred_email,
            COUNT(t.id) as tx_count
        FROM referrals r
        JOIN users u ON u.id = r.referred_id
        LEFT JOIN transactions t ON t.user_id = r.referred_id AND t.status = 'fulfilled' AND t.tx_type != 'wallet_funding'
        WHERE r.status = 'pending'
        GROUP BY r.id
        HAVING COUNT(t.id) > 0
    """).fetchall()

    processed = 0
    errors = []
    results = []

    for referral in pending:
        try:
            # Check if this is a valid referral (not the default code)
            if referral["referrer_id"] == referral["referred_id"]:
                continue

            bonus_amount = 50.00
            bonus_currency = "NGN"

            # Credit the referrer
            credit_result = credit_wallet(
                user_id=referral["referrer_id"],
                amount=bonus_amount,
                currency=bonus_currency,
                description=f"🎉 Referral bonus for {referral['referred_name']} completing first transaction!",
                reference=f"REFBONUS-{referral['id']}",
                metadata={
                    "referral_id": referral["id"],
                    "referred_user_id": referral["referred_id"],
                    "type": "referral_bonus",
                },
            )

            if credit_result.get("success"):
                # Update referral status
                c.execute(
                    """
                    UPDATE referrals 
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (referral["id"],),
                )
                conn.commit()
                processed += 1

                # Create notifications
                create_notification(
                    referral["referrer_id"],
                    "🎉 Referral Bonus Earned!",
                    f"You earned {bonus_currency} {bonus_amount:,.2f} for referring {referral['referred_name']}!",
                    "success",
                )

                create_notification(
                    referral["referred_id"],
                    "🎉 Welcome Bonus!",
                    f"You received a welcome bonus for your first transaction!",
                    "success",
                )

                results.append(
                    {
                        "referral_id": referral["id"],
                        "referrer_id": referral["referrer_id"],
                        "referred_id": referral["referred_id"],
                        "bonus_amount": bonus_amount,
                        "status": "success",
                    }
                )

                logger.info(
                    f"✅ Processed referral {referral['id']}: referrer={referral['referrer_id']}, referred={referral['referred_id']}"
                )
            else:
                errors.append(
                    f"Failed to credit referral {referral['id']}: {credit_result.get('error')}"
                )

        except Exception as e:
            errors.append(f"Error processing referral {referral['id']}: {str(e)}")
            logger.error(f"Error processing referral {referral['id']}: {e}")

    conn.close()

    return {
        "processed": processed,
        "errors": errors,
        "results": results,
        "message": f"Processed {processed} referral rewards",
    }


def init_db():
    """Initialize database with all tables and columns"""
    conn = get_db()
    c = conn.cursor()

    # Enable foreign keys
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode=WAL")

    init_brand_colors_table()
    init_promotions_table()
    init_seasonal_promos_table()

    # ============ USERS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            full_name TEXT NOT NULL,
            password_hash TEXT,
            currency TEXT DEFAULT 'NGN',
            referred_by INTEGER REFERENCES users(id),
            referral_code TEXT UNIQUE,
            account_status TEXT DEFAULT 'active',
            status_reason TEXT,
            status_changed_at TIMESTAMP,
            email_verified BOOLEAN DEFAULT 0,
            phone_verified BOOLEAN DEFAULT 0,
            verified_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Add missing columns to users table (migration)
    user_columns = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    for col, typ, default in [
        ("account_status", "TEXT", "'active'"),
        ("status_reason", "TEXT", "NULL"),
        ("status_changed_at", "TIMESTAMP", "NULL"),
        ("email_verified", "BOOLEAN", "0"),
        ("phone_verified", "BOOLEAN", "0"),
        ("verified_at", "TIMESTAMP", "NULL"),
    ]:
        if col not in user_columns:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ} DEFAULT {default}")

    # ============ SESSIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ TRANSACTIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            reference TEXT UNIQUE NOT NULL,
            tx_type TEXT NOT NULL,
            provider TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            payload TEXT,
            reloadly_result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ RELOADLY TRANSACTIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS reloadly_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            provider_transaction_id TEXT,
            result TEXT,
            currency TEXT DEFAULT 'NGN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ WALLET TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            currency TEXT NOT NULL DEFAULT 'NGN',
            balance REAL DEFAULT 0,
            available_balance REAL DEFAULT 0,
            reserved_balance REAL DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, currency)
        )
    """)

    # Add referral_bonus_config table
    c.execute("""
        CREATE TABLE IF NOT EXISTS referral_bonus_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bonus_percentage REAL DEFAULT 10.0,
            min_bonus REAL DEFAULT 50.0,
            max_bonus REAL DEFAULT 5000.0,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    """)

    # Insert default config if empty
    c.execute("SELECT COUNT(*) FROM referral_bonus_config")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO referral_bonus_config (bonus_percentage, min_bonus, max_bonus)
            VALUES (10.0, 50.0, 5000.0)
        """)
        conn.commit()
    # Migrate the original one-wallet-per-user schema to true multi-currency wallets.
    wallet_columns = {
        row[1] for row in c.execute("PRAGMA table_info(wallets)").fetchall()
    }
    wallet_indexes = c.execute("PRAGMA index_list(wallets)").fetchall()
    has_old_user_unique = False
    for idx in wallet_indexes:
        if len(idx) >= 3 and idx[2]:
            cols = [
                r[2] for r in c.execute(f"PRAGMA index_info('{idx[1]}')").fetchall()
            ]
            if cols == ["user_id"]:
                has_old_user_unique = True
                break
    if has_old_user_unique:
        legacy_name = "wallets_legacy"
        if c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (legacy_name,),
        ).fetchone():
            legacy_name = "wallets_legacy_" + datetime.now().strftime("%Y%m%d%H%M%S")
        c.execute(f"ALTER TABLE wallets RENAME TO {legacy_name}")
        c.execute("""
            CREATE TABLE wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                balance REAL DEFAULT 0,
                available_balance REAL DEFAULT 0,
                reserved_balance REAL DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, currency)
            )
        """)
        legacy_cols = {
            row[1] for row in c.execute(f"PRAGMA table_info({legacy_name})").fetchall()
        }
        if {"user_id", "balance"} <= legacy_cols:
            c.execute(f"""
                INSERT OR IGNORE INTO wallets
                    (user_id, currency, balance, available_balance, reserved_balance, created_at, updated_at)
                SELECT user_id, COALESCE(currency, 'NGN'), COALESCE(balance,0), COALESCE(balance,0), 0,
                       COALESCE(created_at,CURRENT_TIMESTAMP), COALESCE(updated_at,CURRENT_TIMESTAMP)
                FROM {legacy_name}
            """)

    # Add missing wallet/ledger columns for databases created by intermediate versions.
    wallet_columns = {
        row[1] for row in c.execute("PRAGMA table_info(wallets)").fetchall()
    }
    for col, typ, default in [
        ("available_balance", "REAL", "0"),
        ("reserved_balance", "REAL", "0"),
        ("status", "TEXT", "'active'"),
    ]:
        if col not in wallet_columns:
            c.execute(f"ALTER TABLE wallets ADD COLUMN {col} {typ} DEFAULT {default}")
    c.execute(
        "UPDATE wallets SET available_balance = balance WHERE available_balance IS NULL OR available_balance = 0"
    )

    # --- The following table/index/column definitions used to be dead code: they
    # sat after a return statement inside get_all_promotions(), so they never ran,
    # ever, on any deploy. Moved here so a fresh database actually gets these
    # tables (rewards, contacts, notifications, otp_codes, settings, sms_campaigns,
    # visitor_logs, webhook_events, receipt_promos, and more) created at startup. ---
    # ============ WALLET TRANSACTIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL DEFAULT 'NGN',
            type TEXT NOT NULL,
            description TEXT,
            reference TEXT UNIQUE,
            balance_before REAL,
            balance_after REAL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    wallet_tx_columns = {
        row[1] for row in c.execute("PRAGMA table_info(wallet_transactions)").fetchall()
    }
    for col, typ, default in [
        ("currency", "TEXT", "'NGN'"),
        ("balance_before", "REAL", "NULL"),
        ("balance_after", "REAL", "NULL"),
    ]:
        if col not in wallet_tx_columns:
            c.execute(
                f"ALTER TABLE wallet_transactions ADD COLUMN {col} {typ} DEFAULT {default}"
            )

    # ============ REWARDS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            points INTEGER DEFAULT 0,
            level TEXT DEFAULT 'Bronze',
            cashback_value REAL DEFAULT 0,
            cashback_currency TEXT DEFAULT 'NGN',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ REWARDS HISTORY TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS rewards_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            points_change INTEGER NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ REWARD LEDGER ============
    c.execute(
        "CREATE TABLE IF NOT EXISTS reward_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount REAL NOT NULL, currency TEXT NOT NULL, reward_type TEXT NOT NULL, description TEXT, reference TEXT UNIQUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_reward_ledger_user_id ON reward_ledger(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_reward_ledger_reference ON reward_ledger(reference)"
    )

    # ============ CONTACTS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            network TEXT,
            favorite BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, phone)
        )
    """)

    # ============ NOTIFICATIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ SUBSCRIPTIONS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            plan TEXT NOT NULL,
            account_number TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'NGN',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            next_billing_date TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ PROVIDERS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ============ PROVIDER PLANS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS provider_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'NGN',
            active BOOLEAN DEFAULT 1,
            FOREIGN KEY (provider_id) REFERENCES providers(id)
        )
    """)

    # ============ REFERRALS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (referrer_id) REFERENCES users(id),
            FOREIGN KEY (referred_id) REFERENCES users(id)
        )
    """)

    # ============ OTP CODES TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            code TEXT NOT NULL,
            type TEXT DEFAULT 'email',
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used BOOLEAN DEFAULT 0
        )
    """)

    # ============ WEBHOOKS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id TEXT UNIQUE NOT NULL,
            reference TEXT,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ============ RECEIPT PROMOS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS receipt_promos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_index INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            cta_text TEXT,
            cta_url TEXT,
            active BOOLEAN DEFAULT 1,
            source TEXT DEFAULT 'house',
            advertiser_user_id INTEGER,
            status TEXT DEFAULT 'approved',
            impressions_purchased INTEGER DEFAULT 0,
            impressions_delivered INTEGER DEFAULT 0,
            price_paid REAL DEFAULT 0,
            price_currency TEXT DEFAULT 'NGN',
            rejection_reason TEXT,
            reviewed_by TEXT,
            reviewed_at TIMESTAMP,
            submitted_at TIMESTAMP,
            campaign_tier TEXT DEFAULT 'basic',
            target_tx_type TEXT,
            target_min_amount REAL,
            target_max_amount REAL,
            target_customer_type TEXT,
            target_hour_start INTEGER,
            target_hour_end INTEGER,
            clicks_purchased INTEGER,
            clicks_delivered INTEGER DEFAULT 0,
            conversions_delivered INTEGER DEFAULT 0,
            click_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (advertiser_user_id) REFERENCES users(id)
        )
    """)

    # ============ AD CLICKS LOG ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS receipt_ad_clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            promo_id INTEGER NOT NULL,
            transaction_reference TEXT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (promo_id) REFERENCES receipt_promos(id)
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_receipt_ad_clicks_promo ON receipt_ad_clicks(promo_id)"
    )

    # ============ SETTINGS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            notifications_enabled BOOLEAN DEFAULT 1,
            email_notifications BOOLEAN DEFAULT 1,
            sms_notifications BOOLEAN DEFAULT 0,
            theme TEXT DEFAULT 'light',
            language TEXT DEFAULT 'en',
            currency TEXT DEFAULT 'NGN',
            sms_config TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ SCHEDULED PAYMENTS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            service_type TEXT NOT NULL,
            frequency TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'NGN',
            status TEXT DEFAULT 'active',
            metadata TEXT,
            next_run TIMESTAMP,
            day_of_month INTEGER DEFAULT 1,
            day_of_week INTEGER DEFAULT 0,
            month INTEGER DEFAULT 1,
            hour INTEGER DEFAULT 0,
            minute INTEGER DEFAULT 1,
            timezone TEXT DEFAULT 'Africa/Lagos',
            notify_days_before INTEGER DEFAULT 3,
            low_balance_daily BOOLEAN DEFAULT 1,
            last_run TIMESTAMP,
            last_error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ VISITOR LOGS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS visitor_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            visitor_name TEXT,
            ip_address TEXT,
            user_agent TEXT,
            device_type TEXT,
            os_name TEXT,
            browser TEXT,
            path TEXT,
            referrer TEXT,
            session_id TEXT,
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_user_id ON visitor_logs(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_visited_at ON visitor_logs(visited_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_device_type ON visitor_logs(device_type)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_ip_address ON visitor_logs(ip_address)"
    )

    # ============ SMS CAMPAIGNS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS sms_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            sender_id TEXT DEFAULT 'Net365',
            message TEXT NOT NULL,
            contact_list TEXT NOT NULL,
            contacts_json TEXT,
            scheduled_for TIMESTAMP,
            status TEXT DEFAULT 'draft',
            sent_count INTEGER DEFAULT 0,
            failed_count INTEGER DEFAULT 0,
            total_recipients INTEGER DEFAULT 0,
            provider TEXT,
            result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sms_campaigns_user_id ON sms_campaigns(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sms_campaigns_status ON sms_campaigns(status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_sms_campaigns_scheduled_for ON sms_campaigns(scheduled_for)"
    )

    # ============ BULK JOBS TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS bulk_jobs (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            total INTEGER DEFAULT 0,
            processed INTEGER DEFAULT 0,
            successful INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            file_name TEXT,
            error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ SCHEDULER SCHEDULES TABLE ============
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_schedules (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            service_type TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'NGN',
            frequency TEXT NOT NULL,
            country_code TEXT,
            operator_id TEXT,
            operator_name TEXT,
            phone TEXT,
            recipient TEXT,
            department TEXT,
            recipient_type TEXT DEFAULT 'individual',
            biller_id TEXT,
            biller_name TEXT,
            subscriber_account TEXT,
            day_of_month INTEGER DEFAULT 1,
            day_of_week INTEGER DEFAULT 0,
            month INTEGER DEFAULT 1,
            time TEXT DEFAULT '09:00',
            timezone TEXT DEFAULT 'Africa/Lagos',
            notify_days INTEGER DEFAULT 3,
            status TEXT DEFAULT 'active',
            priority INTEGER DEFAULT 5,
            wallet_currency TEXT DEFAULT 'NGN',
            next_run TIMESTAMP,
            last_run TIMESTAMP,
            last_error TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ============ CREATE INDEXES ============
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_user_id ON wallet_transactions(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_reference ON wallet_transactions(reference)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_reloadly_transactions_reference ON reloadly_transactions(reference)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)"
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_user_id ON contacts(user_id)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_rewards_history_user_id ON rewards_history(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id ON referrals(referrer_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referrals_referred_id ON referrals(referred_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_otp_codes_identifier ON otp_codes(identifier)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook_id ON webhook_events(webhook_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_payments_user_id ON scheduled_payments(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_payments_status ON scheduled_payments(status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduler_schedules_user_id ON scheduler_schedules(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduler_schedules_next_run ON scheduler_schedules(next_run)"
    )

    # Transaction money boundary migration
    existing_columns = {
        row[1] for row in c.execute("PRAGMA table_info(transactions)").fetchall()
    }
    for col, typ in [
        ("customer_amount", "REAL"),
        ("customer_currency", "TEXT"),
        ("fulfillment_amount", "REAL"),
        ("fulfillment_currency", "TEXT"),
        ("exchange_rate", "REAL"),
    ]:
        if col not in existing_columns:
            c.execute(f"ALTER TABLE transactions ADD COLUMN {col} {typ}")


    conn.commit()
    conn.close()

    # Keep the promotions table's extra discount/referral columns in sync too —
    # this used to live in a second, broken init_db() stub further down the file
    # that silently shadowed this function (Python keeps only the last def with a
    # given name), so on a fresh database NO tables were ever created. Merged here.
    migrate_promotions_table()


# ============ BRAND COLORS TABLE ============
def init_brand_colors_table():
    """Initialize the brand_colors table for advertiser branding."""
    conn = get_db()  # Use get_db() not get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS brand_colors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advertiser_id TEXT UNIQUE NOT NULL,
            advertiser_name TEXT NOT NULL,
            primary_color TEXT DEFAULT '#4f46e5',
            secondary_color TEXT DEFAULT '#7c3aed',
            accent_color TEXT DEFAULT '#06b6d4',
            text_color TEXT DEFAULT '#ffffff',
            background_color TEXT DEFAULT '#f8fafc',
            logo_url TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Insert default brand colors for common providers
    default_brands = [
        (
            "mtn",
            "MTN Nigeria",
            "#FFCD00",
            "#FFB300",
            "#1A1A2E",
            "#1A1A2E",
            "#FFCD00",
            None,
        ),
        (
            "glo",
            "Glo Nigeria",
            "#00A651",
            "#008C44",
            "#009639",
            "#FFFFFF",
            "#00A651",
            None,
        ),
        (
            "airtel",
            "Airtel Nigeria",
            "#E50000",
            "#CC0000",
            "#FF0000",
            "#FFFFFF",
            "#E50000",
            None,
        ),
        (
            "9mobile",
            "9mobile Nigeria",
            "#00A859",
            "#008C4A",
            "#00B86B",
            "#FFFFFF",
            "#00A859",
            None,
        ),
        ("dstv", "DSTV", "#FF6B00", "#E65C00", "#FF8C00", "#FFFFFF", "#FF6B00", None),
        ("gotv", "GOtv", "#FF6B00", "#E65C00", "#FF8C00", "#FFFFFF", "#FF6B00", None),
        (
            "startimes",
            "Startimes",
            "#ED1C24",
            "#CC0019",
            "#FF3333",
            "#FFFFFF",
            "#ED1C24",
            None,
        ),
        (
            "ikeja_electric",
            "Ikeja Electric",
            "#003366",
            "#002244",
            "#004488",
            "#FFFFFF",
            "#003366",
            None,
        ),
        (
            "eko_electric",
            "Eko Electric",
            "#006633",
            "#004422",
            "#008844",
            "#FFFFFF",
            "#006633",
            None,
        ),
        (
            "spectranet",
            "Spectranet",
            "#1A237E",
            "#0D1445",
            "#283593",
            "#FFFFFF",
            "#1A237E",
            None,
        ),
        ("smile", "Smile", "#E91E63", "#C2185B", "#F06292", "#FFFFFF", "#E91E63", None),
    ]

    for brand_id, name, primary, secondary, accent, text, bg, logo in default_brands:
        try:
            c.execute(
                """
                INSERT OR IGNORE INTO brand_colors 
                (advertiser_id, advertiser_name, primary_color, secondary_color, accent_color, text_color, background_color, logo_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (brand_id, name, primary, secondary, accent, text, bg, logo),
            )
        except Exception as e:
            logger.warning(f"Failed to insert brand {brand_id}: {e}")

    conn.commit()
    conn.close()
    logger.info("brand_colors table initialized")


def init_seasonal_promos_table():
    """Create the seasonal_promos table if it doesn't exist."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS seasonal_promos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                multiplier REAL DEFAULT 1.5,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        conn.commit()
        logger.info("✅ seasonal_promos table created successfully")
    except Exception as e:
        logger.error(f"Failed to create seasonal_promos table: {e}")
    finally:
        conn.close()


# ============ PROMOTIONS TABLE ============
def init_promotions_table():
    """Initialize the promotions table for admin-configurable promotions."""
    conn = get_db()  # Use get_db() not get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS promotions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            cta_text TEXT,
            cta_url TEXT,
            promo_type TEXT DEFAULT 'standard',
            category TEXT DEFAULT 'general',
            icon TEXT DEFAULT '🎁',
            brand_color TEXT DEFAULT '#4f46e5',
            background_color TEXT DEFAULT '#f5f3ff',
            text_color TEXT DEFAULT '#1e293b',
            active BOOLEAN DEFAULT 1,
            priority INTEGER DEFAULT 0,
            start_date TIMESTAMP,
            end_date TIMESTAMP,
            target_tx_type TEXT,
            target_min_amount REAL,
            target_max_amount REAL,
            target_customer_type TEXT,
            target_hour_start INTEGER,
            target_hour_end INTEGER,
            target_days TEXT,
            max_impressions INTEGER,
            impressions_used INTEGER DEFAULT 0,
            max_clicks INTEGER,
            clicks_used INTEGER DEFAULT 0,
            conversions INTEGER DEFAULT 0,
            metadata TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # Create indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_promotions_active ON promotions(active)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_promotions_target_tx_type ON promotions(target_tx_type)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_promotions_start_end ON promotions(start_date, end_date)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_promotions_priority ON promotions(priority)"
    )

    conn.commit()
    conn.close()
    logger.info("promotions table initialized")


# ============ ADD TO database.py - REFERRAL SYSTEM ENHANCEMENT ============


def migrate_referral_tables():
    """Add missing columns for referral tracking with expiry."""
    conn = get_db_connection()
    c = conn.cursor()

    # Add referral_expiry column to track 3-month validity
    columns = {row[1] for row in c.execute("PRAGMA table_info(referrals)").fetchall()}

    if "referral_expiry" not in columns:
        c.execute("ALTER TABLE referrals ADD COLUMN referral_expiry TIMESTAMP")

    if "reward_amount" not in columns:
        c.execute("ALTER TABLE referrals ADD COLUMN reward_amount REAL DEFAULT 0")

    if "reward_currency" not in columns:
        c.execute("ALTER TABLE referrals ADD COLUMN reward_currency TEXT DEFAULT 'NGN'")

    if "reward_paid" not in columns:
        c.execute("ALTER TABLE referrals ADD COLUMN reward_paid BOOLEAN DEFAULT 0")

    if "reward_paid_at" not in columns:
        c.execute("ALTER TABLE referrals ADD COLUMN reward_paid_at TIMESTAMP")

    # Create referral_rewards table for tracking rewards per transaction
    c.execute("""
        CREATE TABLE IF NOT EXISTS referral_rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referral_id INTEGER NOT NULL,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER NOT NULL,
            transaction_reference TEXT NOT NULL,
            transaction_amount REAL NOT NULL,
            reward_amount REAL NOT NULL,
            reward_currency TEXT DEFAULT 'NGN',
            reward_type TEXT DEFAULT 'percentage',
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP,
            FOREIGN KEY (referral_id) REFERENCES referrals(id),
            FOREIGN KEY (referrer_id) REFERENCES users(id),
            FOREIGN KEY (referred_id) REFERENCES users(id)
        )
    """)

    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referral_rewards_referral_id ON referral_rewards(referral_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referral_rewards_referrer_id ON referral_rewards(referrer_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referral_rewards_referred_id ON referral_rewards(referred_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_referral_rewards_status ON referral_rewards(status)"
    )

    conn.commit()
    conn.close()
    logger.info("Referral tables migrated successfully")


@retry_on_lock
def get_brand_colors(advertiser_id: str) -> Optional[Dict]:
    """Get brand colors for an advertiser."""
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute(
        "SELECT * FROM brand_colors WHERE advertiser_id = ? OR advertiser_name LIKE ?",
        (advertiser_id, f"%{advertiser_id}%"),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


@retry_on_lock
def get_all_brand_colors() -> List[Dict]:
    """Get all brand colors."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute("SELECT * FROM brand_colors ORDER BY advertiser_name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@retry_on_lock
def upsert_brand_colors(
    advertiser_id: str,
    advertiser_name: str,
    primary_color: str,
    secondary_color: str = None,
    accent_color: str = None,
    text_color: str = None,
    background_color: str = None,
    logo_url: str = None,
) -> bool:
    """Insert or update brand colors."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO brand_colors 
            (advertiser_id, advertiser_name, primary_color, secondary_color, accent_color, text_color, background_color, logo_url, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(advertiser_id) DO UPDATE SET
                advertiser_name = excluded.advertiser_name,
                primary_color = excluded.primary_color,
                secondary_color = excluded.secondary_color,
                accent_color = excluded.accent_color,
                text_color = excluded.text_color,
                background_color = excluded.background_color,
                logo_url = excluded.logo_url,
                updated_at = CURRENT_TIMESTAMP
        """,
            (
                advertiser_id,
                advertiser_name,
                primary_color,
                secondary_color or primary_color,
                accent_color or "#06b6d4",
                text_color or "#ffffff",
                background_color or "#f8fafc",
                logo_url,
            ),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to upsert brand colors: {e}")
        return False
    finally:
        conn.close()


# ============ PROMOTIONS ENGINE TABLE ============
@retry_on_lock
def init_promotions_table():
    """Initialize the promotions table for admin-configurable promotions."""
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS promotions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            cta_text TEXT,
            cta_url TEXT,
            promo_type TEXT DEFAULT 'standard',
            category TEXT DEFAULT 'general',
            icon TEXT DEFAULT '🎁',
            brand_color TEXT DEFAULT '#4f46e5',
            background_color TEXT DEFAULT '#f5f3ff',
            text_color TEXT DEFAULT '#1e293b',
            active BOOLEAN DEFAULT 1,
            priority INTEGER DEFAULT 0,
            start_date TIMESTAMP,
            end_date TIMESTAMP,
            target_tx_type TEXT,
            target_min_amount REAL,
            target_max_amount REAL,
            target_customer_type TEXT,
            target_hour_start INTEGER,
            target_hour_end INTEGER,
            target_days TEXT,  -- Comma-separated: 0,1,2,3,4,5,6 (Sun-Sat)
            max_impressions INTEGER,
            impressions_used INTEGER DEFAULT 0,
            max_clicks INTEGER,
            clicks_used INTEGER DEFAULT 0,
            conversions INTEGER DEFAULT 0,
            metadata TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # Create indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_promotions_active ON promotions(active)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_promotions_target_tx_type ON promotions(target_tx_type)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_promotions_start_end ON promotions(start_date, end_date)"
    )

    conn.commit()
    conn.close()


@retry_on_lock
def create_promotion(
    name: str,
    title: str,
    body: str,
    cta_text: str = None,
    cta_url: str = None,
    promo_type: str = "standard",
    category: str = "general",
    icon: str = "🎁",
    brand_color: str = "#4f46e5",
    background_color: str = "#f5f3ff",
    text_color: str = "#1e293b",
    active: bool = True,
    priority: int = 0,
    start_date: str = None,
    end_date: str = None,
    target_tx_type: str = None,
    target_min_amount: float = None,
    target_max_amount: float = None,
    target_customer_type: str = None,
    target_hour_start: int = None,
    target_hour_end: int = None,
    target_days: str = None,
    max_impressions: int = None,
    max_clicks: int = None,
    metadata: Dict = None,
    created_by: int = None,
    # ============================================
    # NEW FIELDS - MUST MATCH FRONTEND
    # ============================================
    discount_type: str = "fixed",
    discount_value: float = 0,
    max_discount: float = None,
    min_purchase: float = None,
    service_types: str = None,
    usage_limit_per_user: int = None,
    coupon_code: str = None,
    is_referral: bool = False,
    referrer_bonus_type: str = "fixed",
    referrer_bonus_value: float = 0,
    referred_bonus_type: str = "fixed",
    referred_bonus_value: float = 0,
) -> Optional[int]:
    """Create a new promotion with all fields including percentage discounts."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        # ============================================================
        # STEP 1: Ensure all columns exist
        # ============================================================
        c.execute("PRAGMA table_info(promotions)")
        existing_columns = {row[1] for row in c.fetchall()}

        columns_to_add = [
            ("discount_type", "TEXT", "'fixed'"),
            ("discount_value", "REAL", "0"),
            ("max_discount", "REAL", "NULL"),
            ("min_purchase", "REAL", "0"),
            ("service_types", "TEXT", "NULL"),
            ("usage_limit_per_user", "INTEGER", "NULL"),
            ("coupon_code", "TEXT", "NULL"),
            ("is_referral", "BOOLEAN", "0"),
            ("referrer_bonus_type", "TEXT", "'fixed'"),
            ("referrer_bonus_value", "REAL", "0"),
            ("referred_bonus_type", "TEXT", "'fixed'"),
            ("referred_bonus_value", "REAL", "0"),
        ]

        for col_name, col_type, default in columns_to_add:
            if col_name not in existing_columns:
                try:
                    c.execute(
                        f"ALTER TABLE promotions ADD COLUMN {col_name} {col_type} DEFAULT {default}"
                    )
                    logger.info(f"Added column {col_name} to promotions table")
                except Exception as e:
                    logger.warning(f"Could not add column {col_name}: {e}")

        # ============================================================
        # STEP 2: Insert the data
        # ============================================================
        c.execute(
            """
            INSERT INTO promotions (
                name, title, body, cta_text, cta_url, promo_type, category, icon,
                brand_color, background_color, text_color, active, priority,
                start_date, end_date, target_tx_type, target_min_amount, target_max_amount,
                target_customer_type, target_hour_start, target_hour_end, target_days,
                max_impressions, max_clicks, metadata, created_by,
                discount_type, discount_value, max_discount, min_purchase,
                service_types, usage_limit_per_user, coupon_code,
                is_referral, referrer_bonus_type, referrer_bonus_value,
                referred_bonus_type, referred_bonus_value
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                name,
                title,
                body,
                cta_text,
                cta_url,
                promo_type,
                category,
                icon,
                brand_color,
                background_color,
                text_color,
                1 if active else 0,
                priority,
                start_date,
                end_date,
                target_tx_type,
                target_min_amount,
                target_max_amount,
                target_customer_type,
                target_hour_start,
                target_hour_end,
                target_days,
                max_impressions,
                max_clicks,
                json.dumps(metadata or {}),
                created_by,
                discount_type,
                discount_value,
                max_discount,
                min_purchase,
                service_types,
                usage_limit_per_user,
                coupon_code,
                1 if is_referral else 0,
                referrer_bonus_type,
                referrer_bonus_value,
                referred_bonus_type,
                referred_bonus_value,
            ),
        )
        conn.commit()
        promo_id = c.lastrowid
        logger.info(f"Created promotion #{promo_id}: {name}")
        return promo_id
    except Exception as e:
        logger.error(f"Failed to create promotion: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()


# ============ REFERRAL SYSTEM ENHANCEMENTS ============


@retry_on_lock
def create_referral_code(user_id: int) -> str:
    """Generate a unique referral code for a user."""
    import secrets

    code = None
    attempts = 0
    conn = get_db_connection()
    c = conn.cursor()

    while attempts < 10:
        attempts += 1
        # Format: NET-XXXXX (5 random alphanumeric characters)
        code = f"NET-{secrets.token_hex(3).upper()}"

        existing = c.execute(
            "SELECT id FROM users WHERE referral_code = ?", (code,)
        ).fetchone()

        if not existing:
            c.execute(
                "UPDATE users SET referral_code = ? WHERE id = ?", (code, user_id)
            )
            conn.commit()
            conn.close()
            return code

    conn.close()
    return None


@retry_on_lock
def get_referral_by_code(code: str) -> Optional[Dict]:
    """Get user by referral code."""
    conn = get_db_connection()
    c = conn.cursor()
    user = c.execute(
        "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = UPPER(?)",
        (code,),
    ).fetchone()
    conn.close()
    return dict(user) if user else None


@retry_on_lock
def create_referral(
    referrer_id: int, referred_id: int, referral_code: str = None
) -> Optional[int]:
    """Create a new referral record with 3-month expiry."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check if already referred
    existing = c.execute(
        "SELECT id FROM referrals WHERE referred_id = ?", (referred_id,)
    ).fetchone()

    if existing:
        conn.close()
        return None

    # Calculate expiry (3 months from now)
    expiry = (datetime.now() + timedelta(days=90)).isoformat()

    try:
        c.execute(
            """
            INSERT INTO referrals (
                referrer_id, referred_id, status, referral_expiry, created_at
            ) VALUES (?, ?, 'pending', ?, CURRENT_TIMESTAMP)
        """,
            (referrer_id, referred_id, expiry),
        )

        referral_id = c.lastrowid
        conn.commit()
        conn.close()
        return referral_id
    except Exception as e:
        logger.error(f"Failed to create referral: {e}")
        conn.rollback()
        conn.close()
        return None


@retry_on_lock
def process_referral_reward(
    referred_user_id: int,
    transaction_reference: str,
    transaction_amount: float,
    transaction_currency: str = "NGN",
) -> Dict:
    """Process reward for referrer when referred user completes a transaction."""
    # -----------------------------------------------------------------
    # AUTHORITATIVE KILL-SWITCH
    #
    # Previously this function did `WHERE enabled = 1` when *reading* the
    # configured rate, but if that query returned no row (which is exactly
    # what happens when the admin disables bonuses), it fell back to a
    # hardcoded 5.0 — so bonuses still paid out at 5% with the toggle OFF.
    #
    # Check `enabled` up front and return immediately. This makes the
    # admin toggle truthful for this code path as well.
    # -----------------------------------------------------------------
    config_check = get_referral_bonus_config()
    if not config_check.get("enabled", True):
        return {"success": False, "error": "Referral bonuses are currently disabled"}

    conn = get_db_connection()
    c = conn.cursor()

    # Get pending referral for this user
    referral = c.execute(
        """
        SELECT r.*, u.referral_code as referrer_code
        FROM referrals r
        JOIN users u ON u.id = r.referrer_id
        WHERE r.referred_id = ? 
        AND r.status IN ('pending', 'completed')
        AND (r.referral_expiry IS NULL OR r.referral_expiry > datetime('now'))
        ORDER BY r.created_at DESC
        LIMIT 1
    """,
        (referred_user_id,),
    ).fetchone()

    if not referral:
        return {"success": False, "error": "No active referral found"}

    referral = dict(referral)
    referrer_id = referral["referrer_id"]

    # Check if already rewarded for this transaction
    existing = c.execute(
        "SELECT id FROM referral_rewards WHERE transaction_reference = ?",
        (transaction_reference,),
    ).fetchone()

    if existing:
        return {"success": True, "already_processed": True}

    # Use the percentage captured when the referral was created.
    # Fall back to the currently-configured percentage only for legacy
    # referrals that predate the config table. Since we already confirmed
    # bonuses are enabled above, reading the rate from the config here is
    # safe — but we should still pull the correct row rather than a
    # hardcoded 5%.
    bonus_percentage = float(referral.get("bonus_percentage") or 0)
    max_bonus = float(config_check.get("max_bonus") or 5000.0)

    if bonus_percentage <= 0:
        bonus_percentage = float(config_check.get("bonus_percentage") or 0)
        if bonus_percentage <= 0:
            # Still no rate configured — nothing to pay.
            return {"success": False, "error": "No referral bonus rate configured"}

    # Check if there's an active referral promotion (takes precedence over
    # the config rate if one exists)
    promo = c.execute("""
        SELECT * FROM promotions 
        WHERE active = 1 
        AND is_referral = 1
        AND (start_date IS NULL OR start_date <= datetime('now'))
        AND (end_date IS NULL OR end_date >= datetime('now'))
        ORDER BY priority DESC
        LIMIT 1
    """).fetchone()

    if promo:
        promo = dict(promo)
        if promo.get("referrer_bonus_type") == "percentage":
            bonus_percentage = float(promo.get("referrer_bonus_value") or bonus_percentage)
        else:
            # Fixed bonus - use the value directly, capped by max_bonus
            fixed_bonus = float(promo.get("referrer_bonus_value") or 0)
            if fixed_bonus > 0:
                bonus_amount = min(fixed_bonus, max_bonus)
                return _apply_referral_bonus(
                    referrer_id,
                    referred_user_id,
                    referral["id"],
                    transaction_reference,
                    transaction_amount,
                    bonus_amount,
                    "NGN",
                    "fixed",
                    max_bonus,
                )

    # Calculate percentage bonus, capped by max_bonus
    bonus_amount = min(transaction_amount * (bonus_percentage / 100), max_bonus)

    return _apply_referral_bonus(
        referrer_id,
        referred_user_id,
        referral["id"],
        transaction_reference,
        transaction_amount,
        bonus_amount,
        transaction_currency,
        "percentage",
        max_bonus,
    )

def _apply_referral_bonus(
    referrer_id: int,
    referred_id: int,
    referral_id: int,
    transaction_reference: str,
    transaction_amount: float,
    bonus_amount: float,
    currency: str,
    bonus_type: str,
    max_bonus: float,
) -> Dict:
    """Internal function to apply referral bonus."""
    if bonus_amount <= 0:
        return {"success": False, "error": "Bonus amount is zero"}

    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Credit referrer's wallet
        credit_result = credit_wallet(
            user_id=referrer_id,
            amount=bonus_amount,
            description=f"Referral bonus from user {referred_id} transaction {transaction_reference}",
            reference=f"REFBONUS-{transaction_reference}",
            currency=currency,
        )

        if not credit_result.get("success"):
            conn.close()
            return {
                "success": False,
                "error": credit_result.get("error", "Failed to credit referrer"),
            }

        # Record the reward
        c.execute(
            """
            INSERT INTO referral_rewards (
                referral_id, referrer_id, referred_id, 
                transaction_reference, transaction_amount, 
                reward_amount, reward_currency, reward_type, status, paid_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', CURRENT_TIMESTAMP)
        """,
            (
                referral_id,
                referrer_id,
                referred_id,
                transaction_reference,
                transaction_amount,
                bonus_amount,
                currency,
                bonus_type,
            ),
        )

        # Update referral total reward
        c.execute(
            """
            UPDATE referrals 
            SET reward_amount = reward_amount + ?,
                reward_currency = ?,
                reward_paid = 1,
                reward_paid_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (bonus_amount, currency, referral_id),
        )

        # Keep the referral active until its configured expiry.
        # The reward ledger, not referrals.status, controls duplicate prevention.
        # If this is the first transaction, mark referral as completed
        tx_count = c.execute(
            """
            SELECT COUNT(*) FROM referral_rewards 
            WHERE referral_id = ?
        """,
            (referral_id,),
        ).fetchone()[0]

        if tx_count == 1:
            c.execute(
                """
                UPDATE referrals 
                SET completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP)
                WHERE id = ?
            """,
                (referral_id,),
            )

        conn.commit()

        # Create notification for referrer
        create_notification(
            referrer_id,
            "🎉 Referral Bonus Earned!",
            f"You earned {currency} {bonus_amount:.2f} from a referral transaction!",
            "success",
        )

        conn.close()

        return {
            "success": True,
            "referral_id": referral_id,
            "bonus_amount": bonus_amount,
            "currency": currency,
            "bonus_type": bonus_type,
        }

    except Exception as e:
        logger.error(f"Failed to apply referral bonus: {e}")
        conn.rollback()
        conn.close()
        return {"success": False, "error": str(e)}


@retry_on_lock
def process_pending_referrals() -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    pending = c.execute("""
        SELECT 
            r.id,
            r.referrer_id,
            r.referred_id,
            u.full_name as referred_name,
            MIN(t.amount) as first_tx_amount,
            MIN(t.currency) as first_tx_currency
        FROM referrals r
        JOIN users u ON u.id = r.referred_id
        LEFT JOIN transactions t ON t.user_id = r.referred_id 
            AND t.status = 'fulfilled' 
            AND t.tx_type != 'wallet_funding'
        WHERE r.status = 'pending'
        GROUP BY r.id
        HAVING COUNT(t.id) > 0
    """).fetchall()

    processed = 0
    errors = []

    for referral in pending:
        try:
            first_amount = float(referral["first_tx_amount"] or 0)
            bonus_amount = max(round((first_amount * 10) / 100, 2), 50.00)
            bonus_currency = referral["first_tx_currency"] or "NGN"

            credit_result = credit_wallet(
                user_id=referral["referrer_id"],
                amount=bonus_amount,
                currency=bonus_currency,
                description=f"🎉 10% Referral bonus for {referral['referred_name']}!",
                reference=f"REFBONUS-{referral['id']}",
                metadata={
                    "referral_id": referral["id"],
                    "referred_user_id": referral["referred_id"],
                    "bonus_percentage": 10,
                    "transaction_amount": first_amount,
                    "type": "referral_bonus",
                },
            )

            if credit_result.get("success"):
                c.execute(
                    """
                    UPDATE referrals 
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (referral["id"],),
                )
                conn.commit()
                processed += 1

                create_notification(
                    referral["referrer_id"],
                    "🎉 Referral Bonus Earned!",
                    f"You earned {bonus_currency} {bonus_amount:,.2f} (10%) for referring {referral['referred_name']}!",
                    "success",
                )

        except Exception as e:
            errors.append(str(e))

    conn.close()
    return {"processed": processed, "errors": errors}


def apply_referral_promo(user_id: int, transaction_amount: float = None) -> Dict:
    """Apply referral promotion when a user completes their first transaction."""
    conn = get_db_connection()

    try:
        c = conn.cursor()

        # 1. Fetch pending referral
        c.execute(
            """
            SELECT r.id, r.referrer_id, r.status, u.full_name as referrer_name
            FROM referrals r
            JOIN users u ON u.id = r.referrer_id
            WHERE r.referred_id = ? AND r.status = 'pending'
            ORDER BY r.created_at DESC
            LIMIT 1
        """,
            (user_id,),
        )
        referral = c.fetchone()

        if not referral:
            conn.close()
            return {"success": False, "error": "No pending referral found"}

        ref_id = referral["id"]
        referrer_id = referral["referrer_id"]
        referrer_name = referral.get("referrer_name", "a referrer")

        # 2. Get first transaction amount (excluding wallet funding)
        c.execute(
            """
            SELECT amount, currency 
            FROM transactions 
            WHERE user_id = ? 
            AND status = 'fulfilled' 
            AND tx_type != 'wallet_funding'
            ORDER BY created_at ASC
            LIMIT 1
        """,
            (user_id,),
        )
        first_tx = c.fetchone()

        # ✅ FIX: Use passed transaction_amount if provided, otherwise use first_tx
        if transaction_amount and transaction_amount > 0:
            tx_amount = float(transaction_amount)
            bonus_currency = "NGN"  # Default if not available
        elif first_tx and first_tx["amount"] and float(first_tx["amount"]) > 0:
            tx_amount = float(first_tx["amount"])
            bonus_currency = first_tx["currency"] or "NGN"
        else:
            tx_amount = 0
            bonus_currency = "NGN"

        # 3. Get referral bonus config
        c.execute(
            """
            SELECT bonus_percentage, min_bonus, max_bonus 
            FROM referral_bonus_config 
            ORDER BY id DESC 
            LIMIT 1
        """
        )
        config = c.fetchone()

        if config:
            bonus_percentage = float(config["bonus_percentage"] if config["bonus_percentage"] is not None else 10.0)
            min_bonus = float(config["min_bonus"] if config["min_bonus"] is not None else 50.0)
            max_bonus = float(config["max_bonus"] if config["max_bonus"] is not None else 5000.0)
        else:
            bonus_percentage, min_bonus, max_bonus = 10.0, 50.0, 5000.0

        # 4. Calculate Bonus Amount
        if tx_amount > 0:
            bonus_amount = (tx_amount * bonus_percentage) / 100
            bonus_amount = max(bonus_amount, min_bonus)
            bonus_amount = min(bonus_amount, max_bonus)
            bonus_amount = round(bonus_amount, 2)
        else:
            bonus_amount = min_bonus
            bonus_currency = "NGN"

        logger.info(f"💰 Calculated bonus: {bonus_percentage}% of {tx_amount} = {bonus_amount} {bonus_currency}")

        # 5. Credit Referrer Wallet
        credit_result = credit_wallet(
            user_id=referrer_id,
            amount=bonus_amount,
            currency=bonus_currency,
            description=f"🎉 {bonus_percentage}% Referral bonus for referring a new user!",
            reference=f"REFBONUS-{ref_id}",
            metadata={
                "referral_id": ref_id,
                "referred_user_id": user_id,
                "bonus_percentage": bonus_percentage,
                "transaction_amount": tx_amount,
                "type": "referral_bonus",
            },
        )

        if not credit_result.get("success"):
            conn.close()
            return {
                "success": False,
                "error": f"Failed to credit bonus: {credit_result.get('error')}",
            }

        # 6. Update Referral Status
        c.execute(
            """
            UPDATE referrals 
            SET status = 'completed', 
                completed_at = CURRENT_TIMESTAMP,
                reward_amount = ?,
                reward_currency = ?,
                bonus_percentage = ?
            WHERE id = ? AND status = 'pending'
        """,
            (bonus_amount, bonus_currency, bonus_percentage, ref_id),
        )

        if c.rowcount == 0:
            conn.close()
            logger.warning(f"Referral {ref_id} was already updated by another process.")
            return {
                "success": False,
                "error": "Referral already processed",
            }

        conn.commit()

        # 7. Notifications
        create_notification(
            referrer_id,
            "🎉 Referral Bonus Earned!",
            f"You earned {bonus_currency} {bonus_amount:,.2f} ({bonus_percentage}% of their first transaction) for your referral!",
            "success",
        )

        create_notification(
            user_id,
            "🎉 Welcome Bonus!",
            f"You received {bonus_currency} {bonus_amount:,.2f} as a welcome bonus!",
            "success",
        )

        conn.close()

        return {
            "success": True,
            "bonus_amount": bonus_amount,
            "bonus_currency": bonus_currency,
            "referrer_id": referrer_id,
            "referrer_name": referrer_name,
            "referral_id": ref_id,
            "bonus_percentage": bonus_percentage,
        }

    except Exception as e:
        logger.error(f"Error applying referral promo for user {user_id}: {e}", exc_info=True)
        conn.close()
        return {"success": False, "error": str(e)}


@retry_on_lock
def get_referral_stats(user_id: int) -> Dict:
    """Get detailed referral statistics for a user."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get total referrals
    total = (
        c.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = ?", (user_id,)
        ).fetchone()[0]
        or 0
    )

    # Get completed referrals
    completed = (
        c.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND status = 'completed'",
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    # Get pending referrals
    pending = (
        c.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND status = 'pending'",
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    # Get expired referrals
    expired = (
        c.execute(
            """
        SELECT COUNT(*) FROM referrals 
        WHERE referrer_id = ? 
        AND status = 'pending' 
        AND referral_expiry < datetime('now')
    """,
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    # Get total earnings
    total_earnings = (
        c.execute(
            """
        SELECT COALESCE(SUM(reward_amount), 0) FROM referral_rewards 
        WHERE referrer_id = ? AND status = 'completed'
    """,
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    # Get total transactions from referrals
    total_transactions = (
        c.execute(
            """
        SELECT COUNT(DISTINCT transaction_reference) FROM referral_rewards 
        WHERE referrer_id = ?
    """,
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    # Get active referrals (still within 3-month window)
    active = (
        c.execute(
            """
        SELECT COUNT(*) FROM referrals 
        WHERE referrer_id = ? 
        AND status = 'pending'
        AND (referral_expiry IS NULL OR referral_expiry > datetime('now'))
    """,
            (user_id,),
        ).fetchone()[0]
        or 0
    )

    conn.close()

    return {
        "total": total,
        "completed": completed,
        "pending": pending,
        "expired": expired,
        "active": active,
        "total_earnings": total_earnings,
        "total_transactions": total_transactions,
    }


@retry_on_lock
def get_referral_details(user_id: int) -> List[Dict]:
    """Get detailed referral list for a user."""
    conn = get_db_connection()
    c = conn.cursor()

    rows = c.execute(
        """
        SELECT 
            r.*,
            u.full_name as referred_name,
            u.email as referred_email,
            u.phone as referred_phone,
            u.created_at as referred_joined_at,
            (
                SELECT COUNT(*) FROM referral_rewards rr 
                WHERE rr.referral_id = r.id
            ) as transaction_count,
            (
                SELECT COALESCE(SUM(rr.reward_amount), 0) FROM referral_rewards rr 
                WHERE rr.referral_id = r.id AND rr.status = 'completed'
            ) as total_earned
        FROM referrals r
        JOIN users u ON u.id = r.referred_id
        WHERE r.referrer_id = ?
        ORDER BY r.created_at DESC
    """,
        (user_id,),
    ).fetchall()

    result = []
    for row in rows:
        r = dict(row)
        if r.get("referral_expiry"):
            try:
                expiry = datetime.fromisoformat(r["referral_expiry"])
                r["days_remaining"] = max(0, (expiry - datetime.now()).days)
            except:
                r["days_remaining"] = 0
        result.append(r)

    conn.close()
    return result


@retry_on_lock
def get_referral_code_by_user_id(user_id: int) -> Optional[str]:
    """Get a user's referral code."""
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute(
        "SELECT referral_code FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return row["referral_code"] if row else None


@retry_on_lock
def get_referrals_count_by_code(code: str) -> int:
    """Get count of referrals using a specific referral code."""
    if not code:
        return 0

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "SELECT COUNT(*) FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (code.strip(),),
        )
        result = c.fetchone()
        return result[0] if result else 0
    finally:
        conn.close()


@retry_on_lock
def get_referral_code_owner(code: str) -> Optional[Dict]:
    """Get the user who owns a referral code."""
    if not code:
        return None

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (code.strip(),),
        )
        row = c.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


@retry_on_lock
def get_promotion(promo_id: int) -> Optional[Dict]:
    """Get a promotion by ID."""
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute("SELECT * FROM promotions WHERE id = ?", (promo_id,)).fetchone()
    conn.close()
    if row:
        promo = dict(row)
        if promo.get("metadata"):
            try:
                promo["metadata"] = json.loads(promo["metadata"])
            except:
                pass
        return promo
    return None


@retry_on_lock
def get_active_promotions(context: Dict = None) -> List[Dict]:
    """
    Get all active promotions that match the current context.
    Context should contain: tx_type, amount, user_id, hour, day_of_week, is_new_customer
    """
    conn = get_db_connection()
    c = conn.cursor()

    context = context or {}
    tx_type = context.get("tx_type", "").lower()
    amount = context.get("amount")
    hour = context.get("hour", datetime.now().hour)
    day_of_week = context.get("day_of_week", datetime.now().weekday())
    is_new = context.get("is_new_customer", False)
    user_id = context.get("user_id")
    now = datetime.now().isoformat()

    # Build query with all targeting filters
    query = """
        SELECT * FROM promotions 
        WHERE active = 1
        AND (start_date IS NULL OR start_date <= ?)
        AND (end_date IS NULL OR end_date >= ?)
        AND (max_impressions IS NULL OR impressions_used < max_impressions)
        AND (max_clicks IS NULL OR clicks_used < max_clicks)
    """
    params = [now, now]

    # Target tx_type
    if tx_type:
        query += """ AND (
            target_tx_type IS NULL 
            OR target_tx_type = '' 
            OR target_tx_type = ? 
            OR target_tx_type LIKE '%all%'
        )"""
        params.append(tx_type)

    # Target amount range
    if amount is not None:
        query += """ AND (
            target_min_amount IS NULL 
            OR target_min_amount <= ?
        )"""
        params.append(amount)
        query += """ AND (
            target_max_amount IS NULL 
            OR target_max_amount >= ?
        )"""
        params.append(amount)

    # Target customer type
    if is_new:
        query += """ AND (
            target_customer_type IS NULL 
            OR target_customer_type = '' 
            OR target_customer_type = 'new'
        )"""
    else:
        query += """ AND (
            target_customer_type IS NULL 
            OR target_customer_type = '' 
            OR target_customer_type = 'returning'
        )"""

    # Target hour range
    if hour is not None:
        query += """ AND (
            target_hour_start IS NULL 
            OR target_hour_end IS NULL
            OR (target_hour_start <= target_hour_end AND target_hour_start <= ? AND target_hour_end >= ?)
            OR (target_hour_start > target_hour_end AND (? >= target_hour_start OR ? <= target_hour_end))
        )"""
        params.extend([hour, hour, hour, hour])

    # Target days
    if day_of_week is not None:
        day_str = str(day_of_week)
        query += """ AND (
            target_days IS NULL 
            OR target_days = '' 
            OR target_days LIKE ?
            OR target_days LIKE ?
            OR target_days LIKE ?
            OR target_days = ?
        )"""
        params.extend([f"%{day_str}%", f"{day_str},%", f"%,{day_str}", day_str])

    query += " ORDER BY priority DESC, created_at DESC"

    try:
        rows = c.execute(query, params).fetchall()
        promotions = []
        for row in rows:
            promo = dict(row)
            if promo.get("metadata"):
                try:
                    promo["metadata"] = json.loads(promo["metadata"])
                except:
                    pass
            promotions.append(promo)
        return promotions
    except Exception as e:
        logger.error(f"Error fetching active promotions: {e}")
        return []
    finally:
        conn.close()


@retry_on_lock
def track_promotion_impression(promo_id: int) -> bool:
    """Increment impression count for a promotion."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            UPDATE promotions 
            SET impressions_used = impressions_used + 1
            WHERE id = ? AND (max_impressions IS NULL OR impressions_used < max_impressions)
        """,
            (promo_id,),
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to track promotion impression: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def track_promotion_click(promo_id: int) -> bool:
    """Increment click count for a promotion."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            UPDATE promotions 
            SET clicks_used = clicks_used + 1,
                conversions = conversions + 1
            WHERE id = ? AND (max_clicks IS NULL OR clicks_used < max_clicks)
        """,
            (promo_id,),
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to track promotion click: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def update_promotion(promo_id: int, **kwargs) -> bool:
    """Update a promotion."""
    allowed_fields = [
        "name",
        "title",
        "body",
        "cta_text",
        "cta_url",
        "promo_type",
        "category",
        "icon",
        "brand_color",
        "background_color",
        "text_color",
        "active",
        "priority",
        "start_date",
        "end_date",
        "target_tx_type",
        "target_min_amount",
        "target_max_amount",
        "target_customer_type",
        "target_hour_start",
        "target_hour_end",
        "target_days",
        "max_impressions",
        "max_clicks",
        "metadata",
        # NEW FIELDS
        "discount_type",
        "discount_value",
        "max_discount",
        "min_purchase",
        "service_types",
        "usage_limit_per_user",
        "coupon_code",
        "is_referral",
        "referrer_bonus_type",
        "referrer_bonus_value",
        "referred_bonus_type",
        "referred_bonus_value",
    ]
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not updates:
        return False

    # Handle metadata specially
    if "metadata" in updates:
        updates["metadata"] = json.dumps(updates["metadata"] or {})

    # Handle boolean fields
    if "is_referral" in updates:
        updates["is_referral"] = 1 if updates["is_referral"] else 0
    if "active" in updates:
        updates["active"] = 1 if updates["active"] else 0

    set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
    values = list(updates.values()) + [promo_id]

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            f"UPDATE promotions SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            values,
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to update promotion: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


@retry_on_lock
def delete_promotion(promo_id: int) -> bool:
    """Delete a promotion."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM promotions WHERE id = ?", (promo_id,))
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to delete promotion: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def get_all_promotions(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Get all promotions with pagination."""
    conn = get_db_connection()
    c = conn.cursor()

    # First, ensure all columns exist
    c.execute("PRAGMA table_info(promotions)")
    existing = {row[1] for row in c.fetchall()}

    # If table is missing columns, they'll be added on next create/update

    rows = c.execute(
        """
        SELECT * FROM promotions 
        ORDER BY priority DESC, created_at DESC
        LIMIT ? OFFSET ?
    """,
        (limit, offset),
    ).fetchall()
    conn.close()
    promotions = []
    for row in rows:
        promo = dict(row)
        if promo.get("metadata"):
            try:
                promo["metadata"] = json.loads(promo["metadata"])
            except:
                pass
        # Set defaults for missing fields
        if "discount_type" not in promo:
            promo["discount_type"] = "fixed"
        if "discount_value" not in promo:
            promo["discount_value"] = 0
        if "is_referral" not in promo:
            promo["is_referral"] = 0
        promotions.append(promo)
    return promotions



# ============ USER FUNCTIONS ============


def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


@retry_on_lock
def create_user(
    email: str = None,
    password: str = None,
    full_name: str = None,
    phone: str = None,
    referral_code: str = None,
) -> Optional[int]:
    """
    Create a new user and initialize the user's wallets,
    rewards, settings, and referral relationship.
    """

    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Ensure foreign-key enforcement is enabled for this connection
        cursor.execute("PRAGMA foreign_keys = ON")

        # --------------------------------------------------
        # Check for an existing email
        # --------------------------------------------------
        if email:
            existing = cursor.execute(
                """
                SELECT id
                FROM users
                WHERE LOWER(email) = LOWER(?)
                LIMIT 1
                """,
                (email.strip(),),
            ).fetchone()

            if existing:
                logger.warning(
                    "Registration rejected: email already exists: %s",
                    email,
                )
                return None

        # --------------------------------------------------
        # Check for an existing phone number
        # --------------------------------------------------
        if phone:
            existing = cursor.execute(
                """
                SELECT id
                FROM users
                WHERE phone = ?
                LIMIT 1
                """,
                (phone.strip(),),
            ).fetchone()

            if existing:
                logger.warning(
                    "Registration rejected: phone already exists: %s",
                    phone,
                )
                return None

        # --------------------------------------------------
        # Generate a unique referral code for the new user
        # --------------------------------------------------
        while True:
            user_referral_code = f"NET-{secrets.token_hex(4).upper()}"

            existing_code = cursor.execute(
                """
                SELECT id
                FROM users
                WHERE UPPER(referral_code) = UPPER(?)
                LIMIT 1
                """,
                (user_referral_code,),
            ).fetchone()

            if not existing_code:
                break

        # --------------------------------------------------
        # Hash password
        # --------------------------------------------------
        password_hash = hash_password(password) if password else None

        referrer = None
        referred_by = None

        # --------------------------------------------------
        # Resolve referral code
        # --------------------------------------------------
        if referral_code and referral_code.strip():

            search_code = referral_code.strip().upper()

            # First, try the exact supplied code
            referrer = cursor.execute(
                """
                SELECT id, full_name, referral_code
                FROM users
                WHERE UPPER(referral_code) = UPPER(?)
                LIMIT 1
                """,
                (search_code,),
            ).fetchone()

            # If NET- prefix was omitted, try adding it
            if not referrer and not search_code.startswith("NET-"):
                referrer = cursor.execute(
                    """
                    SELECT id, full_name, referral_code
                    FROM users
                    WHERE UPPER(referral_code) = UPPER(?)
                    LIMIT 1
                    """,
                    (f"NET-{search_code}",),
                ).fetchone()

            # If NET- prefix was supplied, also try without it
            if not referrer and search_code.startswith("NET-"):
                code_without_prefix = search_code[4:]

                referrer = cursor.execute(
                    """
                    SELECT id, full_name, referral_code
                    FROM users
                    WHERE UPPER(referral_code) = UPPER(?)
                    LIMIT 1
                    """,
                    (code_without_prefix,),
                ).fetchone()

            if referrer:
                referred_by = referrer["id"]

                logger.info(
                    "Valid referral code %s from user %s (%s)",
                    search_code,
                    referrer["id"],
                    referrer["full_name"],
                )
            else:
                logger.warning(
                    "Invalid referral code attempted: %s",
                    search_code,
                )

        # --------------------------------------------------
        # Create the user
        # --------------------------------------------------
        cursor.execute(
            """
            INSERT INTO users (
                email,
                phone,
                full_name,
                password_hash,
                referral_code,
                referred_by,
                account_status,
                email_verified
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active', 0)
            """,
            (
                email.strip() if email else None,
                phone.strip() if phone else None,
                full_name.strip() if full_name else "User",
                password_hash,
                user_referral_code,
                referred_by,
            ),
        )

        user_id = cursor.lastrowid

        if not user_id:
            raise sqlite3.IntegrityError("User was not created")

        # --------------------------------------------------
        # Create NGN wallet
        # --------------------------------------------------
        cursor.execute(
            """
            INSERT OR IGNORE INTO wallets (
                user_id,
                currency,
                balance,
                available_balance,
                reserved_balance,
                status
            )
            VALUES (?, 'NGN', 0, 0, 0, 'active')
            """,
            (user_id,),
        )

        # --------------------------------------------------
        # Create USD wallet
        # --------------------------------------------------
        cursor.execute(
            """
            INSERT OR IGNORE INTO wallets (
                user_id,
                currency,
                balance,
                available_balance,
                reserved_balance,
                status
            )
            VALUES (?, 'USD', 0, 0, 0, 'active')
            """,
            (user_id,),
        )

        # --------------------------------------------------
        # Create rewards record
        # --------------------------------------------------
        cursor.execute(
            """
            INSERT INTO rewards (user_id)
            VALUES (?)
            """,
            (user_id,),
        )

        # --------------------------------------------------
        # Create settings record
        # --------------------------------------------------
        cursor.execute(
            """
            INSERT INTO settings (user_id)
            VALUES (?)
            """,
            (user_id,),
        )

        # --------------------------------------------------
        # Create referral relationship
        # --------------------------------------------------
        if referrer and referrer["id"] != user_id:
            cursor.execute(
                """
                INSERT OR IGNORE INTO referrals (
                    referrer_id,
                    referred_id,
                    status
                )
                VALUES (?, ?, 'pending')
                """,
                (
                    referrer["id"],
                    user_id,
                ),
            )

            logger.info(
                "Referral created: referrer=%s, referred=%s",
                referrer["id"],
                user_id,
            )

        # --------------------------------------------------
        # Commit the complete registration transaction
        # --------------------------------------------------
        conn.commit()

        logger.info(
            "User created successfully: %s, referral_code: %s",
            email,
            user_referral_code,
        )

        return user_id

    except sqlite3.IntegrityError as error:
        logger.error(
            "Integrity error creating user: %s",
            error,
        )

        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error as rollback_error:
                logger.warning(
                    "Rollback failed after integrity error: %s",
                    rollback_error,
                )

        return None

    except sqlite3.OperationalError as error:
        logger.error(
            "Database operational error creating user: %s",
            error,
        )

        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error as rollback_error:
                logger.warning(
                    "Rollback failed after operational error: %s",
                    rollback_error,
                )

        return None

    except Exception as error:
        logger.exception(
            "Unexpected error creating user: %s",
            error,
        )

        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error as rollback_error:
                logger.warning(
                    "Rollback failed after unexpected error: %s",
                    rollback_error,
                )

        return None

    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as close_error:
                logger.warning(
                    "Database connection close failed: %s",
                    close_error,
                )


def find_referral_code(search_code: str) -> Optional[Dict]:
    """
    Find a referral code with flexible matching.
    Returns the user record if found, None otherwise.
    """
    conn = get_db_connection()
    c = conn.cursor()

    search_code = search_code.strip().upper()
    referrer = None

    # 1. Try exact match
    referrer = c.execute(
        "SELECT id, full_name, email, referral_code FROM users WHERE UPPER(referral_code) = UPPER(?)",
        (search_code,),
    ).fetchone()

    # 2. Try with NET- prefix
    if not referrer and not search_code.startswith("NET-"):
        referrer = c.execute(
            "SELECT id, full_name, email, referral_code FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (f"NET-{search_code}",),
        ).fetchone()

    # 3. Try without NET- prefix
    if not referrer and search_code.startswith("NET-"):
        code_without_prefix = search_code[4:]
        referrer = c.execute(
            "SELECT id, full_name, email, referral_code FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (code_without_prefix,),
        ).fetchone()

    # 4. Try partial match (ends with)
    if not referrer and len(search_code) >= 4:
        referrer = c.execute(
            "SELECT id, full_name, email, referral_code FROM users WHERE UPPER(referral_code) LIKE UPPER(?)",
            (f"%{search_code}",),
        ).fetchone()

    conn.close()

    if referrer:
        return dict(referrer)
    return None


def get_referrals_count_by_code(referral_code: str) -> int:
    """Get count of users with a specific referral code."""
    conn = get_db_connection()
    c = conn.cursor()

    referral_code = referral_code.strip().upper()

    # Try exact match
    count = c.execute(
        "SELECT COUNT(*) FROM users WHERE UPPER(referral_code) = UPPER(?)",
        (referral_code,),
    ).fetchone()[0]

    # If not found, try with NET- prefix
    if count == 0 and not referral_code.startswith("NET-"):
        count = c.execute(
            "SELECT COUNT(*) FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (f"NET-{referral_code}",),
        ).fetchone()[0]

    # If not found, try without NET- prefix
    if count == 0 and referral_code.startswith("NET-"):
        clean_code = referral_code[4:]
        count = c.execute(
            "SELECT COUNT(*) FROM users WHERE UPPER(referral_code) = UPPER(?)",
            (clean_code,),
        ).fetchone()[0]

    conn.close()
    return count



from typing import Dict
import logging

logger = logging.getLogger(__name__)


def apply_referral_promo(user_id: int, transaction_amount: float = None) -> Dict:
    """Apply referral promotion when a user completes their first transaction."""
    conn = get_db_connection()
    
    try:
        c = conn.cursor()

        # 1. Fetch pending referral
        c.execute(
            """
            SELECT r.id, r.referrer_id, r.status, u.full_name as referrer_name
            FROM referrals r
            JOIN users u ON u.id = r.referrer_id
            WHERE r.referred_id = ? AND r.status = 'pending'
            ORDER BY r.created_at DESC
            LIMIT 1
        """,
            (user_id,),
        )
        referral_row = c.fetchone()
        
        # ✅ FIX: Convert to dict first
        if referral_row:
            referral = dict(referral_row)
        else:
            conn.close()
            return {"success": False, "error": "No pending referral found"}

        ref_id = referral["id"]
        referrer_id = referral["referrer_id"]
        referrer_name = referral.get("referrer_name", "a referrer")

        # 2. Get first transaction amount (excluding wallet funding)
        c.execute(
            """
            SELECT amount, currency 
            FROM transactions 
            WHERE user_id = ? 
            AND status = 'fulfilled' 
            AND tx_type != 'wallet_funding'
            ORDER BY created_at ASC
            LIMIT 1
        """,
            (user_id,),
        )
        first_tx_row = c.fetchone()
        
        # ✅ FIX: Convert to dict if exists
        first_tx = dict(first_tx_row) if first_tx_row else None

        # Use passed transaction_amount if provided
        if transaction_amount and transaction_amount > 0:
            tx_amount = float(transaction_amount)
            bonus_currency = "NGN"
        elif first_tx and first_tx.get("amount") and float(first_tx.get("amount", 0)) > 0:
            tx_amount = float(first_tx.get("amount", 0))
            bonus_currency = first_tx.get("currency", "NGN")
        else:
            tx_amount = 0
            bonus_currency = "NGN"

        # 3. Get referral bonus config
        c.execute(
            """
            SELECT bonus_percentage, min_bonus, max_bonus 
            FROM referral_bonus_config 
            ORDER BY id DESC 
            LIMIT 1
        """
        )
        config_row = c.fetchone()
        
        # ✅ FIX: Convert to dict if exists
        config = dict(config_row) if config_row else None

        if config:
            bonus_percentage = float(config.get("bonus_percentage", 10.0))
            min_bonus = float(config.get("min_bonus", 50.0))
            max_bonus = float(config.get("max_bonus", 5000.0))
        else:
            bonus_percentage, min_bonus, max_bonus = 10.0, 50.0, 5000.0

        # 4. Calculate Bonus Amount
        if tx_amount > 0:
            bonus_amount = (tx_amount * bonus_percentage) / 100
            bonus_amount = max(bonus_amount, min_bonus)
            bonus_amount = min(bonus_amount, max_bonus)
            bonus_amount = round(bonus_amount, 2)
        else:
            bonus_amount = min_bonus
            bonus_currency = "NGN"

        logger.info(f"💰 Calculated bonus: {bonus_percentage}% of {tx_amount} = {bonus_amount} {bonus_currency}")

        # 5. Credit Referrer Wallet
        credit_result = credit_wallet(
            user_id=referrer_id,
            amount=bonus_amount,
            currency=bonus_currency,
            description=f"🎉 {bonus_percentage}% Referral bonus for referring a new user!",
            reference=f"REFBONUS-{ref_id}",
            metadata={
                "referral_id": ref_id,
                "referred_user_id": user_id,
                "bonus_percentage": bonus_percentage,
                "transaction_amount": tx_amount,
                "type": "referral_bonus",
            },
        )

        if not credit_result.get("success"):
            conn.close()
            return {
                "success": False,
                "error": f"Failed to credit bonus: {credit_result.get('error')}",
            }

        # 6. Update Referral Status
        c.execute(
            """
            UPDATE referrals 
            SET status = 'completed', 
                completed_at = CURRENT_TIMESTAMP,
                reward_amount = ?,
                reward_currency = ?,
                bonus_percentage = ?
            WHERE id = ? AND status = 'pending'
        """,
            (bonus_amount, bonus_currency, bonus_percentage, ref_id),
        )

        if c.rowcount == 0:
            conn.close()
            logger.warning(f"Referral {ref_id} was already updated by another process.")
            return {
                "success": False,
                "error": "Referral already processed",
            }

        conn.commit()

        # 7. Notifications
        create_notification(
            referrer_id,
            "🎉 Referral Bonus Earned!",
            f"You earned {bonus_currency} {bonus_amount:,.2f} ({bonus_percentage}% of their first transaction) for your referral!",
            "success",
        )

        create_notification(
            user_id,
            "🎉 Welcome Bonus!",
            f"You received {bonus_currency} {bonus_amount:,.2f} as a welcome bonus!",
            "success",
        )

        conn.close()

        return {
            "success": True,
            "bonus_amount": bonus_amount,
            "bonus_currency": bonus_currency,
            "referrer_id": referrer_id,
            "referrer_name": referrer_name,
            "referral_id": ref_id,
            "bonus_percentage": bonus_percentage,
        }

    except Exception as e:
        logger.error(f"Error applying referral promo for user {user_id}: {e}", exc_info=True)
        if conn:
            conn.close()
        return {"success": False, "error": str(e)}

def calculate_referral_bonus(transaction_amount: float) -> Dict:
    """Calculate referral bonus based on config."""
    config = get_referral_bonus_config()

    bonus_percentage = config.get("bonus_percentage", 10.0)
    min_bonus = config.get("min_bonus", 50.0)
    max_bonus = config.get("max_bonus", 5000.0)

    # Calculate bonus
    bonus_amount = (transaction_amount * bonus_percentage) / 100

    # Apply min/max
    bonus_amount = max(bonus_amount, min_bonus)
    bonus_amount = min(bonus_amount, max_bonus)
    bonus_amount = round(bonus_amount, 2)

    return {
        "bonus_amount": bonus_amount,
        "bonus_percentage": bonus_percentage,
        "min_bonus": min_bonus,
        "max_bonus": max_bonus,
        "transaction_amount": transaction_amount,
    }



@retry_on_lock
def get_user(user_id: int) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    user = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(user) if user else None


@retry_on_lock
def get_user_by_email(email: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    user = c.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(user) if user else None


@retry_on_lock
def get_user_by_phone(phone: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    user = c.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
    return dict(user) if user else None


@retry_on_lock
def authenticate_user(email: str, password: str) -> Optional[Dict]:
    user = get_user_by_email(email)
    if not user:
        return None

    password_hash = hash_password(password)
    if user.get("password_hash") == password_hash:
        status = user.get("account_status", "active")
        if status in ("blocked", "deleted"):
            return None
        return user

    return None


@retry_on_lock
def update_user(user_id: int, **kwargs) -> bool:
    allowed = ["email", "phone", "full_name", "currency"]
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return False

    set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
    values = list(updates.values()) + [user_id]

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE users SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        values,
    )
    conn.commit()
    return True


@retry_on_lock
def set_referral_code(user_id: int, code: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET referral_code = ? WHERE id = ?", (code, user_id))
        conn.commit()
        return True
    except Exception:
        return False


# ============ SESSION FUNCTIONS ============


@retry_on_lock
def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(days=7)).isoformat()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (?, ?, ?)
    """,
        (token, user_id, expires_at),
    )
    conn.commit()
    return token


@retry_on_lock
def get_session(token: str) -> Optional[Dict]:
    if not token:
        return None
    conn = get_db_connection()
    c = conn.cursor()
    session = c.execute(
        """
        SELECT * FROM sessions 
        WHERE token = ? AND expires_at > datetime('now')
    """,
        (token,),
    ).fetchone()
    return dict(session) if session else None


@retry_on_lock
def delete_session(token: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    return True


# ============ TRANSACTION FUNCTIONS ============


@retry_on_lock
def create_pending(
    reference: str,
    tx_type: str,
    provider: str,
    amount: float,
    currency: str,
    payload: Dict,
    user_id: int = None,
) -> bool:
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            INSERT INTO transactions 
            (reference, tx_type, provider, amount, currency, payload, status, user_id)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
            (
                reference,
                tx_type,
                provider,
                amount,
                currency,
                json.dumps(payload),
                user_id,
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


@retry_on_lock
def count_user_fulfilled_transactions(
    user_id: int, before_reference: str = None
) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    if before_reference:
        ref_row = c.execute(
            "SELECT created_at FROM transactions WHERE reference = ?",
            (before_reference,),
        ).fetchone()
        cutoff = ref_row["created_at"] if ref_row else None
        if cutoff:
            row = c.execute(
                f"SELECT COUNT(*) FROM transactions WHERE user_id = ? AND status IN {_SUCCESS_STATUS_SQL} AND created_at <= ?",
                (user_id, cutoff),
            ).fetchone()
            return row[0] if row else 1
    row = c.execute(
        f"SELECT COUNT(*) FROM transactions WHERE user_id = ? AND status IN {_SUCCESS_STATUS_SQL}",
        (user_id,),
    ).fetchone()
    return row[0] if row else 1


@retry_on_lock
def get_transaction(reference: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    tx = c.execute(
        "SELECT * FROM transactions WHERE reference = ?", (reference,)
    ).fetchone()
    if tx:
        result = dict(tx)
        if result.get("payload"):
            try:
                result["payload"] = json.loads(result["payload"])
            except:
                pass
        if result.get("reloadly_result"):
            try:
                result["reloadly_result"] = json.loads(result["reloadly_result"])
            except:
                pass
        return result
    return None


@retry_on_lock
def get_transactions(user_id: int, limit: int = 20, offset: int = 0) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()

    query = """
        SELECT * FROM transactions 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    """
    params = (user_id, limit, offset)

    try:
        c.execute(query, params)
        transactions = c.fetchall()
        result = []
        for tx in transactions:
            tx_dict = dict(tx)
            if tx_dict.get("payload"):
                try:
                    tx_dict["payload"] = json.loads(tx_dict["payload"])
                except:
                    pass
            if tx_dict.get("reloadly_result"):
                try:
                    tx_dict["reloadly_result"] = json.loads(tx_dict["reloadly_result"])
                except:
                    pass
            result.append(tx_dict)
        return result
    except sqlite3.OperationalError as e:
        raise e


@retry_on_lock
def mark_paid(reference: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE transactions 
        SET status = 'paid', updated_at = CURRENT_TIMESTAMP 
        WHERE reference = ? AND status IN ('pending', 'processing')
    """,
        (reference,),
    )
    affected = c.rowcount
    conn.commit()
    return affected > 0


@retry_on_lock
def mark_fulfilled(reference: str, result: Dict) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE transactions 
        SET status = 'fulfilled', reloadly_result = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE reference = ?
    """,
        (json.dumps(result), reference),
    )
    conn.commit()
    return True


@retry_on_lock
def mark_failed(reference: str, error: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE transactions 
        SET status = 'failed', reloadly_result = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE reference = ?
    """,
        (json.dumps({"error": error}), reference),
    )
    conn.commit()
    return True


@retry_on_lock
def mark_fulfillment_failed(reference: str, error: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE transactions 
        SET status = 'fulfillment_failed', reloadly_result = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE reference = ?
    """,
        (json.dumps({"error": error}), reference),
    )
    conn.commit()
    return True


@retry_on_lock
def try_lock_for_fulfillment(reference: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE transactions 
        SET status = 'processing', updated_at = CURRENT_TIMESTAMP 
        WHERE reference = ? AND status IN ('paid', 'pending')
    """,
        (reference,),
    )
    affected = c.rowcount
    conn.commit()
    return affected > 0


@retry_on_lock
def list_needing_attention() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    transactions = c.execute("""
        SELECT * FROM transactions 
        WHERE status IN ('fulfillment_failed', 'processing')
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    result = []
    for tx in transactions:
        tx_dict = dict(tx)
        if tx_dict.get("payload"):
            try:
                tx_dict["payload"] = json.loads(tx_dict["payload"])
            except:
                pass
        if tx_dict.get("reloadly_result"):
            try:
                tx_dict["reloadly_result"] = json.loads(tx_dict["reloadly_result"])
            except:
                pass
        result.append(tx_dict)
    return result


# ============ RELOADLY TRANSACTION FUNCTIONS ============


@retry_on_lock
def create_reloadly_transaction(
    reference: str,
    user_id: int,
    transaction_type: str,
    amount: float,
    status: str = "pending",
    provider_transaction_id: str = None,
    result: Dict = None,
    currency: str = None,
) -> bool:
    conn = get_db_connection()
    c = conn.cursor()

    columns = {
        row[1]
        for row in c.execute("PRAGMA table_info(reloadly_transactions)").fetchall()
    }
    has_currency_column = "currency" in columns

    if not has_currency_column:
        try:
            c.execute(
                "ALTER TABLE reloadly_transactions ADD COLUMN currency TEXT DEFAULT 'NGN'"
            )
            conn.commit()
            has_currency_column = True
        except Exception as e:
            logger.warning(f"Could not add currency column: {e}")
            has_currency_column = False

    try:
        if has_currency_column and currency:
            c.execute(
                """
                INSERT INTO reloadly_transactions 
                (reference, user_id, transaction_type, amount, status, provider_transaction_id, result, currency)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    reference,
                    user_id,
                    transaction_type,
                    amount,
                    status,
                    provider_transaction_id,
                    json.dumps(result) if result else None,
                    currency,
                ),
            )
        else:
            c.execute(
                """
                INSERT INTO reloadly_transactions 
                (reference, user_id, transaction_type, amount, status, provider_transaction_id, result)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    reference,
                    user_id,
                    transaction_type,
                    amount,
                    status,
                    provider_transaction_id,
                    json.dumps(result) if result else None,
                ),
            )

        conn.commit()
        return True

    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e):
            existing = c.execute(
                "SELECT id FROM reloadly_transactions WHERE reference = ?", (reference,)
            ).fetchone()
            if existing:
                return True
        logger.error(f"Failed to create reloadly transaction: {e}")
        return False
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to create reloadly transaction: {e}")
        return False


@retry_on_lock
def get_reloadly_transaction_by_reference(reference: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    tx = c.execute(
        "SELECT * FROM reloadly_transactions WHERE reference = ?", (reference,)
    ).fetchone()
    return dict(tx) if tx else None


@retry_on_lock
def update_reloadly_transaction(
    reference: str,
    status: str,
    provider_transaction_id: str = None,
    result: Dict = None,
) -> bool:
    conn = get_db_connection()
    c = conn.cursor()

    updates = ["status = ?"]
    params = [status]

    if provider_transaction_id:
        updates.append("provider_transaction_id = ?")
        params.append(provider_transaction_id)

    if result:
        updates.append("result = ?")
        params.append(json.dumps(result))

    params.append(reference)

    c.execute(
        f"""
        UPDATE reloadly_transactions 
        SET {', '.join(updates)}
        WHERE reference = ?
    """,
        params,
    )

    conn.commit()
    return True


# ============ WALLET FUNCTIONS ============


@retry_on_lock
def ensure_wallet(user_id: int, currency: str = "NGN") -> Dict:
    currency = (currency or "NGN").upper()
    conn = get_db_connection()
    c = conn.cursor()
    try:
        wallet = c.execute(
            "SELECT * FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        ).fetchone()
        if not wallet:
            c.execute(
                """
                INSERT INTO wallets (user_id, currency, balance, available_balance, reserved_balance)
                VALUES (?, ?, 0, 0, 0)
            """,
                (user_id, currency),
            )
            conn.commit()
            wallet = c.execute(
                "SELECT * FROM wallets WHERE user_id = ? AND currency = ?",
                (user_id, currency),
            ).fetchone()
        return dict(wallet) if wallet else None
    finally:
        pass


@retry_on_lock
def get_wallet(user_id: int, currency: str = "NGN") -> Optional[Dict]:
    currency = (currency or "NGN").upper()
    return ensure_wallet(user_id, currency)


@retry_on_lock
def get_wallets(user_id: int) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    wallets = c.execute(
        "SELECT * FROM wallets WHERE user_id = ? ORDER BY currency", (user_id,)
    ).fetchall()
    return [dict(w) for w in wallets]


@retry_on_lock
def get_wallet_transaction_by_reference(reference: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    tx = c.execute(
        "SELECT * FROM wallet_transactions WHERE reference = ?", (reference,)
    ).fetchone()
    return dict(tx) if tx else None


@retry_on_lock
def credit_wallet(
    user_id: int,
    amount: float,
    description: str = None,
    reference: str = None,
    metadata: Dict = None,
    currency: str = "NGN",
) -> Dict:
    currency = (currency or "NGN").upper()
    amount = round(float(amount), 2)

    if amount <= 0:
        return {"success": False, "error": "Invalid amount"}

    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Generate unique reference if not provided
        if not reference:
            reference = f"wallet_credit_{datetime.now().timestamp()}_{uuid.uuid4().hex[:8]}"
        else:
            # Make reference unique by adding timestamp and random suffix
            reference = f"{reference}_{datetime.now().timestamp()}_{uuid.uuid4().hex[:4]}"

        # Check if reference already exists
        existing = c.execute(
            "SELECT id FROM wallet_transactions WHERE reference = ?",
            (reference,),
        ).fetchone()

        if existing:
            # If reference exists, generate a completely new one
            reference = f"wallet_credit_{datetime.now().timestamp()}_{uuid.uuid4().hex[:8]}"

        wallet = c.execute(
            "SELECT * FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        ).fetchone()

        if not wallet:
            c.execute(
                """
                INSERT INTO wallets (user_id, currency, balance, available_balance, reserved_balance)
                VALUES (?, ?, 0, 0, 0)
            """,
                (user_id, currency),
            )
            wallet = c.execute(
                "SELECT * FROM wallets WHERE user_id = ? AND currency = ?",
                (user_id, currency),
            ).fetchone()

        before = float(wallet["balance"] or 0)
        after = round(before + amount, 2)

        c.execute(
            """
            UPDATE wallets 
            SET balance = ?, available_balance = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ? AND currency = ?
        """,
            (after, after - float(wallet["reserved_balance"] or 0), user_id, currency),
        )

        c.execute(
            """
            INSERT INTO wallet_transactions 
            (user_id, amount, currency, type, description, reference, balance_before, balance_after, metadata)
            VALUES (?, ?, ?, 'credit', ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                amount,
                currency,
                description or "Wallet funding",
                reference,
                before,
                after,
                json.dumps(metadata or {}),
            ),
        )

        tx_id = c.lastrowid
        conn.commit()

        return {
            "success": True,
            "transaction_id": tx_id,
            "new_balance": after,
            "currency": currency,
            "amount": amount,
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Credit wallet error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def update_referral_bonus_config(
    bonus_percentage: float,
    min_bonus: float = 50.0,
    max_bonus: float = 5000.0,
    enabled: bool = True,  # ← Add enabled parameter
    updated_by: int = None,
) -> bool:
    """Update referral bonus configuration."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            INSERT INTO referral_bonus_config 
            (bonus_percentage, min_bonus, max_bonus, enabled, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
            (
                bonus_percentage,
                min_bonus,
                max_bonus,
                1 if enabled else 0,  # ← Store as 1 or 0
                updated_by,
            ),
        )

        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to update referral bonus config: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def debit_wallet(
    user_id: int,
    amount: float,
    description: str = None,
    reference: str = None,
    metadata: Dict = None,
    currency: str = "NGN",
) -> Dict:
    currency = (currency or "NGN").upper()
    amount = round(float(amount), 2)
    if amount <= 0:
        return {"success": False, "error": "Invalid amount"}

    conn = get_db_connection()
    c = conn.cursor()

    try:
        if reference:
            existing = c.execute(
                "SELECT id FROM wallet_transactions WHERE reference=? AND type='debit'",
                (reference,),
            ).fetchone()
            if existing:
                wallet = c.execute(
                    "SELECT balance FROM wallets WHERE user_id=? AND currency=?",
                    (user_id, currency),
                ).fetchone()
                return {
                    "success": True,
                    "already_debited": True,
                    "transaction_id": existing["id"],
                    "new_balance": float(wallet["balance"]) if wallet else 0,
                    "currency": currency,
                    "amount": amount,
                }

        wallet = c.execute(
            "SELECT * FROM wallets WHERE user_id=? AND currency=?", (user_id, currency)
        ).fetchone()
        if not wallet:
            return {"success": False, "error": f"{currency} wallet not found"}

        available = float(
            wallet["available_balance"]
            if wallet["available_balance"] is not None
            else wallet["balance"]
        )
        if available < amount:
            return {"success": False, "error": f"Insufficient {currency} balance"}

        before = float(wallet["balance"] or 0)
        after = round(before - amount, 2)
        reserved = float(wallet["reserved_balance"] or 0)

        c.execute(
            "UPDATE wallets SET balance=?, available_balance=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=? AND currency=?",
            (after, after - reserved, user_id, currency),
        )

        ref = reference or f"wallet_debit_{datetime.now().timestamp()}"
        c.execute(
            """INSERT INTO wallet_transactions
            (user_id,amount,currency,type,description,reference,balance_before,balance_after,metadata)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                user_id,
                amount,
                currency,
                "debit",
                description or "Wallet debit",
                ref,
                before,
                after,
                json.dumps(metadata or {}),
            ),
        )

        tx_id = c.lastrowid
        conn.commit()

        return {
            "success": True,
            "already_debited": False,
            "transaction_id": tx_id,
            "new_balance": after,
            "currency": currency,
            "amount": amount,
        }
    except Exception as e:
        conn.rollback()
        return {"success": False, "error": str(e)}


# ============ NOTIFICATION FUNCTIONS ============


@retry_on_lock
def create_notification(
    user_id: int, title: str, message: str, type: str = "info"
) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO notifications (user_id, title, message, type)
        VALUES (?, ?, ?, ?)
    """,
        (user_id, title, message, type),
    )
    conn.commit()
    return True


@retry_on_lock
def get_notifications(
    user_id: int, limit: int = 20, unread_only: bool = False
) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()

    query = "SELECT * FROM notifications WHERE user_id = ?"
    params = [user_id]

    if unread_only:
        query += " AND read = 0"

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    notifications = c.execute(query, params).fetchall()
    return [dict(n) for n in notifications]


@retry_on_lock
def get_unread_count(user_id: int) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    count = c.execute(
        "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read = 0", (user_id,)
    ).fetchone()[0]
    return count


@retry_on_lock
def mark_notification_read(notification_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET read = 1 WHERE id = ?", (notification_id,))
    conn.commit()
    return True


@retry_on_lock
def mark_all_notifications_read(user_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET read = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    return True


# ============ ADD TO database.py - Enhancement to promotions table ============


# Add new columns to promotions table for percentage-based discounts
def migrate_promotions_table():
    """Add percentage-based discount columns to promotions table."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check and add new columns
    columns = {row[1] for row in c.execute("PRAGMA table_info(promotions)").fetchall()}

    new_columns = [
        ("discount_type", "TEXT", "'fixed'"),  # 'fixed' or 'percentage'
        ("discount_value", "REAL", "0"),  # amount or percentage
        ("max_discount", "REAL", "NULL"),  # max discount for percentage
        ("min_purchase", "REAL", "0"),  # minimum purchase to qualify
        (
            "service_types",
            "TEXT",
            "NULL",
        ),  # comma-separated: airtime,utility,scheduler,topup,wallet_funding
        ("user_segment", "TEXT", "NULL"),  # 'all', 'new', 'returning', 'premium'
        ("usage_limit_per_user", "INTEGER", "NULL"),  # max uses per user
        ("usage_count_per_user", "TEXT", "NULL"),  # JSON: {"user_id": count}
        ("coupon_code", "TEXT", "NULL"),  # optional coupon code
        ("is_referral", "BOOLEAN", "0"),  # is this a referral promo
        ("referral_bonus_type", "TEXT", "'fixed'"),  # 'fixed' or 'percentage'
        ("referral_bonus_value", "REAL", "0"),  # bonus for referrer
        ("referred_bonus_type", "TEXT", "'fixed'"),  # bonus for referred user
        ("referred_bonus_value", "REAL", "0"),  # bonus for referred user
    ]

    for col_name, col_type, default in new_columns:
        if col_name not in columns:
            try:
                c.execute(
                    f"ALTER TABLE promotions ADD COLUMN {col_name} {col_type} DEFAULT {default}"
                )
                logger.info(f"Added column {col_name} to promotions")
            except Exception as e:
                logger.warning(f"Could not add column {col_name}: {e}")

    conn.commit()
    conn.close()


# ============ ENHANCED PROMOTION CALCULATION ============


@retry_on_lock
def calculate_promotion_discount(
    promo: Dict, amount: float, service_type: str = None
) -> Dict:
    """
    Calculate the discount for a given promotion and amount.
    Returns: {discount_amount, discount_type, applied_value, new_total, message}
    """
    if not promo or not promo.get("active"):
        return {
            "discount_amount": 0,
            "applied_value": 0,
            "new_total": amount,
            "message": "No active promotion",
        }

    # Check if service type qualifies
    if promo.get("service_types"):
        service_types = [
            s.strip() for s in str(promo["service_types"]).split(",") if s.strip()
        ]
        if service_type and service_type not in service_types:
            return {
                "discount_amount": 0,
                "applied_value": 0,
                "new_total": amount,
                "message": "Service not eligible",
            }

    # Check min purchase
    min_purchase = float(promo.get("min_purchase") or 0)
    if amount < min_purchase:
        return {
            "discount_amount": 0,
            "applied_value": 0,
            "new_total": amount,
            "message": f"Minimum purchase of {min_purchase} required",
        }

    discount_type = promo.get("discount_type", "fixed")
    discount_value = float(promo.get("discount_value") or 0)
    max_discount = promo.get("max_discount")

    if discount_type == "percentage":
        discount_amount = amount * (discount_value / 100)
        if max_discount is not None:
            discount_amount = min(discount_amount, float(max_discount))
        discount_amount = round(discount_amount, 2)
    else:  # fixed
        discount_amount = min(discount_value, amount)

    new_total = round(amount - discount_amount, 2)

    return {
        "discount_amount": discount_amount,
        "applied_value": discount_value,
        "new_total": new_total,
        "discount_type": discount_type,
        "message": f'{discount_type} discount of {discount_value}{"%" if discount_type == "percentage" else ""} applied',
        "promo_id": promo.get("id"),
        "promo_name": promo.get("name"),
    }

@retry_on_lock
def migrate_contacts_usage_tracking():
    """Add last_used_at / use_count / phone_normalized columns for recency."""
    import re as _re
    conn = get_db_connection()
    c = conn.cursor()
    try:
        columns = {row[1] for row in c.execute("PRAGMA table_info(contacts)").fetchall()}

        if "last_used_at" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN last_used_at TIMESTAMP")
            logger.info("Added last_used_at to contacts")

        if "use_count" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN use_count INTEGER DEFAULT 0")
            logger.info("Added use_count to contacts")

        if "phone_normalized" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN phone_normalized TEXT")
            logger.info("Added phone_normalized to contacts")

        # Backfill phone_normalized for existing rows
        for row in c.execute(
            "SELECT id, phone FROM contacts WHERE phone IS NOT NULL AND (phone_normalized IS NULL OR phone_normalized = '')"
        ).fetchall():
            norm = _re.sub(r"[^\d+]", "", row["phone"] or "")
            if norm:
                c.execute(
                    "UPDATE contacts SET phone_normalized = ? WHERE id = ?",
                    (norm, row["id"]),
                )

        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_last_used ON contacts(user_id, last_used_at DESC)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_phone_normalized ON contacts(phone_normalized)"
        )

        conn.commit()
        logger.info("Contacts usage tracking migration complete")
        return {"success": True}
    except Exception as e:
        conn.rollback()
        logger.error(f"Contacts usage migration failed: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()

@retry_on_lock
def track_promotion_usage(promo_id: int, user_id: int) -> bool:
    """Track usage of a promotion per user."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        promo = c.execute(
            "SELECT usage_count_per_user, usage_limit_per_user FROM promotions WHERE id = ?",
            (promo_id,),
        ).fetchone()
        if not promo:
            return False

        usage_limit = promo.get("usage_limit_per_user")
        if usage_limit is None:
            return True

        usage_data = {}
        if promo.get("usage_count_per_user"):
            try:
                usage_data = json.loads(promo["usage_count_per_user"])
            except:
                pass

        current_usage = usage_data.get(str(user_id), 0)
        if current_usage >= usage_limit:
            return False

        usage_data[str(user_id)] = current_usage + 1
        c.execute(
            "UPDATE promotions SET usage_count_per_user = ? WHERE id = ?",
            (json.dumps(usage_data), promo_id),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to track promotion usage: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def apply_referral_promo(user_id: int, promo_context: Dict = None) -> Dict:
    """
    Resolve what referral bonus should be paid out for this user's completed referral.
    Both referrer and referred user get bonuses (the "referred" side is 0 unless a
    promotions-table referral campaign explicitly sets one — see below).

    Checks in this order:
      0. `referral_bonus_config.enabled` — AUTHORITATIVE KILL-SWITCH. If an admin has
         toggled referral bonuses OFF in Admin > Bonus/Commission, no bonus is paid
         out, period — even if a promotions-table referral campaign is also active.
         This check runs first and short-circuits everything below it.
      1. `promotions` table, active row with is_referral=1 — supports a full two-sided
         campaign (referrer bonus + referred/welcome bonus), set up via the promotions
         admin UI.
      2. `referral_bonus_config` — the simpler single-sided "referrer commission %"
         config set via Admin > Referral Bonus. This table self-populates a sensible
         default (10%, enabled) on a fresh database, so this fallback is what actually
         pays out referral bonuses on a normal install where nobody has manually
         created a promotions-table referral campaign. Previously this function only
         checked (1), so on any fresh deploy referral bonuses silently never paid out
         — admins editing "Referral Bonus %" had zero effect on real payouts because
         the crediting logic never looked at the table that screen edits.
    """
    # -----------------------------------------------------------------
    # 0. AUTHORITATIVE KILL-SWITCH
    #
    # This MUST run before the promotions-table lookup below. Previously
    # the `enabled` flag was only checked in the fallback path (source 2),
    # which meant that if any active promotion with is_referral=1 existed,
    # toggling bonuses OFF in the admin panel had zero effect — bonuses
    # kept paying out. Checking here makes the admin toggle truthful in
    # every configuration.
    # -----------------------------------------------------------------
    config = get_referral_bonus_config()
    if not config.get("enabled", True):
        return {"success": False, "error": "Referral bonuses are currently disabled"}

    conn = get_db_connection()
    c = conn.cursor()

    # 1. Full two-sided campaign via the promotions table, if one is active
    query = """
        SELECT * FROM promotions 
        WHERE active = 1 AND is_referral = 1
        AND (start_date IS NULL OR start_date <= datetime('now'))
        AND (end_date IS NULL OR end_date >= datetime('now'))
        ORDER BY priority DESC, created_at DESC
        LIMIT 1
    """
    promo = c.execute(query).fetchone()
    conn.close()

    if promo:
        promo = dict(promo)
        referrer_bonus_type = promo.get("referral_bonus_type", "fixed")
        referrer_bonus_value = float(promo.get("referral_bonus_value") or 0)
        referred_bonus_type = promo.get("referred_bonus_type", "fixed")
        referred_bonus_value = float(promo.get("referred_bonus_value") or 0)

        return {
            "success": True,
            "source": "promotions",
            "promo_id": promo["id"],
            "promo_name": promo["name"],
            "referrer": {
                "bonus_type": referrer_bonus_type,
                "bonus_value": referrer_bonus_value,
                "description": f'Referral bonus: {referrer_bonus_value}{"%" if referrer_bonus_type == "percentage" else " NGN"}',
            },
            "referred": {
                "bonus_type": referred_bonus_type,
                "bonus_value": referred_bonus_value,
                "description": f'Welcome bonus: {referred_bonus_value}{"%" if referred_bonus_type == "percentage" else " NGN"}',
            },
        }

    # 2. Fall back to the admin-configured referral commission.
    #    (The `enabled` check that used to live here has been moved to the top
    #    so it also guards the promotions-table path above. The `config`
    #    variable is already populated — no need to re-fetch.)
    bonus_percentage = float(config.get("bonus_percentage") or 0)
    commission_mode = (config.get("commission_mode") or "flat").lower()
    referrer_bonus_type = "percentage" if commission_mode == "percentage" else "fixed"
    referrer_bonus_value = bonus_percentage

    if referrer_bonus_value <= 0:
        return {"success": False, "error": "No referral bonus configured"}

    return {
        "success": True,
        "source": "referral_bonus_config",
        "promo_id": None,
        "promo_name": "Referral Program",
        "referrer": {
            "bonus_type": referrer_bonus_type,
            "bonus_value": referrer_bonus_value,
            # min_bonus/max_bonus from referral_bonus_config aren't applied here since
            # this function doesn't have the transaction amount to clamp against —
            # the caller computes the actual NGN amount from bonus_type/bonus_value.
            "description": f'Referral bonus: {referrer_bonus_value}{"%" if referrer_bonus_type == "percentage" else " NGN"}',
        },
        "referred": {
            # referral_bonus_config has no concept of a referred-side welcome bonus.
            "bonus_type": "fixed",
            "bonus_value": 0,
            "description": "No welcome bonus configured",
        },
    }

# ============ REWARDS FUNCTIONS ============
@retry_on_lock
def get_referral_bonus_config() -> Dict:
    """Get current referral bonus configuration."""
    conn = get_db_connection()
    c = conn.cursor()

    config = c.execute("""
        SELECT bonus_percentage, min_bonus, max_bonus, updated_at
        FROM referral_bonus_config
        ORDER BY id DESC LIMIT 1
    """).fetchone()

    conn.close()

    if config:
        return dict(config)
    return {"bonus_percentage": 10.0, "min_bonus": 50.0, "max_bonus": 5000.0}


@retry_on_lock
def update_referral_bonus_config(
    bonus_percentage: float,
    min_bonus: float = 50.0,
    max_bonus: float = 5000.0,
    updated_by: int = None,
) -> bool:
    """Update referral bonus configuration."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            INSERT INTO referral_bonus_config 
            (bonus_percentage, min_bonus, max_bonus, updated_by, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
            (bonus_percentage, min_bonus, max_bonus, updated_by),
        )

        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to update referral bonus config: {e}")
        return False
    finally:
        conn.close()


@retry_on_lock
def get_rewards(user_id: int) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    rewards = c.execute(
        "SELECT * FROM rewards WHERE user_id = ?", (user_id,)
    ).fetchone()
    return dict(rewards) if rewards else None


@retry_on_lock
def add_reward_points(user_id: int, points: int, description: str = None) -> bool:
    conn = get_db_connection()
    c = conn.cursor()

    rewards = c.execute(
        "SELECT points FROM rewards WHERE user_id = ?", (user_id,)
    ).fetchone()
    if not rewards:
        return False

    new_points = rewards["points"] + points

    c.execute(
        """
        UPDATE rewards 
        SET points = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE user_id = ?
    """,
        (new_points, user_id),
    )

    c.execute(
        """
        INSERT INTO rewards_history (user_id, points_change, description)
        VALUES (?, ?, ?)
    """,
        (user_id, points, description or "Added reward points"),
    )

    conn.commit()
    return True


@retry_on_lock
def add_reward_cashback(user_id, amount, currency, reward_type, description, reference):
    amount = round(float(amount), 2)
    currency = (currency or "NGN").upper()
    if amount <= 0 or not reference:
        return {"success": False, "error": "Invalid cashback parameters"}

    conn = get_db_connection()
    c = conn.cursor()
    try:
        if c.execute(
            "SELECT id FROM reward_ledger WHERE reference=?", (reference,)
        ).fetchone():
            return {"success": True, "already_awarded": True}

        c.execute(
            "INSERT INTO reward_ledger (user_id,amount,currency,reward_type,description,reference) VALUES (?,?,?,?,?,?)",
            (user_id, amount, currency, reward_type, description, reference),
        )

        rewards = c.execute(
            "SELECT cashback_value,cashback_currency FROM rewards WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if rewards and (rewards["cashback_currency"] or currency) == currency:
            c.execute(
                "UPDATE rewards SET cashback_value=?,cashback_currency=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?",
                (
                    round(float(rewards["cashback_value"] or 0) + amount, 2),
                    currency,
                    user_id,
                ),
            )

        conn.commit()
        return {"success": True, "amount": amount, "currency": currency}
    except Exception as ex:
        conn.rollback()
        return {"success": False, "error": str(ex)}


@retry_on_lock
def get_cashback_totals(user_id: int) -> Dict:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT currency,ROUND(SUM(amount),2) AS total FROM reward_ledger WHERE user_id=? GROUP BY currency",
        (user_id,),
    ).fetchall()
    return {r["currency"]: float(r["total"] or 0) for r in rows}


@retry_on_lock
def get_rewards_history(user_id: int, limit: int = 20) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    history = c.execute(
        """
        SELECT * FROM rewards_history 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    """,
        (user_id, limit),
    ).fetchall()
    return [dict(h) for h in history]


@retry_on_lock
def convert_rewards_to_cash(user_id: int, points: int) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    rewards = c.execute(
        "SELECT points FROM rewards WHERE user_id = ?", (user_id,)
    ).fetchone()
    if not rewards or rewards["points"] < points:
        return {"success": False, "error": "Insufficient points"}

    cash_amount = points / 100

    new_points = rewards["points"] - points
    c.execute(
        """
        UPDATE rewards 
        SET points = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE user_id = ?
    """,
        (new_points, user_id),
    )

    c.execute(
        """
        INSERT INTO rewards_history (user_id, points_change, description)
        VALUES (?, ?, ?)
    """,
        (user_id, -points, f"Converted {points} points to cash"),
    )

    credit_result = credit_wallet(
        user_id, cash_amount, f"Reward points conversion: {points} points"
    )

    conn.commit()

    if credit_result.get("success"):
        return {"success": True, "cash_amount": cash_amount, "new_points": new_points}
    else:
        return {"success": False, "error": "Failed to credit wallet"}


@retry_on_lock
def get_all_referrals_admin(limit=20, offset=0, status=None, tier=None, date=None):
    """Get all referrals for admin with filters."""
    conn = get_db_connection()
    c = conn.cursor()

    query = """
        SELECT 
            r.id,
            r.referrer_id,
            r.referred_id,
            r.status,
            r.created_at,
            r.completed_at,
            r.referral_expiry,
            r.reward_amount,
            r.reward_currency,
            r.bonus_percentage,
            u1.full_name as referrer_name,
            u2.full_name as referred_name,
            u2.email as referred_email,
            rr.transaction_amount,
            rr.transaction_reference,
            rr.reward_type
        FROM referrals r
        LEFT JOIN users u1 ON u1.id = r.referrer_id
        LEFT JOIN users u2 ON u2.id = r.referred_id
        LEFT JOIN referral_rewards rr ON rr.referral_id = r.id
        WHERE 1=1
    """
    params = []

    if status:
        query += " AND r.status = ?"
        params.append(status)

    if date:
        query += " AND DATE(r.created_at) = ?"
        params.append(date)

    # Get total count
    count_query = query.replace(
        "SELECT r.id, r.referrer_id, r.referred_id, r.status, r.created_at, r.completed_at, r.referral_expiry, r.reward_amount, r.reward_currency, r.bonus_percentage, u1.full_name as referrer_name, u2.full_name as referred_name, u2.email as referred_email, rr.transaction_amount, rr.transaction_reference, rr.reward_type",
        "SELECT COUNT(DISTINCT r.id)",
    )
    total = c.execute(count_query, params).fetchone()[0] or 0

    # Get completed and pending counts
    completed = (
        c.execute(
            "SELECT COUNT(*) FROM referrals WHERE status = 'completed'"
        ).fetchone()[0]
        or 0
    )
    pending = (
        c.execute("SELECT COUNT(*) FROM referrals WHERE status = 'pending'").fetchone()[
            0
        ]
        or 0
    )
    expired = (
        c.execute("SELECT COUNT(*) FROM referrals WHERE status = 'expired'").fetchone()[
            0
        ]
        or 0
    )

    # Get total bonus paid
    total_bonus = (
        c.execute(
            "SELECT COALESCE(SUM(reward_amount), 0) FROM referrals WHERE status = 'completed'"
        ).fetchone()[0]
        or 0
    )

    query += " ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = c.execute(query, params).fetchall()
    conn.close()

    return {
        "success": True,
        "total": total,
        "completed": completed,
        "pending": pending,
        "expired": expired,
        "total_bonus": total_bonus,
        "referrals": [dict(row) for row in rows],
    }


# ============================================================
# REFERRAL BONUS CONFIGURATION
# ============================================================


@retry_on_lock
def get_referral_bonus_config() -> Dict:
    """Get current referral bonus configuration."""
    conn = get_db_connection()
    c = conn.cursor()

    # Create table if it doesn't exist (with enabled column)
    c.execute("""
        CREATE TABLE IF NOT EXISTS referral_bonus_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bonus_percentage REAL DEFAULT 10.0,
            min_bonus REAL DEFAULT 50.0,
            max_bonus REAL DEFAULT 5000.0,
            enabled BOOLEAN DEFAULT 1,  -- ← Add this column
            tier TEXT DEFAULT 'all',
            commission_mode TEXT DEFAULT 'flat',
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    """)

    # Check for columns added after the table was first created (older databases —
    # including ones created by init_db()'s own simpler CREATE TABLE — may be missing
    # any of these; previously only 'enabled' was checked here, so 'tier' and
    # 'commission_mode' stayed permanently missing and crashed the SELECT below with
    # "no such column: tier" on any database that predated those columns).
    columns = {row[1] for row in c.execute("PRAGMA table_info(referral_bonus_config)").fetchall()}
    for col, col_type, default in [
        ("enabled", "BOOLEAN", "1"),
        ("tier", "TEXT", "'all'"),
        ("commission_mode", "TEXT", "'flat'"),
    ]:
        if col not in columns:
            c.execute(f"ALTER TABLE referral_bonus_config ADD COLUMN {col} {col_type} DEFAULT {default}")
            conn.commit()

    # Insert default config if empty
    c.execute("SELECT COUNT(*) FROM referral_bonus_config")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO referral_bonus_config (bonus_percentage, min_bonus, max_bonus, enabled, tier, commission_mode)
            VALUES (10.0, 50.0, 5000.0, 1, 'all', 'flat')
        """)
        conn.commit()

    config = c.execute("""
        SELECT bonus_percentage, min_bonus, max_bonus, enabled, tier, commission_mode, updated_at
        FROM referral_bonus_config
        ORDER BY id DESC LIMIT 1
    """).fetchone()

    conn.close()

    if config:
        return dict(config)
    return {
        "bonus_percentage": 10.0,
        "min_bonus": 50.0,
        "max_bonus": 5000.0,
        "enabled": True,  # ← Default to enabled
        "tier": "all",
        "commission_mode": "flat",
    }


@retry_on_lock
def update_referral_bonus_config(
    bonus_percentage: float,
    min_bonus: float = 50.0,
    max_bonus: float = 5000.0,
    enabled: bool = True,
    tier: str = "all",
    commission_mode: str = "flat",
    updated_by: int = None,
) -> bool:
    """Update referral bonus configuration."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            INSERT INTO referral_bonus_config 
            (bonus_percentage, min_bonus, max_bonus, enabled, tier, commission_mode, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
            (
                bonus_percentage,
                min_bonus,
                max_bonus,
                1 if enabled else 0,
                tier,
                commission_mode,
                updated_by,
            ),
        )

        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to update referral bonus config: {e}")
        return False
    finally:
        conn.close()


# ============================================================
# ADMIN: GET ALL REFERRALS
# ============================================================


@retry_on_lock
def get_all_referrals_admin(limit=20, offset=0, status=None, tier=None, date=None):
    """Get all referrals for admin with filters."""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Check if referrals table has required columns
        columns = {
            row[1] for row in c.execute("PRAGMA table_info(referrals)").fetchall()
        }

        if "bonus_percentage" not in columns:
            try:
                c.execute(
                    "ALTER TABLE referrals ADD COLUMN bonus_percentage REAL DEFAULT 10"
                )
                conn.commit()
            except Exception:
                pass

        if "reward_amount" not in columns:
            try:
                c.execute(
                    "ALTER TABLE referrals ADD COLUMN reward_amount REAL DEFAULT 0"
                )
                conn.commit()
            except Exception:
                pass

        if "reward_currency" not in columns:
            try:
                c.execute(
                    "ALTER TABLE referrals ADD COLUMN reward_currency TEXT DEFAULT 'NGN'"
                )
                conn.commit()
            except Exception:
                pass

        if "referral_expiry" not in columns:
            try:
                c.execute("ALTER TABLE referrals ADD COLUMN referral_expiry TIMESTAMP")
                conn.commit()
            except Exception:
                pass

        query = """
            SELECT 
                r.id,
                r.referrer_id,
                r.referred_id,
                r.status,
                r.created_at,
                r.completed_at,
                r.referral_expiry,
                r.reward_amount,
                r.reward_currency,
                r.bonus_percentage,
                u1.full_name as referrer_name,
                u2.full_name as referred_name,
                u2.email as referred_email,
                rr.transaction_amount,
                rr.transaction_reference,
                rr.reward_type
            FROM referrals r
            LEFT JOIN users u1 ON u1.id = r.referrer_id
            LEFT JOIN users u2 ON u2.id = r.referred_id
            LEFT JOIN referral_rewards rr ON rr.referral_id = r.id
            WHERE 1=1
        """
        params = []

        if status:
            query += " AND r.status = ?"
            params.append(status)

        if date:
            query += " AND DATE(r.created_at) = ?"
            params.append(date)

        # Get counts
        total = (
            c.execute(
                query.replace(
                    "SELECT r.id, r.referrer_id, r.referred_id, r.status, r.created_at, r.completed_at, r.referral_expiry, r.reward_amount, r.reward_currency, r.bonus_percentage, u1.full_name as referrer_name, u2.full_name as referred_name, u2.email as referred_email, rr.transaction_amount, rr.transaction_reference, rr.reward_type",
                    "SELECT COUNT(DISTINCT r.id)",
                ),
                params,
            ).fetchone()[0]
            or 0
        )

        completed = (
            c.execute(
                "SELECT COUNT(*) FROM referrals WHERE status = 'completed'"
            ).fetchone()[0]
            or 0
        )

        pending = (
            c.execute(
                "SELECT COUNT(*) FROM referrals WHERE status = 'pending'"
            ).fetchone()[0]
            or 0
        )

        expired = (
            c.execute(
                "SELECT COUNT(*) FROM referrals WHERE status = 'expired' OR (status = 'pending' AND referral_expiry < datetime('now'))"
            ).fetchone()[0]
            or 0
        )

        total_bonus = (
            c.execute(
                "SELECT COALESCE(SUM(reward_amount), 0) FROM referrals WHERE status = 'completed'"
            ).fetchone()[0]
            or 0
        )

        query += " ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = c.execute(query, params).fetchall()

        result = []
        for row in rows:
            result.append(dict(row))

        return {
            "success": True,
            "total": total,
            "completed": completed,
            "pending": pending,
            "expired": expired,
            "total_bonus": total_bonus,
            "referrals": result,
        }

    except Exception as e:
        logger.error(f"Error getting referrals: {e}")
        return {"success": False, "error": str(e), "referrals": []}
    finally:
        if conn:
            conn.close()


@retry_on_lock
def get_referral_detail_admin(referral_id: int) -> Optional[Dict]:
    """Get detailed referral information for admin."""
    conn = get_db_connection()
    c = conn.cursor()

    row = c.execute(
        """
        SELECT 
            r.*,
            u1.full_name as referrer_name,
            u1.email as referrer_email,
            u2.full_name as referred_name,
            u2.email as referred_email,
            rr.transaction_amount,
            rr.transaction_reference,
            rr.reward_type,
            rr.created_at as reward_created_at,
            rr.paid_at
        FROM referrals r
        LEFT JOIN users u1 ON u1.id = r.referrer_id
        LEFT JOIN users u2 ON u2.id = r.referred_id
        LEFT JOIN referral_rewards rr ON rr.referral_id = r.id
        WHERE r.id = ?
    """,
        (referral_id,),
    ).fetchone()

    conn.close()
    return dict(row) if row else None


@retry_on_lock
def complete_referral_admin(referral_id: int) -> bool:
    """Manually complete a referral."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            UPDATE referrals 
            SET status = 'completed', completed_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending'
        """,
            (referral_id,),
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to complete referral {referral_id}: {e}")
        return False
    finally:
        conn.close()


# ============================================================
# ADMIN: BONUS HISTORY
# ============================================================





# ============================================================
# SEASONAL PROMOTION
# ============================================================


@retry_on_lock
def get_seasonal_promo():
    """Get current seasonal promotion."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Create table if it doesn't exist
        c.execute("""
            CREATE TABLE IF NOT EXISTS seasonal_promos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                multiplier REAL DEFAULT 1.5,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        conn.commit()

        # Now query the table
        row = c.execute("""
            SELECT * FROM seasonal_promos 
            WHERE active = 1 
            AND (start_date IS NULL OR start_date <= datetime('now'))
            AND (end_date IS NULL OR end_date >= datetime('now'))
            ORDER BY created_at DESC LIMIT 1
        """).fetchone()

        return dict(row) if row else None

    except Exception as e:
        logger.error(f"Error getting seasonal promo: {e}")
        return None
    finally:
        conn.close()


@retry_on_lock
def save_seasonal_promo(name=None, multiplier=1.5, start_date=None, end_date=None):
    """Save a seasonal promotion."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Create table if it doesn't exist
        c.execute("""
            CREATE TABLE IF NOT EXISTS seasonal_promos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                multiplier REAL DEFAULT 1.5,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        # Deactivate old promos
        c.execute("UPDATE seasonal_promos SET active = 0")

        # Insert new promo
        c.execute(
            """
            INSERT INTO seasonal_promos (name, multiplier, start_date, end_date, active)
            VALUES (?, ?, ?, ?, 1)
        """,
            (name, multiplier, start_date, end_date),
        )

        conn.commit()
        return {
            "success": True,
            "message": f"Seasonal promo '{name}' launched with {multiplier}x multiplier",
        }

    except Exception as e:
        logger.error(f"Failed to save seasonal promo: {e}")
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def cancel_seasonal_promo():
    """Cancel current seasonal promotion."""
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Create table if it doesn't exist
        c.execute("""
            CREATE TABLE IF NOT EXISTS seasonal_promos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                multiplier REAL DEFAULT 1.5,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        c.execute("UPDATE seasonal_promos SET active = 0")
        conn.commit()
        return {"success": True, "message": "Seasonal promo cancelled"}

    except Exception as e:
        logger.error(f"Failed to cancel seasonal promo: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def get_bonus_history_admin(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Return every referral bonus that has actually been credited to a wallet.

    Source of truth: wallet_transactions, filtered by reference prefix
    'REFBONUS-'. Every referral bonus code path ends up here via
    credit_wallet() — wallet funding, referral completion, admin 'Process
    Pending' — whereas the previous referral_rewards-only query missed
    bonuses paid outside _apply_referral_bonus().

    Column names are aliased to match what admin.html's Bonus History
    table already expects (bonus_percentage, transaction_amount,
    referred_name, status), so the frontend doesn't need changes.
    """
    conn = get_db_connection()
    c = conn.cursor()

    rows = c.execute(
        """
        SELECT
            wt.id                AS id,
            wt.reference         AS reference,
            wt.user_id           AS referrer_id,
            u.full_name          AS referrer_name,
            NULL                 AS referred_id,
            NULL                 AS referred_name,
            wt.amount            AS amount,
            wt.currency          AS currency,
            wt.description       AS description,
            wt.metadata          AS metadata,
            wt.created_at        AS created_at,
            wt.balance_before    AS balance_before,
            wt.balance_after     AS balance_after,
            'completed'          AS status
        FROM wallet_transactions wt
        LEFT JOIN users u ON u.id = wt.user_id
        WHERE wt.reference LIKE 'REFBONUS-%'
           OR wt.reference LIKE 'AUTOREFUND-%'
           OR (wt.type = 'credit' AND wt.description LIKE '%Referral bonus%')
        ORDER BY wt.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()

    conn.close()

    result = []
    for row in rows:
        r = dict(row)

        # Extract fields the JS expects from the metadata JSON, which is
        # now populated at credit time in _finalize_transaction.
        meta = {}
        if r.get("metadata"):
            try:
                meta = json.loads(r["metadata"]) if isinstance(r["metadata"], str) else r["metadata"]
            except Exception:
                meta = {}

        r["metadata"] = meta
        r["bonus_percentage"] = meta.get("bonus_percentage")
        r["transaction_amount"] = meta.get("trigger_amount")
        # referred_name stays None unless we join the referred user in,
        # which we can't do here without knowing the referred_id — it's
        # in the metadata though, so pull it from there for display.
        if meta.get("referred_id"):
            try:
                referred = c.execute(
                    "SELECT full_name FROM users WHERE id = ?",
                    (meta["referred_id"],),
                ).fetchone()
                # note: c is already closed here in this version — see
                # below for the corrected version.
            except Exception:
                pass

        result.append(r)

    return result


@retry_on_lock
def get_leaderboard(limit: int = 10) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    leaderboard = c.execute(
        """
        SELECT u.id, u.full_name, r.points, r.level
        FROM rewards r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.points DESC
        LIMIT ?
    """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in leaderboard]


# ============ CONTACT FUNCTIONS ============


@retry_on_lock
def get_contacts(user_id: int, limit: int = None) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()

    # Ensure contacts table exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            network TEXT,
            favorite BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, phone)
        )
    """)

    # Ensure every column we're about to reference exists.
    columns = {row[1] for row in c.execute("PRAGMA table_info(contacts)").fetchall()}
    for col, typ, default in [
        ("email", "TEXT", "NULL"),
        ("country", "TEXT", "NULL"),
        ("updated_at", "TIMESTAMP", "CURRENT_TIMESTAMP"),
        ("last_used_at", "TIMESTAMP", "NULL"),
        ("use_count", "INTEGER", "0"),
        ("phone_normalized", "TEXT", "NULL"),
    ]:
        if col not in columns:
            try:
                c.execute(f"ALTER TABLE contacts ADD COLUMN {col} {typ} DEFAULT {default}")
                logger.info(f"get_contacts: added column {col} to contacts")
            except sqlite3.OperationalError as e:
                logger.warning(f"get_contacts: could not add column {col}: {e}")

    conn.commit()

    query = """
        SELECT * FROM contacts
        WHERE user_id = ?
        ORDER BY
            (last_used_at IS NULL),
            last_used_at DESC,
            updated_at DESC,
            favorite DESC,
            name ASC
    """
    params = [user_id]
    if limit:
        query += " LIMIT ?"
        params.append(limit)

    rows = c.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]
    
@retry_on_lock
def migrate_contacts_usage_tracking():
    """Add last_used_at / use_count / phone_normalized columns for recency."""
    import re as _re
    conn = get_db_connection()
    c = conn.cursor()
    try:
        columns = {row[1] for row in c.execute("PRAGMA table_info(contacts)").fetchall()}

        if "last_used_at" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN last_used_at TIMESTAMP")
        if "use_count" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN use_count INTEGER DEFAULT 0")
        if "phone_normalized" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN phone_normalized TEXT")

        # Backfill phone_normalized for existing rows
        for row in c.execute(
            "SELECT id, phone FROM contacts WHERE phone IS NOT NULL AND (phone_normalized IS NULL OR phone_normalized = '')"
        ).fetchall():
            norm = _re.sub(r"[^\d+]", "", row["phone"] or "")
            if norm:
                c.execute(
                    "UPDATE contacts SET phone_normalized = ? WHERE id = ?",
                    (norm, row["id"]),
                )

        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_last_used ON contacts(user_id, last_used_at DESC)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_phone_normalized ON contacts(phone_normalized)"
        )

        conn.commit()
        logger.info("Contacts usage tracking migration complete")
        return {"success": True}
    except Exception as e:
        conn.rollback()
        logger.error(f"Contacts usage migration failed: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


@retry_on_lock
def upsert_contact_from_transaction(
    user_id: int, phone: str, name: str = None, network: str = None
) -> bool:
    """
    Ensure a contact exists for a phone used in a transaction, and bump usage.
    Safe to call repeatedly — will not create duplicates.
    """
    import re as _re
    if not phone:
        return False

    normalized = _re.sub(r"[^\d+]", "", phone)
    if not normalized or len(normalized) < 7:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    try:
        existing = c.execute(
            """
            SELECT id FROM contacts
            WHERE user_id = ? AND (phone = ? OR phone_normalized = ?)
            LIMIT 1
            """,
            (user_id, phone, normalized),
        ).fetchone()

        if existing:
            c.execute(
                """
                UPDATE contacts
                SET last_used_at = CURRENT_TIMESTAMP,
                    use_count = COALESCE(use_count, 0) + 1,
                    network = COALESCE(NULLIF(?, ''), network),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (network or "", existing["id"]),
            )
        else:
            c.execute(
                """
                INSERT INTO contacts
                    (user_id, name, phone, phone_normalized, network,
                     use_count, last_used_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (user_id, name or "Unknown", phone, normalized, network),
            )

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"upsert_contact_from_transaction failed: {e}")
        return False
    finally:
        conn.close()    
    
@retry_on_lock
def migrate_contacts_usage_tracking():
    """Add last_used_at and use_count columns for recency tracking."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        columns = {row[1] for row in c.execute("PRAGMA table_info(contacts)").fetchall()}

        if "last_used_at" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN last_used_at TIMESTAMP")
            logger.info("Added last_used_at to contacts")

        if "use_count" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN use_count INTEGER DEFAULT 0")
            logger.info("Added use_count to contacts")

        if "phone_normalized" not in columns:
            c.execute("ALTER TABLE contacts ADD COLUMN phone_normalized TEXT")
            logger.info("Added phone_normalized to contacts")

        # Backfill phone_normalized for existing rows
        rows = c.execute(
            "SELECT id, phone FROM contacts WHERE phone IS NOT NULL AND (phone_normalized IS NULL OR phone_normalized = '')"
        ).fetchall()
        for row in rows:
            norm = re.sub(r"[^\d+]", "", row["phone"] or "")
            if norm:
                c.execute(
                    "UPDATE contacts SET phone_normalized = ? WHERE id = ?",
                    (norm, row["id"]),
                )

        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_last_used ON contacts(user_id, last_used_at DESC)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_contacts_phone_normalized ON contacts(phone_normalized)"
        )

        conn.commit()
        logger.info("Contacts usage tracking migration complete")
        return {"success": True}
    except Exception as e:
        conn.rollback()
        logger.error(f"Contacts usage migration failed: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()

    
    
@retry_on_lock
def mark_contact_used(user_id: int, phone: str) -> bool:
    """
    Bump last_used_at and use_count for a contact by normalized phone.
    Called whenever a transaction is successfully sent to a phone number.
    """
    if not phone:
        return False

    normalized = re.sub(r"[^\d+]", "", phone)
    # Match by either raw or normalized phone (contacts may store either)
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            UPDATE contacts
            SET last_used_at = CURRENT_TIMESTAMP,
                use_count = COALESCE(use_count, 0) + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
              AND (
                  phone = ?
                  OR phone_normalized = ?
                  OR phone = ?
              )
            """,
            (user_id, phone, normalized, normalized),
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.error(f"mark_contact_used failed: {e}")
        return False
    finally:
        conn.close()    


@retry_on_lock
def add_contact(user_id: int, name: str, phone: str, network: str = None) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute(
            """
            INSERT INTO contacts (user_id, name, phone, network)
            VALUES (?, ?, ?, ?)
        """,
            (user_id, name, phone, network),
        )
        conn.commit()
        contact_id = c.lastrowid
        return {"success": True, "id": contact_id}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Contact already exists"}




@retry_on_lock
def toggle_favorite_contact(contact_id: int) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    contact = c.execute(
        "SELECT favorite FROM contacts WHERE id = ?", (contact_id,)
    ).fetchone()
    if not contact:
        return {"success": False, "error": "Contact not found"}

    new_value = 0 if contact["favorite"] else 1
    c.execute("UPDATE contacts SET favorite = ? WHERE id = ?", (new_value, contact_id))
    conn.commit()
    return {"success": True, "favorite": bool(new_value)}


@retry_on_lock
def delete_contact(contact_id: int) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    conn.commit()
    return {"success": True}


# ============ SETTINGS FUNCTIONS ============


@retry_on_lock
def get_settings(user_id: int) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    settings = c.execute(
        "SELECT * FROM settings WHERE user_id = ?", (user_id,)
    ).fetchone()
    return dict(settings) if settings else None


@retry_on_lock
def update_settings(user_id: int, **kwargs) -> bool:
    allowed = [
        "notifications_enabled",
        "email_notifications",
        "sms_notifications",
        "theme",
        "language",
        "currency",
        "sms_config",
    ]
    updates = {k: v for k, v in kwargs.items() if k in allowed}

    if not updates:
        return False

    set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
    values = list(updates.values()) + [user_id]

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE settings SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        values,
    )
    conn.commit()
    return True


@retry_on_lock
def get_sms_config() -> Optional[Dict]:
    """Get SMS provider configuration from settings"""
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute("SELECT sms_config FROM settings LIMIT 1").fetchone()
    if row and row["sms_config"]:
        try:
            return json.loads(row["sms_config"])
        except:
            return None
    return None


@retry_on_lock
def save_sms_config(config: Dict) -> bool:
    """Save SMS provider configuration to settings"""
    conn = get_db_connection()
    c = conn.cursor()
    # Try to update existing settings row
    c.execute(
        "UPDATE settings SET sms_config = ? WHERE id = (SELECT id FROM settings LIMIT 1)",
        (json.dumps(config),),
    )
    if c.rowcount == 0:
        # No settings row exists, create one
        c.execute(
            "INSERT INTO settings (user_id, sms_config) VALUES (1, ?)",
            (json.dumps(config),),
        )
    conn.commit()
    return True


# ============ REFERRAL FUNCTIONS ============


@retry_on_lock
def get_referral_stats(user_id: int) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    total = c.execute(
        "SELECT COUNT(*) FROM referrals WHERE referrer_id = ?", (user_id,)
    ).fetchone()[0]
    completed = c.execute(
        "SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND status = 'completed'",
        (user_id,),
    ).fetchone()[0]
    pending = total - completed

    return {"total": total, "completed": completed, "pending": pending}


@retry_on_lock
def get_referrals(user_id: int) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    referrals = c.execute(
        """
        SELECT r.*, u.full_name as referred_name, u.email as referred_email
        FROM referrals r
        JOIN users u ON u.id = r.referred_id
        WHERE r.referrer_id = ?
        ORDER BY r.created_at DESC
    """,
        (user_id,),
    ).fetchall()
    return [dict(r) for r in referrals]


@retry_on_lock
def complete_referral(referral_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE referrals SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
        (referral_id,),
    )
    changed = c.rowcount > 0
    conn.commit()
    return changed


# ============ SUBSCRIPTION FUNCTIONS ============


@retry_on_lock
def get_providers() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    providers = c.execute("SELECT * FROM providers WHERE active = 1").fetchall()
    return [dict(p) for p in providers]


@retry_on_lock
def get_provider_plans(provider_id: int) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    plans = c.execute(
        """
        SELECT * FROM provider_plans 
        WHERE provider_id = ? AND active = 1
        ORDER BY amount ASC
    """,
        (provider_id,),
    ).fetchall()
    return [dict(p) for p in plans]


@retry_on_lock
def get_subscriptions(user_id: int, status: str = None) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()

    query = "SELECT * FROM subscriptions WHERE user_id = ?"
    params = [user_id]

    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC"

    subscriptions = c.execute(query, params).fetchall()
    return [dict(s) for s in subscriptions]


@retry_on_lock
def create_subscription(
    user_id: int,
    provider: str,
    plan: str,
    account_number: str,
    amount: float,
    currency: str = "NGN",
) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()

    next_billing = (datetime.now() + timedelta(days=30)).isoformat()

    try:
        c.execute(
            """
            INSERT INTO subscriptions 
            (user_id, provider, plan, account_number, amount, currency, next_billing_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (user_id, provider, plan, account_number, amount, currency, next_billing),
        )

        conn.commit()
        sub_id = c.lastrowid
        return {"success": True, "id": sub_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


@retry_on_lock
def cancel_subscription(subscription_id: int) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE subscriptions SET status = 'cancelled' WHERE id = ?", (subscription_id,)
    )
    conn.commit()
    return {"success": True}


# ============ WEBHOOK FUNCTIONS ============


@retry_on_lock
def has_processed_webhook(webhook_id: str) -> bool:
    if not webhook_id:
        return False
    conn = get_db_connection()
    c = conn.cursor()
    exists = c.execute(
        "SELECT id FROM webhook_events WHERE webhook_id = ?", (webhook_id,)
    ).fetchone()
    return exists is not None


@retry_on_lock
def record_webhook(webhook_id: str, reference: str = None) -> bool:
    if not webhook_id:
        return False

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO webhook_events (webhook_id, reference)
            VALUES (?, ?)
        """,
            (webhook_id, reference),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return True
    except Exception as e:
        conn.rollback()
        return False


# ============ VISITOR TRACKING FUNCTIONS ============

# In database.py - Replace the visitor tracking functions with these:


@retry_on_lock
def log_visitor(
    user_id: Optional[int],
    visitor_name: Optional[str],
    ip_address: str,
    user_agent: str,
    device_type: str,
    os_name: str,
    browser: str,
    path: str,
    referrer: str,
    session_id: str,
) -> bool:
    """Log a page visit for analytics."""
    conn = get_db_connection()
    c = conn.cursor()

    # Create table if it doesn't exist with ALL columns
    c.execute("""
        CREATE TABLE IF NOT EXISTS visitor_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            visitor_name TEXT,
            ip_address TEXT,
            user_agent TEXT,
            device_type TEXT,
            os_name TEXT,
            browser TEXT,
            path TEXT,
            referrer TEXT,
            session_id TEXT,
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Check for missing columns and add them if needed
    columns = {
        row[1] for row in c.execute("PRAGMA table_info(visitor_logs)").fetchall()
    }
    required_columns = [
        "user_id",
        "visitor_name",
        "ip_address",
        "user_agent",
        "device_type",
        "os_name",
        "browser",
        "path",
        "referrer",
        "session_id",
        "visited_at",
    ]
    for col in required_columns:
        if col not in columns and col != "id":
            col_type = "INTEGER" if col in ["user_id"] else "TEXT"
            if col == "visited_at":
                col_type = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            try:
                c.execute(f"ALTER TABLE visitor_logs ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass

    # Create indexes
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_user_id ON visitor_logs(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_visited_at ON visitor_logs(visited_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_device_type ON visitor_logs(device_type)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_ip_address ON visitor_logs(ip_address)"
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_visitor_logs_path ON visitor_logs(path)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_visitor_logs_session_id ON visitor_logs(session_id)"
    )

    try:
        c.execute(
            """
            INSERT INTO visitor_logs 
            (user_id, visitor_name, ip_address, user_agent, device_type, os_name, browser, path, referrer, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                visitor_name,
                ip_address,
                user_agent,
                device_type,
                os_name,
                browser,
                path,
                referrer,
                session_id,
            ),
        )
        conn.commit()
        logger.info(f"Visitor logged: path={path}, user_id={user_id}, ip={ip_address}")
        return True
    except Exception as e:
        logger.error(f"Failed to log visitor: {e}")
        conn.rollback()
        return False


@retry_on_lock
def get_visitor_logs(
    limit: int = 100,
    offset: int = 0,
    device_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> List[Dict]:
    """Get visitor logs with filters."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check if table exists
    c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='visitor_logs'"
    )
    if not c.fetchone():
        logger.warning("visitor_logs table does not exist")
        return []

    query = "SELECT * FROM visitor_logs WHERE 1=1"
    params = []

    if device_type:
        query += " AND device_type = ?"
        params.append(device_type)

    if start_date:
        query += " AND date(visited_at) >= ?"
        params.append(start_date)

    if end_date:
        query += " AND date(visited_at) <= ?"
        params.append(end_date)

    query += " ORDER BY visited_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        rows = c.execute(query, params).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            # Format dates for display
            if r.get("visited_at"):
                try:
                    dt = datetime.fromisoformat(
                        str(r["visited_at"]).replace("Z", "+00:00")
                    )
                    r["visited_at"] = dt.isoformat()
                except:
                    pass
            result.append(r)
        return result
    except Exception as e:
        logger.error(f"Error getting visitor logs: {e}")
        return []


@retry_on_lock
def get_visitor_stats() -> Dict:
    """Get visitor statistics for admin dashboard."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check if table exists
    c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='visitor_logs'"
    )
    if not c.fetchone():
        logger.warning("visitor_logs table does not exist")
        return {
            "total_visits": 0,
            "unique_ips": 0,
            "registered_visitors": 0,
            "by_device": [],
            "by_day": [],
        }

    try:
        # Total visits
        total = c.execute("SELECT COUNT(*) FROM visitor_logs").fetchone()[0] or 0

        # Unique IPs
        unique_ips = (
            c.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM visitor_logs WHERE ip_address IS NOT NULL AND ip_address != ''"
            ).fetchone()[0]
            or 0
        )

        # Registered visitors (user_id IS NOT NULL)
        registered = (
            c.execute(
                "SELECT COUNT(DISTINCT user_id) FROM visitor_logs WHERE user_id IS NOT NULL"
            ).fetchone()[0]
            or 0
        )

        # By device
        by_device = c.execute("""
            SELECT device_type, COUNT(*) as count 
            FROM visitor_logs 
            WHERE device_type IS NOT NULL AND device_type != ''
            GROUP BY device_type 
            ORDER BY count DESC
        """).fetchall()

        # By day (last 30 days)
        by_day = c.execute("""
            SELECT DATE(visited_at) as day, COUNT(*) as count 
            FROM visitor_logs 
            WHERE visited_at >= DATE('now', '-30 days')
            GROUP BY DATE(visited_at) 
            ORDER BY day DESC
        """).fetchall()

        return {
            "total_visits": total,
            "unique_ips": unique_ips,
            "registered_visitors": registered,
            "by_device": [dict(r) for r in by_device],
            "by_day": [dict(r) for r in by_day],
        }
    except Exception as e:
        logger.error(f"Error getting visitor stats: {e}")
        return {
            "total_visits": 0,
            "unique_ips": 0,
            "registered_visitors": 0,
            "by_device": [],
            "by_day": [],
        }


# ============ SMS CAMPAIGN FUNCTIONS ============


@retry_on_lock
def get_due_sms_campaigns() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    now_utc_iso = datetime.utcnow().isoformat()

    rows = c.execute(
        """
        SELECT * FROM sms_campaigns 
        WHERE status = 'scheduled' 
        AND scheduled_for IS NOT NULL 
        AND scheduled_for <= ?
        ORDER BY scheduled_for ASC
    """,
        (now_utc_iso,),
    ).fetchall()

    return [dict(r) for r in rows]


@retry_on_lock
def claim_sms_campaign_for_dispatch(campaign_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    claimed = c.execute(
        """
        UPDATE sms_campaigns 
        SET status = 'processing', updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'scheduled'
    """,
        (campaign_id,),
    )
    conn.commit()
    return claimed.rowcount > 0


@retry_on_lock
def update_sms_campaign_result(
    campaign_id: int, status: str, sent: int, failed: int, result: Dict
) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE sms_campaigns 
        SET status = ?, sent_count = ?, failed_count = ?, 
            result = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """,
        (status, sent, failed, json.dumps(result), campaign_id),
    )
    conn.commit()
    return True


@retry_on_lock
def create_sms_campaign(
    user_id: int,
    name: str,
    sender_id: str,
    message: str,
    contact_list: str,
    scheduled_for: Optional[str] = None,
    total_recipients: int = 0,
    provider: Optional[str] = None,
    contacts: List = None,
) -> int:
    conn = get_db_connection()
    c = conn.cursor()

    status = "scheduled" if scheduled_for else "draft"
    contacts_json = json.dumps(contacts or [])

    c.execute(
        """
        INSERT INTO sms_campaigns 
        (user_id, name, sender_id, message, contact_list, contacts_json, 
         scheduled_for, total_recipients, provider, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            user_id,
            name,
            sender_id,
            message,
            contact_list,
            contacts_json,
            scheduled_for,
            total_recipients,
            provider,
            status,
        ),
    )

    conn.commit()
    return c.lastrowid


@retry_on_lock
def get_sms_campaigns(user_id: int, limit: int = 50) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT * FROM sms_campaigns 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    """,
        (user_id, limit),
    ).fetchall()

    result = []
    for row in rows:
        r = dict(row)
        if r.get("contacts_json"):
            try:
                r["contacts"] = json.loads(r["contacts_json"])
            except:
                r["contacts"] = []
        if r.get("result"):
            try:
                r["result"] = json.loads(r["result"])
            except:
                pass
        result.append(r)
    return result


# ============ USER MANAGEMENT FUNCTIONS ============


@retry_on_lock
def set_account_status(user_id: int, status: str, reason: str = None) -> bool:
    """Set a user's account status."""
    conn = get_db_connection()
    c = conn.cursor()

    # Validate status
    valid_statuses = ["active", "suspended", "blocked", "deleted"]
    if status not in valid_statuses:
        logger.error(f"Invalid status: {status}")
        return False

    c.execute(
        """
        UPDATE users 
        SET account_status = ?, 
            status_reason = ?, 
            status_changed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """,
        (status, reason, user_id),
    )

    affected = c.rowcount
    conn.commit()
    conn.close()

    logger.info(f"User {user_id} status changed to '{status}' (reason: {reason})")
    return affected > 0


@retry_on_lock
def kill_user_sessions(user_id: int) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    killed = c.rowcount
    conn.commit()
    return killed


@retry_on_lock
def set_password(user_id: int, new_password: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    password_hash = hash_password(new_password)
    c.execute(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (password_hash, user_id),
    )
    conn.commit()
    return c.rowcount > 0


@retry_on_lock
def change_password(user_id: int, current_password: str, new_password: str) -> Dict:
    user = get_user(user_id)
    if not user:
        return {"success": False, "error": "User not found"}

    current_hash = hash_password(current_password)
    if user.get("password_hash") != current_hash:
        return {"success": False, "error": "Current password is incorrect"}

    if set_password(user_id, new_password):
        kill_user_sessions(user_id)
        return {"success": True}
    return {"success": False, "error": "Failed to update password"}


@retry_on_lock
def is_user_verified(user_id: int) -> bool:
    user = get_user(user_id)
    if not user:
        return False
    return user.get("email_verified", False) == 1


# ============ OTP FUNCTIONS ============


@retry_on_lock
def create_verification_otp(
    identifier: str, otp_type: str = "email", ttl_minutes: int = 10
) -> str:
    conn = get_db_connection()
    c = conn.cursor()

    code = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    expires_at = (datetime.now() + timedelta(minutes=ttl_minutes)).isoformat()

    c.execute(
        """
        INSERT INTO otp_codes (identifier, code, type, expires_at)
        VALUES (?, ?, ?, ?)
    """,
        (identifier, code, otp_type, expires_at),
    )
    conn.commit()
    return code


@retry_on_lock
def verify_otp(identifier: str, code: str, otp_type: str = "email") -> bool:
    conn = get_db_connection()
    c = conn.cursor()

    row = c.execute(
        """
        SELECT id FROM otp_codes 
        WHERE identifier = ? AND code = ? AND type = ? 
        AND used = 0 AND expires_at > datetime('now')
        ORDER BY created_at DESC LIMIT 1
    """,
        (identifier, code, otp_type),
    ).fetchone()

    if not row:
        return False

    c.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))

    if otp_type == "email":
        user = get_user_by_email(identifier)
        if user:
            c.execute(
                "UPDATE users SET email_verified = 1, verified_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user["id"],),
            )

    conn.commit()
    return True


# ============ SPONSORED CAMPAIGN FUNCTIONS ============


@retry_on_lock
def get_active_sponsored_campaign_for_tx(
    user_id: int, tx_type: str = None, amount: float = None, tx_reference: str = None
) -> Optional[Dict]:
    """Get an active sponsored campaign that should show on this receipt."""
    conn = get_db_connection()
    c = conn.cursor()

    # Get all active sponsored campaigns
    now = datetime.now().isoformat()
    campaigns = c.execute("""
        SELECT id, title, body, cta_text, cta_url, advertiser_user_id, 
               impressions_purchased, impressions_delivered,
               campaign_tier, target_tx_type, target_min_amount, target_max_amount,
               target_customer_type, target_hour_start, target_hour_end,
               clicks_purchased, clicks_delivered, click_token
        FROM receipt_promos
        WHERE source = 'sponsored' AND status = 'approved'
        AND (campaign_tier != 'performance' OR clicks_delivered < clicks_purchased)
        AND (campaign_tier != 'basic' OR impressions_delivered < impressions_purchased)
        AND (campaign_tier != 'dominant' OR impressions_delivered < impressions_purchased)
        ORDER BY 
            CASE campaign_tier 
                WHEN 'dominant' THEN 1 
                WHEN 'performance' THEN 2 
                WHEN 'basic' THEN 3 
                ELSE 4 
            END ASC,
            impressions_delivered ASC,
            id ASC
    """).fetchall()

    if not campaigns:
        return None

    # Get user's transaction history to determine if they're new or returning
    is_new = False
    try:
        tx_count = c.execute(
            f"SELECT COUNT(*) FROM transactions WHERE user_id = ? AND status IN {_SUCCESS_STATUS_SQL} AND reference != ?",
            (user_id, tx_reference or ""),
        ).fetchone()[0]
        is_new = tx_count == 0
    except:
        pass

    # Get hour of day
    current_hour = datetime.now().hour

    for campaign in campaigns:
        campaign = dict(campaign)

        # Check target tx_type
        if campaign.get("target_tx_type"):
            if campaign["target_tx_type"] != tx_type:
                continue

        # Check target amount range
        if campaign.get("target_min_amount") is not None:
            if not amount or amount < campaign["target_min_amount"]:
                continue
        if campaign.get("target_max_amount") is not None:
            if not amount or amount > campaign["target_max_amount"]:
                continue

        # Check target customer type
        if campaign.get("target_customer_type") == "new" and not is_new:
            continue
        if campaign.get("target_customer_type") == "returning" and is_new:
            continue

        # Check target hour range
        if campaign.get("target_hour_start") is not None:
            if current_hour < campaign["target_hour_start"]:
                continue
        if campaign.get("target_hour_end") is not None:
            if current_hour > campaign["target_hour_end"]:
                continue

        # This campaign matches the targeting criteria
        return campaign

    return None


@retry_on_lock
def track_sponsored_impression(campaign_id: int, tx_reference: str):
    """Track an impression for a sponsored campaign."""
    conn = get_db_connection()
    c = conn.cursor()

    # Log the impression
    c.execute(
        """
        INSERT INTO receipt_ad_clicks (promo_id, transaction_reference, clicked_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    """,
        (campaign_id, tx_reference),
    )

    # Decrement impressions remaining (increment impressions delivered)
    c.execute(
        """
        UPDATE receipt_promos 
        SET impressions_delivered = impressions_delivered + 1
        WHERE id = ? 
    """,
        (campaign_id,),
    )

    # If impressions_delivered >= impressions_purchased, mark as completed
    c.execute(
        """
        UPDATE receipt_promos 
        SET status = 'completed' 
        WHERE id = ? AND campaign_tier != 'performance' 
        AND impressions_delivered >= impressions_purchased
    """,
        (campaign_id,),
    )

    conn.commit()
    return True


@retry_on_lock
def get_campaigns_for_advertiser(user_id: int) -> List[Dict]:
    """Get all campaigns for an advertiser (including old ones)."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT * FROM receipt_promos 
        WHERE source = 'sponsored' AND advertiser_user_id = ?
        ORDER BY created_at DESC
    """,
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


@retry_on_lock
def get_all_sponsored_campaigns(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Get all sponsored campaigns for admin (including old ones)."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT rp.*, u.email as advertiser_email, u.full_name as advertiser_name
        FROM receipt_promos rp 
        LEFT JOIN users u ON u.id = rp.advertiser_user_id
        WHERE rp.source = 'sponsored'
        ORDER BY rp.created_at DESC
        LIMIT ? OFFSET ?
    """,
        (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


# ============ RECEIPT AD CONSTANTS - COMPLETE LIST ============

RECEIPT_AD_BASIC_PRICE = 100000.0
RECEIPT_AD_BASIC_IMPRESSIONS = 100000

RECEIPT_AD_PREMIUM_PRICE_PER_IMPRESSION = 2.5
RECEIPT_AD_PREMIUM_MIN_BUDGET = 250000.0
RECEIPT_AD_PREMIUM_MAX_BUDGET = 500000.0

RECEIPT_AD_DOMINANT_PRICE = 1000000.0
RECEIPT_AD_DOMINANT_IMPRESSIONS = 200000
RECEIPT_AD_DOMINANT_PRICE_PER_IMPRESSION = (
    5.0  # = DOMINANT_PRICE / DOMINANT_IMPRESSIONS
)

RECEIPT_AD_PERFORMANCE_DEFAULT_COST_PER_CLICK = 200.0
RECEIPT_AD_PERFORMANCE_MIN_CLICKS = 100
RECEIPT_AD_PERFORMANCE_MAX_CLICKS = 50000

RECEIPT_AD_MIN_IMPRESSIONS = 100
RECEIPT_AD_MAX_IMPRESSIONS = 1000000

RECEIPT_AD_VALID_TX_TYPES = {"airtime", "data", "utility", "topup", "giftcard"}

# ============ RECEIPT PROMO FUNCTIONS ============

RECEIPT_AD_BASIC_PRICE = 100000.0
RECEIPT_AD_BASIC_IMPRESSIONS = 100000
RECEIPT_AD_PREMIUM_PRICE_PER_IMPRESSION = 2.5
RECEIPT_AD_PREMIUM_MIN_BUDGET = 250000.0
RECEIPT_AD_PREMIUM_MAX_BUDGET = 500000.0
RECEIPT_AD_DOMINANT_PRICE = 1000000.0
RECEIPT_AD_DOMINANT_IMPRESSIONS = 200000
RECEIPT_AD_PERFORMANCE_DEFAULT_COST_PER_CLICK = 200.0
RECEIPT_AD_PERFORMANCE_MIN_CLICKS = 100
RECEIPT_AD_PERFORMANCE_MAX_CLICKS = 50000
RECEIPT_AD_MIN_IMPRESSIONS = 100
RECEIPT_AD_MAX_IMPRESSIONS = 1000000
RECEIPT_AD_VALID_TX_TYPES = {"airtime", "data", "utility", "topup", "giftcard"}


def get_all_receipt_promos() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        "SELECT * FROM receipt_promos WHERE source = 'house' ORDER BY slot_index ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def upsert_receipt_promo(
    promo_id: Optional[int],
    slot_index: int,
    title: str,
    body: str,
    cta_text: str = None,
    cta_url: str = None,
    active: bool = True,
) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()
    if promo_id:
        c.execute(
            """
            UPDATE receipt_promos SET slot_index=?, title=?, body=?, cta_text=?, cta_url=?,
                active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
        """,
            (slot_index, title, body, cta_text, cta_url, 1 if active else 0, promo_id),
        )
    else:
        c.execute(
            """
            INSERT INTO receipt_promos (slot_index, title, body, cta_text, cta_url, active)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (slot_index, title, body, cta_text, cta_url, 1 if active else 0),
        )
        promo_id = c.lastrowid
    conn.commit()
    row = c.execute("SELECT * FROM receipt_promos WHERE id = ?", (promo_id,)).fetchone()
    return dict(row) if row else {}


def delete_receipt_promo(promo_id: int) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM receipt_promos WHERE id = ?", (promo_id,))
    conn.commit()
    return c.rowcount > 0


def dominant_slot_is_occupied() -> bool:
    """Check if the dominant slot is currently occupied by a live or pending campaign."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check if there's an active or pending dominant campaign
    row = c.execute("""
        SELECT COUNT(*) FROM receipt_promos 
        WHERE source = 'sponsored' 
        AND campaign_tier = 'dominant' 
        AND status IN ('approved', 'pending_review', 'live')
    """).fetchone()

    conn.close()
    return row[0] > 0 if row else False


def get_receipt_promo_for_slot(
    receipt_number: int, context: Dict = None
) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    receipt_number = max(receipt_number, 1)
    context = context or {}

    # Check for dominant campaign first
    dominant = c.execute("""
        SELECT * FROM receipt_promos
        WHERE source = 'sponsored' AND status = 'approved' AND campaign_tier = 'dominant'
          AND impressions_delivered < impressions_purchased
        ORDER BY id ASC LIMIT 1
    """).fetchone()
    if dominant:
        promo = dict(dominant)
        c.execute(
            "UPDATE receipt_promos SET impressions_delivered = impressions_delivered + 1 WHERE id = ?",
            (promo["id"],),
        )
        conn.commit()
        return promo

    # Check for other campaigns every 3rd receipt
    if receipt_number % 3 == 0:
        candidates = c.execute("""
            SELECT * FROM receipt_promos
            WHERE source = 'sponsored' AND status = 'approved'
              AND campaign_tier IN ('basic', 'performance')
              AND (
                    (campaign_tier = 'basic' AND impressions_delivered < impressions_purchased)
                 OR (campaign_tier = 'performance' AND clicks_delivered < clicks_purchased)
                  )
            ORDER BY impressions_delivered ASC, id ASC
        """).fetchall()
        for row in candidates:
            promo = dict(row)
            # Check targeting
            if (
                promo.get("target_tx_type")
                and context.get("tx_type") != promo["target_tx_type"]
            ):
                continue
            amount = context.get("amount")
            if promo.get("target_min_amount") is not None and (
                amount is None or amount < promo["target_min_amount"]
            ):
                continue
            if promo.get("target_max_amount") is not None and (
                amount is None or amount > promo["target_max_amount"]
            ):
                continue

            c.execute(
                "UPDATE receipt_promos SET impressions_delivered = impressions_delivered + 1 WHERE id = ?",
                (promo["id"],),
            )
            conn.commit()
            return promo

    # Fall back to house promos
    house = c.execute(
        "SELECT * FROM receipt_promos WHERE source = 'house' AND active = 1 ORDER BY slot_index ASC"
    ).fetchall()
    if not house:
        return None
    idx = (receipt_number - 1) % len(house)
    return dict(house[idx])


# Add these functions to your database.py - place them near the other receipt promo functions

# ============ SPONSORED CAMPAIGN FUNCTIONS ============


@retry_on_lock
def get_active_sponsored_campaign_for_tx(
    user_id: int, tx_type: str = None, amount: float = None, tx_reference: str = None
) -> Optional[Dict]:
    """
    Get an active sponsored campaign that should show on this receipt.
    This is the CRITICAL function that bridges receipt generation with sponsored ads.
    """
    conn = get_db_connection()
    c = conn.cursor()

    # First, check if the receipt_promos table has the required columns
    columns = {
        row[1] for row in c.execute("PRAGMA table_info(receipt_promos)").fetchall()
    }
    required_cols = [
        "source",
        "status",
        "campaign_tier",
        "impressions_purchased",
        "impressions_delivered",
    ]
    missing_cols = [col for col in required_cols if col not in columns]

    if missing_cols:
        logger.warning(
            f"receipt_promos table missing columns: {missing_cols}. Adding them..."
        )
        for col in missing_cols:
            try:
                col_type = (
                    "TEXT"
                    if col in ["source", "status", "campaign_tier"]
                    else "INTEGER DEFAULT 0"
                )
                c.execute(f"ALTER TABLE receipt_promos ADD COLUMN {col} {col_type}")
                conn.commit()
                logger.info(f"Added column {col} to receipt_promos")
            except Exception as e:
                logger.error(f"Failed to add column {col}: {e}")

    # Now get all active sponsored campaigns
    now = datetime.now().isoformat()

    # Get campaigns that are:
    # 1. Sponsored source
    # 2. Approved status
    # 3. Have impressions remaining (or performance tier with clicks remaining)
    campaigns = c.execute("""
        SELECT id, title, body, cta_text, cta_url, advertiser_user_id, 
               impressions_purchased, impressions_delivered,
               campaign_tier, target_tx_type, target_min_amount, target_max_amount,
               target_customer_type, target_hour_start, target_hour_end,
               clicks_purchased, clicks_delivered, click_token,
               price_paid, price_currency
        FROM receipt_promos
        WHERE source = 'sponsored' 
        AND status = 'approved'
        AND (
            (campaign_tier != 'performance' AND impressions_delivered < impressions_purchased)
            OR (campaign_tier = 'performance' AND clicks_delivered < clicks_purchased)
        )
        ORDER BY 
            CASE campaign_tier 
                WHEN 'dominant' THEN 1 
                WHEN 'performance' THEN 2 
                WHEN 'basic' THEN 3 
                ELSE 4 
            END ASC,
            impressions_delivered ASC,
            id ASC
    """).fetchall()

    if not campaigns:
        logger.debug("No active sponsored campaigns found")
        return None

    # Get user's transaction history to determine if they're new or returning
    is_new = False
    try:
        tx_count = c.execute(
            f"SELECT COUNT(*) FROM transactions WHERE user_id = ? AND status IN {_SUCCESS_STATUS_SQL} AND reference != ?",
            (user_id, tx_reference or ""),
        ).fetchone()[0]
        is_new = tx_count == 0
    except Exception as e:
        logger.warning(f"Could not determine if user is new: {e}")

    # Get hour of day
    current_hour = datetime.now().hour

    for campaign in campaigns:
        campaign = dict(campaign)

        # Check target tx_type
        if campaign.get("target_tx_type"):
            if campaign["target_tx_type"] != tx_type:
                logger.debug(
                    f"Campaign {campaign['id']} skipped: target_tx_type mismatch ({campaign['target_tx_type']} != {tx_type})"
                )
                continue

        # Check target amount range
        if campaign.get("target_min_amount") is not None:
            if not amount or amount < campaign["target_min_amount"]:
                logger.debug(
                    f"Campaign {campaign['id']} skipped: amount below min ({amount} < {campaign['target_min_amount']})"
                )
                continue
        if campaign.get("target_max_amount") is not None:
            if not amount or amount > campaign["target_max_amount"]:
                logger.debug(
                    f"Campaign {campaign['id']} skipped: amount above max ({amount} > {campaign['target_max_amount']})"
                )
                continue

        # Check target customer type
        if campaign.get("target_customer_type") == "new" and not is_new:
            logger.debug(
                f"Campaign {campaign['id']} skipped: target is new customer but user is returning"
            )
            continue
        if campaign.get("target_customer_type") == "returning" and is_new:
            logger.debug(
                f"Campaign {campaign['id']} skipped: target is returning customer but user is new"
            )
            continue

        # Check target hour range
        if (
            campaign.get("target_hour_start") is not None
            and campaign.get("target_hour_end") is not None
        ):
            start = campaign["target_hour_start"]
            end = campaign["target_hour_end"]
            if start <= end:
                if not (start <= current_hour <= end):
                    logger.debug(
                        f"Campaign {campaign['id']} skipped: hour {current_hour} not in range {start}-{end}"
                    )
                    continue
            else:
                # Wraps past midnight
                if not (current_hour >= start or current_hour <= end):
                    logger.debug(
                        f"Campaign {campaign['id']} skipped: hour {current_hour} not in wrapped range {start}-{end}"
                    )
                    continue

        # This campaign matches all criteria - return it
        logger.info(
            f"Found matching sponsored campaign: {campaign['id']} - {campaign.get('title')}"
        )
        return campaign

    logger.debug("No matching sponsored campaigns found for this transaction")
    return None


@retry_on_lock
def track_sponsored_impression(campaign_id: int, tx_reference: str):
    """
    Track an impression for a sponsored campaign.
    This is called when a sponsored ad is displayed on a receipt.
    """
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Log the impression in receipt_ad_clicks
        c.execute(
            """
            INSERT INTO receipt_ad_clicks (promo_id, transaction_reference, clicked_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """,
            (campaign_id, tx_reference),
        )

        # Increment impressions_delivered
        c.execute(
            """
            UPDATE receipt_promos 
            SET impressions_delivered = impressions_delivered + 1
            WHERE id = ? 
        """,
            (campaign_id,),
        )

        # If impressions_delivered >= impressions_purchased, mark as completed
        c.execute(
            """
            UPDATE receipt_promos 
            SET status = 'completed' 
            WHERE id = ? 
            AND campaign_tier != 'performance' 
            AND impressions_delivered >= impressions_purchased
            AND impressions_purchased > 0
        """,
            (campaign_id,),
        )

        conn.commit()
        logger.info(
            f"Tracked impression for campaign {campaign_id} on transaction {tx_reference}"
        )
        return True
    except Exception as e:
        logger.error(f"Failed to track sponsored impression: {e}")
        conn.rollback()
        return False


@retry_on_lock
def get_all_sponsored_campaigns(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Get all sponsored campaigns for admin (including old ones)."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT rp.*, u.email as advertiser_email, u.full_name as advertiser_name
        FROM receipt_promos rp 
        LEFT JOIN users u ON u.id = rp.advertiser_user_id
        WHERE rp.source = 'sponsored'
        ORDER BY rp.created_at DESC
        LIMIT ? OFFSET ?
    """,
        (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


@retry_on_lock
def get_campaigns_for_advertiser(user_id: int) -> List[Dict]:
    """Get all campaigns for an advertiser (including old ones)."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT * FROM receipt_promos 
        WHERE source = 'sponsored' AND advertiser_user_id = ?
        ORDER BY created_at DESC
    """,
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


@retry_on_lock
def get_pending_sponsored_campaigns() -> List[Dict]:
    """Get all pending sponsored campaigns for admin review."""
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute("""
        SELECT rp.*, u.email as advertiser_email, u.full_name as advertiser_name
        FROM receipt_promos rp 
        LEFT JOIN users u ON u.id = rp.advertiser_user_id
        WHERE rp.source = 'sponsored' AND rp.status = 'pending_review'
        ORDER BY rp.submitted_at ASC
    """).fetchall()
    return [dict(r) for r in rows]


@retry_on_lock
def moderate_sponsored_campaign(
    campaign_id: int, approve: bool, reviewer: str, reason: str = None
) -> Optional[Dict]:
    """Approve or reject a pending campaign."""
    conn = get_db_connection()
    c = conn.cursor()
    existing = c.execute(
        "SELECT * FROM receipt_promos WHERE id = ? AND source = 'sponsored'",
        (campaign_id,),
    ).fetchone()
    if not existing or existing["status"] != "pending_review":
        return None

    new_status = "approved" if approve else "rejected"
    c.execute(
        """
        UPDATE receipt_promos 
        SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP,
            rejection_reason = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """,
        (new_status, reviewer, reason if not approve else None, campaign_id),
    )
    conn.commit()
    row = c.execute(
        "SELECT * FROM receipt_promos WHERE id = ?", (campaign_id,)
    ).fetchone()
    return dict(row)


@retry_on_lock
def pause_sponsored_campaign(campaign_id: int, advertiser_user_id: int) -> bool:
    """Pause a live campaign."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        UPDATE receipt_promos 
        SET status = 'paused', updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND advertiser_user_id = ? AND source = 'sponsored' AND status = 'approved'
    """,
        (campaign_id, advertiser_user_id),
    )
    conn.commit()
    return c.rowcount > 0


@retry_on_lock
def create_sponsored_campaign(
    advertiser_user_id: int,
    title: str,
    body: str,
    impressions: int = None,
    cta_text: str = None,
    cta_url: str = None,
    currency: str = "NGN",
    campaign_tier: str = "basic",
    budget: float = None,
    clicks: int = None,
    target_tx_type: str = None,
    target_min_amount: float = None,
    target_max_amount: float = None,
    target_customer_type: str = None,
    target_hour_start: int = None,
    target_hour_end: int = None,
) -> Dict:
    """Create a sponsored campaign in pending_review status."""

    # Pricing based on tier
    if campaign_tier == "basic":
        price = RECEIPT_AD_BASIC_PRICE
        impressions_count = RECEIPT_AD_BASIC_IMPRESSIONS
        clicks_purchased = None
    elif campaign_tier == "premium":
        budget = budget or RECEIPT_AD_PREMIUM_MIN_BUDGET
        price = round(budget, 2)
        impressions_count = int(budget / RECEIPT_AD_PREMIUM_PRICE_PER_IMPRESSION)
        clicks_purchased = None
    elif campaign_tier == "dominant":
        price = RECEIPT_AD_DOMINANT_PRICE
        impressions_count = RECEIPT_AD_DOMINANT_IMPRESSIONS
        clicks_purchased = None
    elif campaign_tier == "performance":
        clicks = int(clicks or RECEIPT_AD_PERFORMANCE_MIN_CLICKS)
        clicks = max(
            RECEIPT_AD_PERFORMANCE_MIN_CLICKS,
            min(clicks, RECEIPT_AD_PERFORMANCE_MAX_CLICKS),
        )
        price = round(clicks * RECEIPT_AD_PERFORMANCE_DEFAULT_COST_PER_CLICK, 2)
        impressions_count = None
        clicks_purchased = clicks
    else:
        return {"error": f"Unknown campaign_tier '{campaign_tier}'"}

    click_token = secrets.token_urlsafe(16) if campaign_tier == "performance" else None
    db_tier = "basic" if campaign_tier == "premium" else campaign_tier

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO receipt_promos
            (slot_index, title, body, cta_text, cta_url, active, source, advertiser_user_id,
             status, impressions_purchased, impressions_delivered, price_paid, price_currency, submitted_at,
             campaign_tier, target_tx_type, target_min_amount, target_max_amount,
             target_customer_type, target_hour_start, target_hour_end,
             clicks_purchased, clicks_delivered, click_token)
        VALUES (0, ?, ?, ?, ?, 0, 'sponsored', ?, 'pending_review', ?, 0, ?, ?, CURRENT_TIMESTAMP,
                ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    """,
        (
            title,
            body,
            cta_text,
            cta_url,
            advertiser_user_id,
            impressions_count or 0,
            price,
            currency,
            db_tier,
            target_tx_type,
            target_min_amount,
            target_max_amount,
            target_customer_type,
            target_hour_start,
            target_hour_end,
            clicks_purchased,
            click_token,
        ),
    )
    conn.commit()
    campaign_id = c.lastrowid
    row = c.execute(
        "SELECT * FROM receipt_promos WHERE id = ?", (campaign_id,)
    ).fetchone()
    return dict(row)


# ============ ADMIN FUNCTIONS ============


@retry_on_lock
def get_admin_transactions(
    limit: int = 20,
    offset: int = 0,
    status: str = None,
    tx_type: str = None,
    date: str = None,
) -> tuple:
    conn = get_db_connection()
    c = conn.cursor()

    query = "SELECT * FROM transactions WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM transactions WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        count_query += " AND status = ?"
        params.append(status)

    if tx_type:
        query += " AND tx_type = ?"
        count_query += " AND tx_type = ?"
        params.append(tx_type)

    if date:
        query += " AND DATE(created_at) = ?"
        count_query += " AND DATE(created_at) = ?"
        params.append(date)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    count_params = params.copy()
    params.extend([limit, offset])

    rows = c.execute(query, params).fetchall()
    total = c.execute(count_query, count_params).fetchone()[0] or 0

    transactions = []
    for row in rows:
        tx = dict(row)
        if tx.get("payload"):
            try:
                tx["payload"] = json.loads(tx["payload"])
            except:
                pass
        if tx.get("reloadly_result"):
            try:
                tx["reloadly_result"] = json.loads(tx["reloadly_result"])
            except:
                pass
        transactions.append(tx)

    return transactions, total


# ============ SEED PROVIDERS ============


def seed_providers():
    conn = get_db()
    c = conn.cursor()

    providers = [
        ("MTN Nigeria", "Airtime and data services"),
        ("Glo Nigeria", "Airtime and data services"),
        ("Airtel Nigeria", "Airtime and data services"),
        ("9mobile Nigeria", "Airtime and data services"),
        ("DSTV", "Cable TV services"),
        ("GOtv", "Cable TV services"),
        ("Startimes", "Cable TV services"),
        ("Spectranet", "Internet services"),
        ("Smile", "Internet services"),
    ]

    for name, desc in providers:
        c.execute(
            """
            INSERT OR IGNORE INTO providers (name, description)
            VALUES (?, ?)
        """,
            (name, desc),
        )

    conn.commit()
    conn.close()


# ============ CHECK DATABASE ============


def check_database():
    try:
        conn = get_db()
        c = conn.cursor()

        tables = [
            "users",
            "sessions",
            "transactions",
            "wallets",
            "wallet_transactions",
            "rewards",
            "rewards_history",
            "contacts",
            "notifications",
            "subscriptions",
            "providers",
            "provider_plans",
            "referrals",
            "otp_codes",
            "webhook_events",
            "settings",
            "reloadly_transactions",
            "scheduled_payments",
            "bulk_jobs",
            "visitor_logs",
            "sms_campaigns",
            "receipt_promos",
            "receipt_ad_clicks",
            "scheduler_schedules",
        ]

        missing = []
        for table in tables:
            c.execute(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"
            )
            if not c.fetchone():
                missing.append(table)

        conn.close()

        if missing:
            print(f"Missing tables: {missing}")
            return False
        return True
    except Exception as e:
        print(f"Database check error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("Net365 Database Setup")
    print("=" * 50)
    print(f"Database path: {DATABASE}")

    if os.path.exists(DATABASE):
        size = os.path.getsize(DATABASE)
        print(f"Database size: {size} bytes")
        import shutil

        backup = DATABASE + ".backup." + datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(DATABASE, backup)
        print(f"Backed up to {backup}")

    print("\nInitializing database...")
    init_db()
    seed_providers()

    if check_database():
        print("Database initialized successfully!")
    else:
        print("Database initialization failed!")
