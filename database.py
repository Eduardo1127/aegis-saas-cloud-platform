#!/usr/bin/env python3
"""
AEGIS PRIME SAAS CLOUD PLATFORM - DATABASE MANAGER (SQLite)
Author: Eduardo Mex Rodriguez (EMR)
"""

import sqlite3
import os
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "aegis_saas.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company TEXT,
        role TEXT DEFAULT 'client',
        plan TEXT DEFAULT 'basic',
        hwid_license TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Scans History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT,
        details_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    # Subscriptions / Payments Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        stripe_session_id TEXT,
        amount REAL,
        plan TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    
    # Ensure Admin Master user ALWAYS exists on server boot
    admin_pwd_hash = generate_password_hash("AdminMaster123!")
    cursor.execute("""
    INSERT OR REPLACE INTO users (id, email, password_hash, company, role, plan, hwid_license)
    VALUES (1, 'admin@aegis.com', ?, 'EMR Security HQ', 'admin', 'enterprise', 'EMR-ADMIN-MASTER-KEY')
    """, (admin_pwd_hash,))
    
    conn.commit()
    conn.close()

def register_user(email, password, company=""):
    email = (email or "").strip().lower()
    password = (password or "").strip()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    pwd_hash = generate_password_hash(password)
    hwid_key = f"EMR-SAAS-{os.urandom(4).hex().upper()}"
    try:
        cursor.execute("INSERT INTO users (email, password_hash, company, hwid_license) VALUES (?, ?, ?, ?)",
                       (email, pwd_hash, company, hwid_key))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return True, user_id, hwid_key
    except sqlite3.IntegrityError:
        conn.close()
        return False, "El usuario ya existe.", None

def verify_user(email, password):
    email = (email or "").strip().lower()
    password = (password or "").strip()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, company, role, plan, hwid_license FROM users WHERE LOWER(email) = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row and check_password_hash(row[2], password):
        return True, {
            "id": row[0],
            "email": row[1],
            "company": row[3],
            "role": row[4],
            "plan": row[5],
            "hwid_license": row[6]
        }
    return False, "Credenciales incorrectas."

def record_scan(user_id, scan_type, target, status, summary, details_json=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_history (user_id, scan_type, target, status, summary, details_json) VALUES (?, ?, ?, ?, ?, ?)",
                   (user_id, scan_type, target, status, summary, details_json))
    conn.commit()
    conn.close()

def get_user_scans(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT scan_type, target, status, summary, created_at FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 10", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"scan_type": r[0], "target": r[1], "status": r[2], "summary": r[3], "created_at": r[4]} for r in rows]

def count_user_scans_week(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND created_at >= datetime('now', '-7 days')", (user_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_user_plan(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT plan FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "basic"

def update_user_plan(user_id, plan):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, user_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, company, role, plan, hwid_license, created_at FROM users ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "email": r[1],
        "company": r[2],
        "role": r[3],
        "plan": r[4],
        "hwid_license": r[5],
        "created_at": r[6]
    } for r in rows]

def update_license(user_id, new_plan, new_hwid=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if new_hwid:
        cursor.execute("UPDATE users SET plan = ?, hwid_license = ? WHERE id = ?", (new_plan, new_hwid, user_id))
    else:
        cursor.execute("UPDATE users SET plan = ? WHERE id = ?", (new_plan, user_id))
    conn.commit()
    conn.close()

init_db()
