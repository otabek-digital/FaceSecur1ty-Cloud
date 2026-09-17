# -*- coding: utf-8 -*-
"""
FaceSecurity School v2.3 - Central Cloud Backend & License Server
FastAPI based high-performance enterprise management server.
Upgraded with full multi-worker SQLite state persistence, automatic token pruning, and robust security.
"""

import os
import time
import hmac
import hashlib
import random
import sqlite3
import json
import logging
from typing import Optional, Dict, Any, List
import requests
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CloudServer")

app = FastAPI(
    title="FaceSecurity Cloud Hub API",
    version="2.3",
    description="Central licensing, device heartbeat, and remote command dispatcher for FaceSecurity School v2.3"
)

# ── 🛡️ CORS Configuration ──
raw_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

SERVER_SECRET_KEY = os.environ.get("FSS_SERVER_SECRET") or os.environ.get("SERVER_SECRET_KEY", "FSS_PROD_SECURE_TOKEN_2026_RANDOM_GUARD")
RECOVERY_BOT_TOKEN = os.environ.get("FSS_BOT_TOKEN") or os.environ.get("RECOVERY_BOT_TOKEN") or os.environ.get("BOT_TOKEN", "")

if SERVER_SECRET_KEY == "FSS_PROD_SECURE_TOKEN_2026_RANDOM_GUARD":
    logger.warning("⚠️ OGOHLANTIRISH: Server standart maxfiy kalit bilan ishlamoqda. Ishlab chiqarishda FSS_SERVER_SECRET muhit o'zgaruvchisini o'rnating!")

# ── 🛡️ Persistent SQLite Database for Devices, OTPs, Nonces, and Sessions ──
DB_PATH = os.path.join(os.path.dirname(__file__), "cloud_devices.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA synchronous = NORMAL;")
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            hwid TEXT PRIMARY KEY,
            pc_name TEXT,
            school TEXT,
            version TEXT,
            status TEXT,
            last_seen INTEGER,
            extra_json TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS command_nonces (
            nonce TEXT PRIMARY KEY,
            created_at INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_tokens (
            chat_id TEXT PRIMARY KEY,
            otp TEXT NOT NULL,
            hwid TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def db_verify_and_burn_nonce(nonce: str, ttl_seconds: int = 60) -> bool:
    if not nonce:
        return True  # Nonce optional for backwards compatibility unless passed
    now = int(time.time())
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM command_nonces WHERE created_at < ?", (now - ttl_seconds * 2,))
        c.execute("SELECT nonce FROM command_nonces WHERE nonce = ?", (nonce,))
        if c.fetchone():
            conn.close()
            return False
            
        c.execute("INSERT INTO command_nonces (nonce, created_at) VALUES (?, ?)", (nonce, now))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Nonce error: {e}")
        return False

def db_save_device(hwid: str, pc_name: str, school: str, version: str, status: str, last_seen: int):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO devices (hwid, pc_name, school, version, status, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hwid) DO UPDATE SET
                pc_name = excluded.pc_name,
                school = excluded.school,
                version = excluded.version,
                status = excluded.status,
                last_seen = excluded.last_seen
        """, (hwid, pc_name, school, version, status, last_seen))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Save Device Error: {e}")

def db_load_devices() -> Dict[str, Dict[str, Any]]:
    devs = {}
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT hwid, pc_name, school, version, status, last_seen FROM devices")
        for row in c.fetchall():
            devs[row["hwid"]] = {
                "hwid": row["hwid"],
                "pc_name": row["pc_name"] or "",
                "school": row["school"] or "",
                "version": row["version"] or "v2.3",
                "status": row["status"] or "ACTIVE",
                "last_seen": row["last_seen"] or 0
            }
        conn.close()
    except Exception as e:
        logger.error(f"DB Load Devices Error: {e}")
    return devs

def db_save_otp(chat_id: str, otp: str, hwid: str, ttl_seconds: int = 300):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        expires_at = time.time() + ttl_seconds
        c.execute("""
            INSERT INTO otp_tokens (chat_id, otp, hwid, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                otp = excluded.otp,
                hwid = excluded.hwid,
                expires_at = excluded.expires_at
        """, (chat_id, otp, hwid, expires_at))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Save OTP Error: {e}")

def db_verify_and_burn_otp(chat_id: str, code: str) -> tuple[bool, str, str]:
    now = time.time()
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Clean expired
        c.execute("DELETE FROM otp_tokens WHERE expires_at < ?", (now,))
        
        c.execute("SELECT otp, hwid, expires_at FROM otp_tokens WHERE chat_id = ?", (chat_id,))
        row = c.fetchone()
        if not row:
            conn.commit()
            conn.close()
            return False, "", "OTP topilmadi yoki muddati o'tgan!"
            
        stored_otp = row["otp"]
        hwid = row["hwid"]
        
        if hmac.compare_digest(stored_otp, code.strip()):
            c.execute("DELETE FROM otp_tokens WHERE chat_id = ?", (chat_id,))
            conn.commit()
            conn.close()
            return True, hwid, "Muvaffaqiyatli tasdiqlandi!"
            
        conn.commit()
        conn.close()
        return False, "", "Noto'g'ri kod!"
    except Exception as e:
        logger.error(f"DB Verify OTP Error: {e}")
        return False, "", f"Xatolik yuz berdi: {e}"

def db_save_admin_session(token: str, ttl_seconds: int = 1800):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        expires_at = time.time() + ttl_seconds
        c.execute("INSERT OR REPLACE INTO admin_sessions (token, expires_at) VALUES (?, ?)", (token, expires_at))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Save Admin Session Error: {e}")

def db_check_admin_session(token: str) -> bool:
    if not token:
        return False
    now = time.time()
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT expires_at FROM admin_sessions WHERE token = ?", (token,))
        row = c.fetchone()
        conn.close()
        if row and row["expires_at"] > now:
            return True
        return False
    except Exception as e:
        logger.error(f"DB Check Admin Session Error: {e}")
        return False

# Pydantic Schemas
class HeartbeatRequest(BaseModel):
    hwid: str
    pc_name: Optional[str] = ""
    school: Optional[str] = ""
    version: Optional[str] = "v2.3"
    status: Optional[str] = "ACTIVE"

class CommandRequest(BaseModel):
    hwid: str
    command: str  # LOCK, UNLOCK, RESET_PIN
    signature: Optional[str] = ""
    admin_token: Optional[str] = ""
    nonce: Optional[str] = ""

class OtpRequest(BaseModel):
    chat_id: str
    hwid: str

class OtpVerifyRequest(BaseModel):
    chat_id: str
    otp_code: str

class LicenseVerifyRequest(BaseModel):
    hwid: str
    license_key: Optional[str] = ""

class SendPasswordRequest(BaseModel):
    hwid: Optional[str] = ""
    chat_id: str
    password: str
    teacher_name: Optional[str] = "O'qituvchi / Mas'ul"
    school_name: Optional[str] = ""

class AdminLoginRequest(BaseModel):
    password: str

class AdminLoginResponse(BaseModel):
    ok: bool
    token: str
    expires_in_seconds: int

def get_admin_auth(authorization: Optional[str] = Header(None)) -> bool:
    if not authorization:
        return False
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        return False
    # Direct match against SERVER_SECRET_KEY
    if hmac.compare_digest(token, SERVER_SECRET_KEY):
        return True
    # Match valid persistent session token
    if db_check_admin_session(token):
        return True
    return False

def verify_signature(data_str: str, sig: str) -> bool:
    if not sig:
        return False
    expected = hmac.new(SERVER_SECRET_KEY.encode(), data_str.encode(), hashlib.sha256).hexdigest().upper()
    return hmac.compare_digest(expected, sig.upper())

@app.get("/")
def root():
    devices = db_load_devices()
    return {
        "service": "FaceSecurity School Cloud Server",
        "version": "2.3",
        "status": "ONLINE",
        "active_devices": len(devices)
    }

@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    input_pass = req.password.strip()
    # Constant-time comparison
    if hmac.compare_digest(input_pass, SERVER_SECRET_KEY):
        sess_token = hashlib.sha256(f"{input_pass}_{time.time()}_{random.random()}".encode()).hexdigest()
        db_save_admin_session(sess_token, ttl_seconds=1800)
        return {"ok": True, "token": sess_token, "expires_in_seconds": 1800}
    raise HTTPException(status_code=401, detail="Noto'g'ri admin paroli!")

@app.get("/api/admin/devices")
def get_all_devices_admin(authorization: Optional[str] = Header(None)):
    if not get_admin_auth(authorization):
        raise HTTPException(status_code=403, detail="Ruxsat berilmadi: Faqat administrator uchun!")
    return {"ok": True, "devices": db_load_devices()}

@app.post("/api/devices/heartbeat")
def receive_heartbeat(req: HeartbeatRequest):
    hwid = req.hwid.strip().upper()
    now = int(time.time())
    
    current_devices = db_load_devices()
    current = current_devices.get(hwid, {})
    current_status = current.get("status", "ACTIVE")
    
    status_to_save = current_status if current_status == "LOCKED" else (req.status or "ACTIVE")
    db_save_device(hwid, req.pc_name or "", req.school or "", req.version or "v2.3", status_to_save, now)
    
    return {
        "ok": True,
        "hwid": hwid,
        "status": status_to_save,
        "server_time": now
    }

@app.get("/api/devices/status/{hwid}")
def get_device_status(hwid: str):
    hwid = hwid.strip().upper()
    current_devices = db_load_devices()
    device = current_devices.get(hwid)
    if not device:
        return {"hwid": hwid, "status": "ACTIVE", "registered": False}
    return device

@app.post("/api/devices/command")
def send_command(req: CommandRequest):
    hwid = req.hwid.strip().upper()
    cmd = req.command.strip().upper()
    
    # Strict Authorization Check: Signature or Admin Token required
    is_valid_auth = False
    if req.admin_token and (hmac.compare_digest(req.admin_token, SERVER_SECRET_KEY) or db_check_admin_session(req.admin_token)):
        is_valid_auth = True
    elif req.signature and verify_signature(f"{hwid}:{cmd}", req.signature):
        is_valid_auth = True
        
    if not is_valid_auth:
        raise HTTPException(status_code=401, detail="Ruxsat berilmadi: Yaroqsiz imzo yoki admin token!")
        
    # Nonce Replay Protection
    if req.nonce and not db_verify_and_burn_nonce(req.nonce):
        raise HTTPException(status_code=400, detail="Xatolik: Nonce allaqachon ishlatilgan yoki eskirgan (Replay Attack)!")
    
    if cmd not in ["LOCK", "UNLOCK", "ACTIVE", "BLOCKED"]:
        raise HTTPException(status_code=400, detail="Noto'g'ri buyruq")
    
    target_status = "LOCKED" if cmd in ["LOCK", "BLOCKED"] else "ACTIVE"
    now = int(time.time())
    
    current_devices = db_load_devices()
    if hwid == "GLOBAL":
        for k, v in current_devices.items():
            db_save_device(k, v.get("pc_name", ""), v.get("school", ""), v.get("version", "v2.3"), target_status, now)
    else:
        existing = current_devices.get(hwid, {})
        db_save_device(hwid, existing.get("pc_name", ""), existing.get("school", ""), existing.get("version", "v2.3"), target_status, now)
            
    return {"ok": True, "target": hwid, "new_status": target_status}

@app.post("/api/auth/otp/request")
def request_otp(req: OtpRequest):
    if not req.chat_id:
        raise HTTPException(status_code=400, detail="Chat ID required")
        
    otp = f"{random.randint(100000, 999999)}"
    db_save_otp(req.chat_id.strip(), otp, req.hwid.strip())
    
    # Send OTP ONLY via Telegram Bot
    if RECOVERY_BOT_TOKEN:
        msg_text = (
            f"🔐 <b>FaceSecurity Tiklash Kodi (OTP)</b>\n\n"
            f"🖥 Kompyuter: <code>{req.hwid}</code>\n"
            f"🔑 Tasdiqlash kodi: <b><code>{otp}</code></b>\n\n"
            f"<i>Kod 5 daqiqa davomida amal qiladi. Kodni hech kimga bermang!</i>"
        )
        tg_url = f"https://api.telegram.org/bot{RECOVERY_BOT_TOKEN}/sendMessage"
        try:
            requests.post(tg_url, json={"chat_id": req.chat_id.strip(), "text": msg_text, "parse_mode": "HTML"}, timeout=10)
        except Exception as e:
            logger.error(f"Telegram OTP dispatch failed: {e}")
        
    return {"ok": True, "message": "OTP Telegram bot orqali yuborildi", "expires_in_seconds": 300}

@app.post("/api/auth/otp/verify")
def verify_otp(req: OtpVerifyRequest):
    ok, hwid, msg = db_verify_and_burn_otp(req.chat_id.strip(), req.otp_code.strip())
    if ok:
        return {"ok": True, "message": msg, "hwid": hwid}
    return {"ok": False, "message": msg}

@app.post("/api/license/verify")
def verify_license(req: LicenseVerifyRequest):
    hwid = req.hwid.strip().upper()
    key = (req.license_key or "").strip()
    
    if not key:
        return {"ok": False, "hwid": hwid, "valid": False, "message": "Litsenziya kaliti kiritilmagan"}
        
    expected_hash = hmac.new(SERVER_SECRET_KEY.encode(), f"{hwid}:PRO".encode(), hashlib.sha256).hexdigest()[:16].upper()
    is_valid = hmac.compare_digest(expected_hash, key.upper())
    
    if is_valid:
        return {
            "ok": True,
            "hwid": hwid,
            "plan": "pro",
            "expires": "1 yil",
            "valid": True
        }
    else:
        return {
            "ok": False,
            "hwid": hwid,
            "valid": False,
            "message": "Yaroqsiz litsenziya kaliti!"
        }

@app.post("/api/auth/recovery/send-password")
def send_recovery_password(req: SendPasswordRequest, authorization: Optional[str] = Header(None)):
    auth_token = authorization.replace("Bearer ", "").strip() if authorization else ""
    if not auth_token or not (hmac.compare_digest(auth_token, SERVER_SECRET_KEY) or db_check_admin_session(auth_token)):
        raise HTTPException(status_code=401, detail="Ruxsat berilmadi: Avtorizatsiya tokeni talab qilinadi")

    if not req.chat_id or not req.password:
        raise HTTPException(status_code=400, detail="chat_id and password required")
    
    teacher_name = req.teacher_name if req.teacher_name and req.teacher_name.strip() else "O'qituvchi / Mas'ul"
    hwid_text = req.hwid if req.hwid and req.hwid.strip() else "Noma'lum"
    
    msg_text = (
        f"🔑 <b>FaceSecurity School v2.3 — Dastur Paroli</b>\n\n"
        f"Hurmatli <b>{teacher_name}</b>,\n"
        f"🖥 Kompyuter: <code>{hwid_text}</code>\n"
        f"🔐 <b>Sizning dastur parolingiz:</b> <code>{req.password}</code>\n\n"
        f"<i>Ushbu parolni dastur qulf oynasiga kiriting yoki 'Kirish' tugmasini bosing.</i>"
    )
    
    tg_url = f"https://api.telegram.org/bot{RECOVERY_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": req.chat_id.strip(),
        "text": msg_text,
        "parse_mode": "HTML"
    }
    
    try:
        r = requests.post(tg_url, json=payload, timeout=10)
        resp_data = r.json()
        if r.status_code == 200 and resp_data.get("ok"):
            return {"ok": True, "message": "Parol Telegramga muvaffaqiyatli yuborildi"}
        else:
            return {"ok": False, "error": resp_data.get("description", "Telegram API xatolik berdi")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
