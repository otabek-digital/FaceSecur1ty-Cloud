# -*- coding: utf-8 -*-
"""
FaceSecurity School v2.3 - Central Cloud Backend & License Server
FastAPI based high-performance management server.
"""

import os
import time
import hmac
import hashlib
import random
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="FaceSecurity Cloud Hub API",
    version="2.3",
    description="Central licensing, device heartbeat, and remote command dispatcher for FaceSecurity School v2.3"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SERVER_SECRET_KEY = os.getenv("FSS_SERVER_SECRET", "FaceSecurity_Master_2026_Key_!x99")

# In-memory device state cache
devices_db: Dict[str, Dict[str, Any]] = {}
otp_tokens: Dict[str, Dict[str, Any]] = {}

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

class OtpRequest(BaseModel):
    chat_id: str
    hwid: str

class OtpVerifyRequest(BaseModel):
    chat_id: str
    otp_code: str

class LicenseVerifyRequest(BaseModel):
    hwid: str
    license_key: Optional[str] = ""

def verify_signature(data_str: str, sig: str) -> bool:
    if not sig:
        return False
    expected = hmac.new(SERVER_SECRET_KEY.encode(), data_str.encode(), hashlib.sha256).hexdigest().upper()
    return hmac.compare_digest(expected, sig.upper())

@app.get("/")
def root():
    return {
        "service": "FaceSecurity School Cloud Server",
        "version": "2.3",
        "status": "ONLINE",
        "active_devices": len(devices_db)
    }

@app.post("/api/devices/heartbeat")
def receive_heartbeat(req: HeartbeatRequest):
    hwid = req.hwid.strip().upper()
    now = int(time.time())
    
    current = devices_db.get(hwid, {})
    current_status = current.get("status", "ACTIVE")
    
    devices_db[hwid] = {
        "hwid": hwid,
        "pc_name": req.pc_name,
        "school": req.school,
        "version": req.version,
        "status": current_status if current_status == "LOCKED" else req.status,
        "last_seen": now
    }
    
    return {
        "ok": True,
        "hwid": hwid,
        "status": devices_db[hwid]["status"],
        "server_time": now
    }

@app.get("/api/devices/status/{hwid}")
def get_device_status(hwid: str):
    hwid = hwid.strip().upper()
    device = devices_db.get(hwid)
    if not device:
        return {"hwid": hwid, "status": "ACTIVE", "registered": False}
    return device

@app.post("/api/devices/command")
def send_command(req: CommandRequest):
    hwid = req.hwid.strip().upper()
    cmd = req.command.strip().upper()
    
    if cmd not in ["LOCK", "UNLOCK", "ACTIVE", "BLOCKED"]:
        raise HTTPException(status_code=400, detail="Invalid command")
    
    target_status = "LOCKED" if cmd in ["LOCK", "BLOCKED"] else "ACTIVE"
    
    if hwid == "GLOBAL":
        for k in devices_db:
            devices_db[k]["status"] = target_status
    else:
        if hwid in devices_db:
            devices_db[hwid]["status"] = target_status
        else:
            devices_db[hwid] = {"hwid": hwid, "status": target_status, "last_seen": int(time.time())}
            
    return {"ok": True, "target": hwid, "new_status": target_status}

@app.post("/api/auth/otp/request")
def request_otp(req: OtpRequest):
    otp = f"{random.randint(100000, 999999)}"
    otp_tokens[req.chat_id] = {
        "otp": otp,
        "hwid": req.hwid,
        "expires_at": time.time() + 300
    }
    return {"ok": True, "otp": otp, "expires_in_seconds": 300}

@app.post("/api/auth/otp/verify")
def verify_otp(req: OtpVerifyRequest):
    stored = otp_tokens.get(req.chat_id)
    if not stored:
        return {"ok": False, "message": "OTP topilmadi yoki muddati o'tgan!"}
    
    if time.time() > stored["expires_at"]:
        del otp_tokens[req.chat_id]
        return {"ok": False, "message": "OTP muddati tugagan!"}
        
    if stored["otp"] == req.otp_code.strip():
        del otp_tokens[req.chat_id]
        return {"ok": True, "message": "Muvaffaqiyatli tasdiqlandi!", "hwid": stored["hwid"]}
        
    return {"ok": False, "message": "Noto'g'ri kod!"}

@app.post("/api/license/verify")
def verify_license(req: LicenseVerifyRequest):
    return {
        "ok": True,
        "hwid": req.hwid,
        "plan": "pro",
        "expires": "∞ Cheksiz",
        "valid": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

