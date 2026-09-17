# -*- coding: utf-8 -*-
"""
FaceSecurity School v2.3 - Telegram Recovery & Security Bot
"""

import os
import sys
import json
import time
import random
import requests

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("❌ XATOLIK: BOT_TOKEN yoki TELEGRAM_BOT_TOKEN environment o'zgaruvchisi topilmadi!")
    print("Iltimos: export BOT_TOKEN='SIZNING_BOT_TOKENINGIZ' o'rnating.")
    sys.exit(1)

API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# In-memory OTP storage: chat_id -> { "code": "123456", "expires_at": timestamp }
otp_store = {}

def send_message(chat_id, text, parse_mode="HTML"):
    try:
        url = f"{API_URL}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode
        }
        res = requests.post(url, json=payload, timeout=10)
        return res.json()
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def generate_otp_for_user(chat_id):
    code = f"{random.randint(100000, 999999)}"
    otp_store[str(chat_id)] = {
        "code": code,
        "expires_at": time.time() + 300 # 5 minutes
    }
    return code

# Audit logger
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Allowlist for admin commands if configured (from ENV)
ALLOWED_ADMIN_IDS = set(filter(None, [x.strip() for x in os.environ.get("ALLOWED_TELEGRAM_ADMINS", "").split(",")]))

def handle_update(update):
    if "message" not in update:
        return
    msg = update["message"]
    chat_id = msg.get("chat", {}).get("id")
    text = msg.get("text", "").strip()
    username = msg.get("from", {}).get("username", "")
    first_name = msg.get("from", {}).get("first_name", "Foydalanuvchi")
    user_id = msg.get("from", {}).get("id")

    if not chat_id:
        return

    logging.info(f"[AUDIT] Message from user {user_id} (@{username}) in chat {chat_id}: {text[:30]}")

    if text.startswith("/start"):
        welcome = (
            f"👋 Assalomu alaykum, <b>{first_name}</b>!\n\n"
            f"🛡️ <b>FaceSecurity School v2.3</b> Xavfsiz Botiga xush kelibsiz!\n\n"
            f"🆔 <b>Sizning Telegram Chat ID:</b> <code>{chat_id}</code>\n"
            f"👤 <b>Sizning Nik:</b> @{username if username else 'ko`rsatilmagan'}\n\n"
            f"📌 <b>Yo'riqnoma:</b>\n"
            f"1. FaceSecurity dasturi (Sozlamalar -> Xavfsizlik) bo'limida Chat ID maydoniga <code>{chat_id}</code> ni saqlang.\n"
            f"2. Bot faqat tasdiqlangan va biriktirilgan kompyuterlarga xizmat ko'rsatadi.\n\n"
            f"🔐 <i>Dastur parollari va 2FA kodlarini begonalar bilan ulashmang!</i>"
        )
        send_message(chat_id, welcome)

    elif text.startswith("/myid") or text.startswith("/id"):
        send_message(chat_id, f"🆔 <b>Sizning Telegram Chat ID:</b> <code>{chat_id}</code>")

    elif text.startswith("/admin"):
        if ALLOWED_ADMIN_IDS and str(user_id) not in ALLOWED_ADMIN_IDS:
            logging.warning(f"[SECURITY] Unauthorized admin attempt by user {user_id} (@{username})")
            send_message(chat_id, "⛔ <b>Kirish rad etildi:</b> Siz administratorlar ro'yxatida emassiz.")
            return
        send_message(chat_id, f"🛡️ <b>Administrator paneli:</b> Tizim barqaror va barcha xavfsizlik protokollari faol.")

    else:
        send_message(chat_id, f"ℹ️ Sizning Chat ID: <code>{chat_id}</code>.\n\nParolni tiklash yoki dasturga ulanish uchun kompyuter ekranidagi 6 xonali <b>PIN kodni</b> ushbu botga yuboring.")

def main():
    print("=" * 60)
    print("🛡️ FaceSecurity School Telegram Bot ishga tushdi!")
    print(f"🤖 Bot Token: {BOT_TOKEN[:15]}...")
    print("=" * 60)

    offset = 0
    while True:
        try:
            url = f"{API_URL}/getUpdates?offset={offset}&timeout=20"
            resp = requests.get(url, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    handle_update(upd)
        except Exception as e:
            time.sleep(2)

if __name__ == "__main__":
    main()
