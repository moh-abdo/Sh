import time
import json
import pandas as pd
import numpy as np
import subprocess
import os
import requests
from pathlib import Path
from datetime import datetime
from threading import Thread, Lock
from collections import deque

# استيراد المكونات الأخرى
try:
    from features import extract_features, FEATURE_COLUMNS
    from model import HybridSecurityModel
except ImportError:
    from defender_system.features import extract_features, FEATURE_COLUMNS
    from defender_system.model import HybridSecurityModel

# المسارات
DATA_DIR = Path("defender_system/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_FILE = DATA_DIR / "alerts.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
CONFIG_FILE = DATA_DIR / "config.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"

class DefenderEngine:
    """
    محرك الدفاع المحدث:
    - لا توجد محاكاة تلقائية أو تحديثات وهمية.
    - يعتمد كلياً على البيانات المستلمة عبر الـ API أو الالتقاط الحي.
    - يدعم إرسال تنبيهات تلجرام فورية.
    """
    def __init__(self, mode="manual", interface=None):
        self.mode = mode
        self.interface = interface
        self.model = HybridSecurityModel()
        self.packet_buffer = deque(maxlen=500)
        self.alerts = []
        self.blocked_ips = {}
        self.whitelist = ["127.0.0.1", "::1"]
        self.config = {
            "threshold": 0.7,
            "auto_block": True,
            "proactive_mode": True,
            "telegram_enabled": False,
            "telegram_token": "",
            "telegram_chat_id": ""
        }
        self.is_running = False
        self.lock = Lock()
        
        self._load_state()
        self._load_config()
        self._load_whitelist()

    def _load_state(self):
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, "r") as f:
                try: self.alerts = json.load(f)
                except: self.alerts = []
        if BLOCKED_IPS_FILE.exists():
            with open(BLOCKED_IPS_FILE, "r") as f:
                try: self.blocked_ips = json.load(f)
                except: self.blocked_ips = {}

    def _load_config(self):
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as f:
                try: self.config.update(json.load(f))
                except: pass

    def _load_whitelist(self):
        if WHITELIST_FILE.exists():
            with open(WHITELIST_FILE, "r") as f:
                try:
                    self.whitelist.extend(json.load(f))
                    self.whitelist = list(set(self.whitelist))
                except: pass

    def _save_state(self):
        with open(ALERTS_FILE, "w") as f:
            json.dump(self.alerts[-1000:], f, indent=2, ensure_ascii=False)
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(self.blocked_ips, f, indent=2, ensure_ascii=False)

    def send_telegram_message(self, message):
        """إرسال رسالة إلى تلجرام إذا كانت الميزة مفعلة"""
        if not self.config.get("telegram_enabled") or not self.config.get("telegram_token") or not self.config.get("telegram_chat_id"):
            return
        
        token = self.config["telegram_token"]
        chat_id = self.config["telegram_chat_id"]
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            # إرسال في خيط منفصل لعدم تعطيل المحرك
            Thread(target=lambda: requests.post(url, json=payload, timeout=10)).start()
        except Exception as e:
            print(f"[⚠️] خطأ في إرسال تنبيه تلجرام: {e}")

    def block_ip(self, ip, reason, severity="CRITICAL"):
        if ip in self.whitelist: return
        with self.lock:
            if ip not in self.blocked_ips:
                self.blocked_ips[ip] = {
                    "reason": reason,
                    "blocked_at": datetime.now().isoformat(),
                    "status": "isolated (proactive)",
                    "severity": severity
                }
                print(f"[🛡️] تم عزل المهاجم: {ip} | السبب: {reason}")
                self._save_state()
                
                # إرسال تنبيه تلجرام عند الحظر
                msg = f"🔒 *تم عزل جهاز مهاجم!*\n\n" \
                      f"🌐 *IP:* `{ip}`\n" \
                      f"🚨 *الخطورة:* `{severity}`\n" \
                      f"📝 *السبب:* {reason}\n" \
                      f"⏰ *الوقت:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                self.send_telegram_message(msg)

    def send_alert(self, ip, score, reason, protocol="TCP"):
        severity = "CRITICAL" if score > self.config["threshold"] else "HIGH"
        alert = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip,
            "score": float(score),
            "reason": reason,
            "protocol": protocol,
            "severity": severity
        }
        with self.lock:
            self.alerts.append(alert)
            self._save_state()
            
            # إرسال تنبيه تلجرام عند اكتشاف هجوم خطير
            if severity == "CRITICAL":
                msg = f"🚨 *تنبيه أمني حرج!*\n\n" \
                      f"🌐 *المصدر:* `{ip}`\n" \
                      f"🎯 *الهدف:* `نظام الشبكة`\n" \
                      f"📊 *درجة التهديد:* `{score:.2%}`\n" \
                      f"📝 *السبب:* {reason}\n" \
                      f"🌐 *البروتوكول:* {protocol}"
                self.send_telegram_message(msg)

    def start(self):
        self.is_running = True
        print(f"[🛡️] محرك الدفاع يعمل الآن في وضع: {self.mode}")
        print("[🛡️] في انتظار هجمات حقيقية من واجهة المخترق...")

    def stop(self):
        self.is_running = False
