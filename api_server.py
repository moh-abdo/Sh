import logging
from flask import Flask, request, jsonify
import json
import threading
from pathlib import Path
from datetime import datetime
import sys
import numpy as np
import pandas as pd
from collections import defaultdict

# إعداد التسجيل
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# استيراد محرك الدفاع
sys.path.insert(0, str(Path(__file__).parent))
try:
    from defender import DefenderEngine
    from features import extract_features
except ImportError:
    from defender_system.defender import DefenderEngine
    from defender_system.features import extract_features

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# تهيئة محرك الدفاع
defender = DefenderEngine(mode="manual")
defender.start()

DATA_DIR = Path("defender_system/data")
ATTACKS_LOG = DATA_DIR / "attacks_log.json"
CONNECTED_DEVICES_FILE = DATA_DIR / "connected_devices.json"
UNBLOCK_HISTORY_FILE = DATA_DIR / "unblock_history.json"

# متغيرات لتتبع الأجهزة المتصلة
connected_devices = {}
device_lock = threading.Lock()

def load_connected_devices():
    """تحميل قائمة الأجهزة المتصلة"""
    global connected_devices
    if CONNECTED_DEVICES_FILE.exists():
        try:
            with open(CONNECTED_DEVICES_FILE, 'r', encoding='utf-8') as f:
                connected_devices = json.load(f)
        except:
            connected_devices = {}

def save_connected_devices():
    """حفظ قائمة الأجهزة المتصلة"""
    try:
        with open(CONNECTED_DEVICES_FILE, 'w', encoding='utf-8') as f:
            json.dump(connected_devices, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"خطأ في حفظ الأجهزة المتصلة: {e}")

def log_attack(attack_data):
    """تسجيل الهجوم في ملف السجل"""
    try:
        if ATTACKS_LOG.exists():
            with open(ATTACKS_LOG, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append({
            'timestamp': datetime.now().isoformat(),
            'attack': attack_data
        })
        
        # الاحتفاظ بآخر 1000 هجوم فقط
        logs = logs[-1000:]
        
        with open(ATTACKS_LOG, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"خطأ في تسجيل الهجوم: {e}")

def log_unblock_action(ip, reason, admin_user="system"):
    """تسجيل عملية رفع الحظر"""
    try:
        history = []
        if UNBLOCK_HISTORY_FILE.exists():
            with open(UNBLOCK_HISTORY_FILE, 'r', encoding='utf-8') as f:
                try:
                    history = json.load(f)
                except:
                    history = []
        
        history.append({
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'reason': reason,
            'admin_user': admin_user
        })
        
        # الاحتفاظ بآخر 500 عملية
        history = history[-500:]
        
        with open(UNBLOCK_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"خطأ في تسجيل عملية رفع الحظر: {e}")

@app.route('/api/device/connect', methods=['POST'])
def device_connect():
    """
    سيناريو اتصال جهاز بالشبكة
    يحاكي اتصال هاكر بالشبكة ويرسل إشعار تلقائي
    """
    try:
        data = request.get_json()
        device_ip = data.get('ip', '0.0.0.0')
        device_name = data.get('name', 'Unknown Device')
        device_mac = data.get('mac', 'XX:XX:XX:XX:XX:XX')
        
        with device_lock:
            if device_ip not in connected_devices:
                connected_devices[device_ip] = {
                    'name': device_name,
                    'mac': device_mac,
                    'connected_at': datetime.now().isoformat(),
                    'status': 'active',
                    'is_suspicious': False,
                    'attack_count': 0
                }
                save_connected_devices()
                
                # إرسال إشعار عند الاتصال
                alert_msg = f"جهاز جديد متصل بالشبكة: {device_ip} ({device_name})"
                logger.info(f"[📡] {alert_msg}")
                
                # إضافة إشعار للنظام
                defender.send_alert(
                    ip=device_ip,
                    score=0.1,
                    reason=alert_msg,
                    protocol="NETWORK"
                )
                
                return jsonify({
                    "status": "connected",
                    "message": alert_msg,
                    "device_ip": device_ip
                }), 200
            else:
                return jsonify({
                    "status": "already_connected",
                    "message": f"الجهاز {device_ip} متصل بالفعل"
                }), 200
                
    except Exception as e:
        logger.error(f"خطأ في اتصال الجهاز: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/device/disconnect', methods=['POST'])
def device_disconnect():
    """قطع اتصال جهاز عن الشبكة"""
    try:
        data = request.get_json()
        device_ip = data.get('ip', '0.0.0.0')
        
        with device_lock:
            if device_ip in connected_devices:
                connected_devices[device_ip]['status'] = 'disconnected'
                connected_devices[device_ip]['disconnected_at'] = datetime.now().isoformat()
                save_connected_devices()
                
                logger.info(f"[📡] جهاز قطع الاتصال: {device_ip}")
                return jsonify({
                    "status": "disconnected",
                    "message": f"تم قطع اتصال الجهاز {device_ip}"
                }), 200
            else:
                return jsonify({
                    "status": "not_found",
                    "message": f"الجهاز {device_ip} غير متصل"
                }), 404
                
    except Exception as e:
        logger.error(f"خطأ في قطع الاتصال: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/devices', methods=['GET'])
def get_connected_devices():
    """الحصول على قائمة الأجهزة المتصلة"""
    with device_lock:
        active_devices = {ip: info for ip, info in connected_devices.items() 
                         if info['status'] == 'active'}
    return jsonify({"devices": active_devices, "count": len(active_devices)}), 200

@app.route('/api/attack', methods=['POST'])
def receive_attack():
    """
    استقبال هجوم حقيقي من واجهة المخترق وتحليله بنموذج الـ AI
    مع حظر ذكي تلقائي
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"status": "error", "message": "لا توجد بيانات"}), 400
        
        attacker_ip = data.get('attacker_ip', '0.0.0.0')
        attack_type = data.get('attack_type', 'Unknown')
        packets = data.get('packets', [])

        if not packets:
            return jsonify({"status": "error", "message": "لا توجد حزم"}), 400
        
        # تحديث معلومات الجهاز المهاجم
        with device_lock:
            if attacker_ip in connected_devices:
                connected_devices[attacker_ip]['attack_count'] = \
                    connected_devices[attacker_ip].get('attack_count', 0) + 1
                connected_devices[attacker_ip]['is_suspicious'] = True
                connected_devices[attacker_ip]['last_attack'] = datetime.now().isoformat()
                save_connected_devices()
        
        # تسجيل الهجوم
        log_attack(data)
        
        logger.info(f"🚨 هجوم مستلم من {attacker_ip}: {attack_type}")
        
        # تحويل الحزم إلى DataFrame واستخراج الميزات
        df = pd.DataFrame(packets)
        features_df = extract_features(df)
        
        if not features_df.empty:
            X = features_df.drop(columns=["label"]).values
            
            # التنبؤ باستخدام نموذج الـ AI
            predictions = defender.model.predict(X)
            proba = defender.model.predict_proba(X)
            
            # حساب درجة الخطورة
            threat_score = float(np.mean(proba))
            is_attack = int(np.sum(predictions)) > 0
            
            # عتبة الكشف من الإعدادات
            threshold = defender.config.get("threshold", 0.7)
            
            if is_attack or threat_score > threshold:
                reason = f"رصد هجوم {attack_type} حقيقي من {attacker_ip}"
                
                # إرسال التنبيه
                defender.send_alert(
                    ip=attacker_ip,
                    score=threat_score,
                    reason=reason,
                    protocol=packets[0].get('protocol', 'TCP')
                )
                
                # تفعيل الحظر الذكي التلقائي
                if defender.config.get("auto_block", True):
                    # حظر فوري
                    defender.block_ip(
                        ip=attacker_ip,
                        reason=reason,
                        severity="CRITICAL" if threat_score > 0.9 else "HIGH"
                    )
                    
                    logger.warning(f"🔒 تم حظر {attacker_ip} تلقائياً - الخطورة: {threat_score:.2%}")
                
                return jsonify({
                    "status": "blocked",
                    "message": f"تم كشف الهجوم وعزل {attacker_ip}",
                    "threat_score": threat_score,
                    "action": "blocked",
                    "attack_type": attack_type
                }), 200
            else:
                return jsonify({
                    "status": "safe",
                    "message": "حركة مرور طبيعية",
                    "threat_score": threat_score
                }), 200
        else:
            return jsonify({"status": "error", "message": "فشل تحليل البيانات"}), 500
            
    except Exception as e:
        logger.error(f"خطأ في معالجة الهجوم: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/block/unblock', methods=['POST'])
def unblock_ip():
    """
    رفع الحظر عن عنوان IP من لوحة التحكم
    مع تسجيل العملية
    """
    try:
        data = request.get_json()
        ip_to_unblock = data.get('ip', '0.0.0.0')
        reason = data.get('reason', 'رفع الحظر من قبل المسؤول')
        admin_user = data.get('admin_user', 'admin')
        
        if ip_to_unblock in defender.blocked_ips:
            # حذف من قائمة الحظر
            del defender.blocked_ips[ip_to_unblock]
            defender._save_state()
            
            # تسجيل العملية
            log_unblock_action(ip_to_unblock, reason, admin_user)
            
            logger.info(f"✅ تم رفع الحظر عن {ip_to_unblock} - السبب: {reason}")
            
            return jsonify({
                "status": "unblocked",
                "message": f"تم رفع الحظر عن {ip_to_unblock}",
                "ip": ip_to_unblock
            }), 200
        else:
            return jsonify({
                "status": "not_blocked",
                "message": f"العنوان {ip_to_unblock} غير محظور"
            }), 404
            
    except Exception as e:
        logger.error(f"خطأ في رفع الحظر: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/block/list', methods=['GET'])
def get_blocked_list():
    """الحصول على قائمة العناوين المحظورة"""
    return jsonify({
        "blocked_ips": defender.blocked_ips,
        "count": len(defender.blocked_ips)
    }), 200

@app.route('/api/status', methods=['GET'])
def get_status():
    """الحصول على حالة النظام"""
    with device_lock:
        active_count = len([d for d in connected_devices.values() if d['status'] == 'active'])
    
    return jsonify({
        "status": "running",
        "defender_running": defender.is_running,
        "mode": defender.mode,
        "blocked_count": len(defender.blocked_ips),
        "connected_devices": active_count,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """الحصول على آخر التنبيهات"""
    return jsonify({"alerts": defender.alerts[-50:]}), 200

@app.route('/api/blocked', methods=['GET'])
def get_blocked():
    """الحصول على قائمة العناوين المحظورة"""
    return jsonify({"blocked_ips": defender.blocked_ips}), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    """فحص صحة النظام"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }), 200

if __name__ == '__main__':
    # تحميل الأجهزة المتصلة السابقة
    load_connected_devices()
    
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
