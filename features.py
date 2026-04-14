import pandas as pd
import numpy as np
from pathlib import Path
from collections import defaultdict

# الثوابت
SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 6666, 8080, 1337, 31337}
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}

FEATURE_COLUMNS = [
    "protocol_enc", "packet_size", "payload_size", "ttl",
    "src_port", "dst_port", "is_suspicious_port",
    "pkt_per_sec_src", "unique_dst_ratio", "avg_payload_src",
    "std_packet_size_src", "port_entropy", "iat_avg", "label"
]

def encode_protocol(proto):
    return PROTOCOL_MAP.get(str(proto).upper(), 3)

def compute_iat(timestamps):
    """حساب متوسط الوقت بين الحزم (Inter-Arrival Time)"""
    if len(timestamps) < 2:
        return 0
    diffs = np.diff(pd.to_datetime(timestamps).values.astype(np.int64)) // 10**6 # بالملي ثانية
    return np.mean(diffs)

def extract_features(df):
    """محرك استخراج الخصائص المطور"""
    if df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    
    # تحويل الأنواع
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # تجميع البيانات حسب المصدر IP
    features_list = []
    
    # حساب الإحصائيات لكل نافذة زمنية أو لكل مجموعة حزم
    # في الوقت الفعلي، سنقوم بمعالجة الحزم في مجموعات (Chunks)
    
    for src_ip, group in df.groupby('src_ip'):
        # إحصائيات المجموعة
        pkt_count = len(group)
        duration = max((group['timestamp'].max() - group['timestamp'].min()).total_seconds(), 0.1)
        pkt_per_sec = pkt_count / duration
        
        unique_dst = group['dst_ip'].nunique()
        dst_ratio = unique_dst / pkt_count
        
        avg_payload = group['payload_size'].mean()
        std_size = group['packet_size'].std() if pkt_count > 1 else 0
        
        # إنتروبيا المنافذ
        port_counts = group['dst_port'].value_counts()
        probs = port_counts / port_counts.sum()
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        
        iat_avg = compute_iat(group['timestamp'])
        
        for _, row in group.iterrows():
            feat = {
                "protocol_enc": encode_protocol(row['protocol']),
                "packet_size": row['packet_size'],
                "payload_size": row['payload_size'],
                "ttl": row['ttl'],
                "src_port": row['src_port'],
                "dst_port": row['dst_port'],
                "is_suspicious_port": 1 if row['dst_port'] in SUSPICIOUS_PORTS else 0,
                "pkt_per_sec_src": pkt_per_sec,
                "unique_dst_ratio": dst_ratio,
                "avg_payload_src": avg_payload,
                "std_packet_size_src": std_size,
                "port_entropy": entropy,
                "iat_avg": iat_avg,
                "label": 0 # سيتم تحديثه في مرحلة التدريب أو الكشف
            }
            features_list.append(feat)
            
    return pd.DataFrame(features_list)
