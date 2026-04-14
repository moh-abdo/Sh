import os
import pickle
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

MODEL_DIR = Path("defender_system/data/models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)


class HybridSecurityModel:
    """
    نموذج أمني هجين متطور للدفاع الاستباقي:
    1. Isolation Forest: كشف الشذوذ (التهديدات غير المعروفة).
    2. Random Forest: تصنيف الهجمات المعروفة بدقة عالية.
    3. Gradient Boosting: تحليل الأنماط الزمنية للاستباقية.
    """
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.15,
            n_estimators=200,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.classifier = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        self.proactive_booster = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            subsample=0.8,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_importances_ = None

    def train(self, X, y=None):
        """تدريب النموذج الثلاثي على بيانات ضخمة"""
        print("\n[*] بدء عملية التدريب على البيانات الضخمة...")
        print(f"[*] حجم البيانات: {len(X):,} عينة")

        X_scaled = self.scaler.fit_transform(X)

        # 1. تدريب كاشف الشذوذ
        print("[*] (1/3) تدريب كاشف الشذوذ (Isolation Forest 200 شجرة)...")
        self.anomaly_detector.fit(X_scaled)
        print("    ✓ اكتمل")

        # 2. تدريب المصنفات إذا توفرت التسميات
        if y is not None and len(np.unique(y)) > 1:
            # تقسيم للتحقق
            X_train, X_val, y_train, y_val = train_test_split(
                X_scaled, y, test_size=0.15, random_state=42, stratify=y
            )

            print(f"[*] (2/3) تدريب المصنف الرئيسي (Random Forest 300 شجرة)...")
            self.classifier.fit(X_train, y_train)
            self.feature_importances_ = self.classifier.feature_importances_
            val_preds = self.classifier.predict(X_val)
            print("    ✓ اكتمل")
            print("\n--- تقرير دقة Random Forest ---")
            print(classification_report(y_val, val_preds, target_names=["طبيعي", "هجوم"]))

            cm = confusion_matrix(y_val, val_preds)
            tn, fp, fn, tp = cm.ravel()
            print(f"    الكشف الصحيح عن الهجمات (TP): {tp:,}")
            print(f"    الهجمات الفائتة (FN): {fn:,}")
            print(f"    إنذارات كاذبة (FP): {fp:,}")
            print(f"    طبيعي صحيح (TN): {tn:,}")

            print(f"\n[*] (3/3) تدريب المعزز الاستباقي (Gradient Boosting 200 مرحلة)...")
            self.proactive_booster.fit(X_train, y_train)
            val_preds_boost = self.proactive_booster.predict(X_val)
            print("    ✓ اكتمل")
            print("\n--- تقرير دقة Gradient Boosting ---")
            print(classification_report(y_val, val_preds_boost, target_names=["طبيعي", "هجوم"]))

        self.is_trained = True
        self.save_model()
        print("\n[✓] تم حفظ النموذج المحسّن بنجاح في:", MODEL_DIR / "hybrid_model.pkl")

    def predict(self, X):
        """التنبؤ الاستباقي بالتهديدات"""
        if not self.is_trained:
            self.load_model()

        X_scaled = self.scaler.transform(X)

        # كشف الشذوذ: -1 يعني شذوذ
        anomaly_scores = self.anomaly_detector.predict(X_scaled)

        # تصنيف الهجمات المعروفة
        class_preds = self.classifier.predict(X_scaled)

        # التنبؤ الاستباقي (الاحتمالي)
        if hasattr(self.proactive_booster, "predict_proba"):
            proactive_probs = self.proactive_booster.predict_proba(X_scaled)[:, 1]
        else:
            proactive_probs = np.zeros(len(X))

        # دمج النتائج: يُعتبر هجوماً إذا:
        # - رصدها Isolation Forest كشذوذ
        # - أو صنفها Random Forest كهجوم
        # - أو كانت احتمالية Gradient Boosting > 0.55
        final_preds = np.where(
            (anomaly_scores == -1) |
            (class_preds == 1) |
            (proactive_probs > 0.55),
            1, 0
        )

        return final_preds

    def predict_proba(self, X):
        """إرجاع درجة الخطورة كاحتمالية"""
        if not self.is_trained:
            self.load_model()
        X_scaled = self.scaler.transform(X)
        if hasattr(self.proactive_booster, "predict_proba"):
            return self.proactive_booster.predict_proba(X_scaled)[:, 1]
        return np.zeros(len(X))

    def save_model(self):
        with open(MODEL_DIR / "hybrid_model.pkl", "wb") as f:
            pickle.dump({
                "anomaly": self.anomaly_detector,
                "classifier": self.classifier,
                "booster": self.proactive_booster,
                "scaler": self.scaler,
                "is_trained": self.is_trained,
                "feature_importances": self.feature_importances_
            }, f)

    def load_model(self):
        model_path = MODEL_DIR / "hybrid_model.pkl"
        if model_path.exists():
            with open(model_path, "rb") as f:
                data = pickle.load(f)
                self.anomaly_detector = data["anomaly"]
                self.classifier = data["classifier"]
                self.proactive_booster = data.get("booster", self.proactive_booster)
                self.scaler = data["scaler"]
                self.is_trained = data["is_trained"]
                self.feature_importances_ = data.get("feature_importances")
        else:
            print("[!] ملف النموذج غير موجود. يرجى التدريب أولاً.")
