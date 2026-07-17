"""
ML 보안 분석 모듈 — 자체 AI 모델
─────────────────────────────────
1. Isolation Forest   → 트래픽 이상 탐지 (비지도 학습)
2. Random Forest      → 공격 유형 분류  (지도 학습)
3. LSTM Autoencoder   → 시계열 재구성 오차 기반 딥러닝 탐지
4. Q-Learning Agent   → 탐지 임계값 자동 최적화 (강화학습)
"""
import threading
import time
import random
import json
import os
import numpy as np
from collections import deque
from datetime import datetime

# ── scikit-learn ──
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

# ── TensorFlow / Keras ──
try:
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

# ─────────────────────────────────────────
#  Feature 정의 (8개 수치형 피처)
# ─────────────────────────────────────────
FEATURE_NAMES = [
    "pps",           # 패킷/초
    "bps",           # 바이트/초
    "tcp_ratio",     # TCP 비율
    "udp_ratio",     # UDP 비율
    "icmp_ratio",    # ICMP 비율
    "unique_src",    # 고유 출발지 IP 수
    "unique_dst_port",  # 고유 목적지 포트 수
    "avg_pkt_size",  # 평균 패킷 크기
]

THREAT_LABELS = {
    0: "NORMAL",
    1: "DDOS",
    2: "PORT_SCAN",
    3: "BRUTE_FORCE",
    4: "DATA_EXFIL",
    5: "MALWARE_C2",
}

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "models")


# ─────────────────────────────────────────
#  합성 학습 데이터 생성
# ─────────────────────────────────────────

def _generate_training_data():
    """공격 유형별 합성 데이터 생성 (각 클래스 200샘플)"""
    rng = np.random.RandomState(42)
    X, y = [], []

    # 0: NORMAL
    for _ in range(200):
        X.append([
            rng.uniform(10, 300),      # pps
            rng.uniform(5000, 500000), # bps
            rng.uniform(0.5, 0.8),     # tcp_ratio
            rng.uniform(0.1, 0.35),    # udp_ratio
            rng.uniform(0.01, 0.05),   # icmp_ratio
            rng.randint(1, 20),        # unique_src
            rng.randint(1, 15),        # unique_dst_port
            rng.uniform(200, 1200),    # avg_pkt_size
        ])
        y.append(0)

    # 1: DDoS — pps 급증, icmp/udp 증가
    for _ in range(200):
        X.append([
            rng.uniform(5000, 50000),
            rng.uniform(5e6, 1e8),
            rng.uniform(0.05, 0.3),
            rng.uniform(0.4, 0.8),
            rng.uniform(0.1, 0.5),
            rng.randint(5, 30),
            rng.randint(1, 5),
            rng.uniform(40, 100),
        ])
        y.append(1)

    # 2: PORT_SCAN — unique_dst_port 급증
    for _ in range(200):
        X.append([
            rng.uniform(50, 500),
            rng.uniform(50000, 300000),
            rng.uniform(0.85, 1.0),
            rng.uniform(0, 0.05),
            rng.uniform(0, 0.02),
            rng.randint(1, 5),
            rng.randint(80, 1024),
            rng.uniform(40, 80),
        ])
        y.append(2)

    # 3: BRUTE_FORCE — 중간 pps, 특정 포트 반복
    for _ in range(200):
        X.append([
            rng.uniform(100, 1000),
            rng.uniform(100000, 1000000),
            rng.uniform(0.9, 1.0),
            rng.uniform(0, 0.05),
            rng.uniform(0, 0.01),
            rng.randint(1, 3),
            rng.randint(1, 3),
            rng.uniform(60, 200),
        ])
        y.append(3)

    # 4: DATA_EXFIL — bps 급증, 높은 평균 패킷 크기
    for _ in range(200):
        X.append([
            rng.uniform(100, 2000),
            rng.uniform(5e6, 5e8),
            rng.uniform(0.6, 0.9),
            rng.uniform(0.05, 0.2),
            rng.uniform(0, 0.02),
            rng.randint(1, 5),
            rng.randint(1, 4),
            rng.uniform(1000, 1500),
        ])
        y.append(4)

    # 5: MALWARE_C2 — 낮은 pps, 주기적 beacon
    for _ in range(200):
        X.append([
            rng.uniform(1, 30),
            rng.uniform(500, 50000),
            rng.uniform(0.7, 1.0),
            rng.uniform(0, 0.1),
            rng.uniform(0, 0.05),
            rng.randint(1, 3),
            rng.randint(1, 3),
            rng.uniform(60, 300),
        ])
        y.append(5)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


# ─────────────────────────────────────────
#  LSTM Autoencoder 정의
# ─────────────────────────────────────────

def _build_lstm_autoencoder(seq_len=30, n_features=8):
    if not TF_AVAILABLE:
        return None
    inp = keras.Input(shape=(seq_len, n_features))
    # Encoder
    x = layers.LSTM(64, return_sequences=True)(inp)
    x = layers.LSTM(32)(x)
    encoded = layers.Dense(16, activation="relu")(x)
    # Decoder
    x = layers.RepeatVector(seq_len)(encoded)
    x = layers.LSTM(32, return_sequences=True)(x)
    x = layers.LSTM(64, return_sequences=True)(x)
    decoded = layers.TimeDistributed(layers.Dense(n_features))(x)

    model = keras.Model(inp, decoded)
    model.compile(optimizer="adam", loss="mse")
    return model


# ─────────────────────────────────────────
#  Q-Learning Agent (임계값 최적화)
# ─────────────────────────────────────────

class ThresholdQLearner:
    """
    상태: (트래픽 수준 0~2, 알림 빈도 0~2, 오탐 의심 0~1)  → 27가지 상태
    행동: 0=임계값 낮춤(-10%), 1=유지, 2=임계값 높임(+10%)
    보상: 탐지 성공 +5, 오탐 -3, 미탐지 -10
    """
    STATE_BINS = 3
    N_ACTIONS = 3

    def __init__(self, lr=0.1, gamma=0.9, epsilon=0.3):
        self.lr = lr
        self.gamma = gamma
        self.epsilon = epsilon
        self.q_table = np.zeros((self.STATE_BINS ** 3, self.N_ACTIONS))
        self.threshold_multiplier = 1.0  # 현재 임계값 배율
        self.history = deque(maxlen=200)
        self._step = 0

    def _state_index(self, pps, alert_rate, fp_rate):
        t = min(int(pps / 500), 2)
        a = min(int(alert_rate / 5), 2)
        f = 1 if fp_rate > 0.4 else 0
        return t * 9 + a * 3 + f

    def act(self, pps, alert_rate, fp_rate):
        state = self._state_index(pps, alert_rate, fp_rate)
        if random.random() < self.epsilon:
            return random.randint(0, self.N_ACTIONS - 1)
        return int(np.argmax(self.q_table[state]))

    def update(self, pps, alert_rate, fp_rate, action, reward, next_pps, next_ar, next_fp):
        s  = self._state_index(pps, alert_rate, fp_rate)
        ns = self._state_index(next_pps, next_ar, next_fp)
        td = reward + self.gamma * np.max(self.q_table[ns]) - self.q_table[s, action]
        self.q_table[s, action] += self.lr * td
        self.epsilon = max(0.05, self.epsilon * 0.9995)
        self._step += 1

    def apply_action(self, action):
        if action == 0:
            self.threshold_multiplier = max(0.3, self.threshold_multiplier * 0.9)
        elif action == 2:
            self.threshold_multiplier = min(3.0, self.threshold_multiplier * 1.1)
        return self.threshold_multiplier

    def get_status(self):
        return {
            "threshold_multiplier": round(self.threshold_multiplier, 3),
            "epsilon": round(self.epsilon, 4),
            "steps": self._step,
            "q_table_max": float(np.max(self.q_table)),
        }


# ─────────────────────────────────────────
#  메인 ML 분석기
# ─────────────────────────────────────────

class MLAnalyst:

    WINDOW = 30   # LSTM 시퀀스 길이

    def __init__(self, socketio):
        self.socketio = socketio
        self.running = False
        self._lock = threading.Lock()

        # 피처 버퍼 (슬라이딩 윈도우)
        self._feature_buffer = deque(maxlen=self.WINDOW * 2)
        self._seq_buffer     = deque(maxlen=self.WINDOW)

        # 모델
        self.iso_forest:   IsolationForest       = None
        self.rf_classifier: RandomForestClassifier = None
        self.scaler:        StandardScaler        = None
        self.lstm_model                           = None
        self.rl_agent       = ThresholdQLearner()

        # 통계
        self.stats = {
            "if_anomalies":   0,
            "rf_predictions": {},
            "lstm_anomalies": 0,
            "rl_steps":       0,
            "model_status":   "초기화 중...",
            "training_done":  False,
        }
        self.analysis_log = deque(maxlen=100)

        # RL 상태 추적
        self._prev_obs        = None  # (pps, alert_rate, fp_rate, action)
        self._prev_alert_rate = 0.0
        self._prev_fp_rate    = 0.0
        self._alert_window    = deque(maxlen=30)
        self._fp_window       = deque(maxlen=30)

        os.makedirs(MODEL_DIR, exist_ok=True)

    # ──────────────────── 공개 API ────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._init_models, daemon=True).start()

    def stop(self):
        self.running = False

    def feed_traffic(self, stats: dict):
        """PacketAnalyzer 통계를 피처로 변환해 모델에 입력"""
        feat = self._extract_features(stats)
        with self._lock:
            self._feature_buffer.append(feat)
            self._seq_buffer.append(feat)
        return feat

    def analyze_now(self, stats: dict) -> dict:
        """동기 분석 — REST API 호출용"""
        feat = self._extract_features(stats)
        return self._run_all_models(feat)

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)

    def get_log(self, limit=20) -> list:
        with self._lock:
            return list(self.analysis_log)[-limit:]

    def get_rl_status(self) -> dict:
        return self.rl_agent.get_status()

    def mark_alert(self, is_fp=False):
        """알림 발생 or 오탐 피드백을 RL에 전달"""
        self._alert_window.append(1)
        if is_fp:
            self._fp_window.append(1)
        else:
            self._fp_window.append(0)

    # ──────────────────── 초기화 / 학습 ────────────────────

    def _init_models(self):
        """앱 시작 시 백그라운드에서 모델 학습"""
        with self._lock:
            self.stats["model_status"] = "학습 중..."

        try:
            self._train_isolation_forest()
            self._train_random_forest()
            if TF_AVAILABLE:
                self._train_lstm_autoencoder()
            with self._lock:
                self.stats["model_status"] = "정상 운영"
                self.stats["training_done"] = True
            self.socketio.emit("ml_model_ready", {
                "message": "ML 모델 학습 완료",
                "models": ["Isolation Forest", "Random Forest"] + (["LSTM Autoencoder"] if TF_AVAILABLE else []),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })
        except Exception as e:
            with self._lock:
                self.stats["model_status"] = f"오류: {e}"
            print(f"[MLAnalyst] 모델 초기화 오류: {e}")
            return

        # 메인 분석 루프 시작
        threading.Thread(target=self._analysis_loop, daemon=True).start()

    def _train_isolation_forest(self):
        model_path = os.path.join(MODEL_DIR, "iso_forest.pkl")
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.iso_forest = joblib.load(model_path)
                self.scaler     = joblib.load(scaler_path)
                return
            except Exception as e:
                # sklearn 버전 불일치 등으로 로드 실패 → 재학습
                print(f"[MLAnalyst] IF 모델 로드 실패({e}) — 재학습")

        X, _ = _generate_training_data()
        normal_X = X[0:200]  # 정상 트래픽만

        self.scaler     = StandardScaler().fit(normal_X)
        X_scaled        = self.scaler.transform(normal_X)
        self.iso_forest = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=42,
            n_jobs=-1,
        ).fit(X_scaled)

        joblib.dump(self.iso_forest, model_path)
        joblib.dump(self.scaler,     scaler_path)

    def _train_random_forest(self):
        model_path = os.path.join(MODEL_DIR, "rf_classifier.pkl")
        if os.path.exists(model_path):
            try:
                self.rf_classifier = joblib.load(model_path)
                return
            except Exception as e:
                print(f"[MLAnalyst] RF 모델 로드 실패({e}) — 재학습")

        X, y = _generate_training_data()
        X_scaled = self.scaler.transform(X)
        self.rf_classifier = RandomForestClassifier(
            n_estimators=300,
            max_depth=12,
            random_state=42,
            n_jobs=-1,
        ).fit(X_scaled, y)

        joblib.dump(self.rf_classifier, model_path)

    def _train_lstm_autoencoder(self):
        if not TF_AVAILABLE:
            return
        model_path = os.path.join(MODEL_DIR, "lstm_autoencoder.keras")
        if os.path.exists(model_path):
            try:
                self.lstm_model = keras.models.load_model(model_path)
                return
            except Exception:
                pass

        # 정상 트래픽 시퀀스 합성
        rng = np.random.RandomState(7)
        seqs = []
        for _ in range(400):
            seq = []
            for t in range(self.WINDOW):
                seq.append([
                    rng.uniform(10, 300),
                    rng.uniform(5000, 500000),
                    rng.uniform(0.5, 0.8),
                    rng.uniform(0.1, 0.35),
                    rng.uniform(0.01, 0.05),
                    rng.randint(1, 20),
                    rng.randint(1, 15),
                    rng.uniform(200, 1200),
                ])
            seqs.append(seq)

        seqs_np = np.array(seqs, dtype=np.float32)
        # 시퀀스별 정규화
        flat = seqs_np.reshape(-1, len(FEATURE_NAMES))
        self.scaler.fit(flat)  # 이미 fit 됐지만 재확인
        seqs_scaled = self.scaler.transform(flat).reshape(-1, self.WINDOW, len(FEATURE_NAMES))

        self.lstm_model = _build_lstm_autoencoder(self.WINDOW, len(FEATURE_NAMES))
        self.lstm_model.fit(
            seqs_scaled, seqs_scaled,
            epochs=15,
            batch_size=32,
            validation_split=0.1,
            verbose=0,
        )
        self.lstm_model.save(model_path)

    # ──────────────────── 분석 루프 ────────────────────

    def _analysis_loop(self):
        while self.running:
            time.sleep(3)
            with self._lock:
                if len(self._feature_buffer) < 5:
                    continue
                feat = list(self._feature_buffer)[-1]
                seq  = list(self._seq_buffer)

            result = self._run_all_models(feat, seq)

            # RL 업데이트: 직전 스텝의 (상태, 행동)에 대한 보상을 현재 상태로 평가
            pps   = feat[0]
            ar    = sum(self._alert_window) / max(len(self._alert_window), 1) * 10
            fp    = sum(self._fp_window)    / max(len(self._fp_window),    1)
            if self._prev_obs is not None:
                p_pps, p_ar, p_fp, p_action = self._prev_obs
                reward = self._compute_reward(result, p_action)
                self.rl_agent.update(p_pps, p_ar, p_fp, p_action, reward, pps, ar, fp)
            action = self.rl_agent.act(pps, ar, fp)
            new_mult = self.rl_agent.apply_action(action)
            self._prev_obs = (pps, ar, fp, action)

            result["rl"] = {
                "action": ["임계값 낮춤", "유지", "임계값 높임"][action],
                "threshold_multiplier": round(new_mult, 3),
                "epsilon": round(self.rl_agent.epsilon, 4),
            }

            with self._lock:
                self.analysis_log.append(result)
                self.stats["rl_steps"] += 1

            self.socketio.emit("ml_analysis", result)

    def _run_all_models(self, feat, seq=None) -> dict:
        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": dict(zip(FEATURE_NAMES, [round(float(v), 3) for v in feat])),
        }

        feat_arr = np.array(feat, dtype=np.float32).reshape(1, -1)

        # ── Isolation Forest ──
        if self.iso_forest and self.scaler:
            scaled  = self.scaler.transform(feat_arr)
            if_pred = self.iso_forest.predict(scaled)[0]         # 1=정상 -1=이상
            if_score = float(self.iso_forest.score_samples(scaled)[0])
            anomaly  = bool(if_pred == -1)
            if anomaly:
                with self._lock:
                    self.stats["if_anomalies"] += 1
            result["isolation_forest"] = {
                "anomaly":    anomaly,
                "score":      round(if_score, 4),
                "label":      "이상 탐지" if anomaly else "정상",
            }

        # ── Random Forest ──
        if self.rf_classifier and self.scaler:
            scaled   = self.scaler.transform(feat_arr)
            pred_cls = int(self.rf_classifier.predict(scaled)[0])
            proba    = self.rf_classifier.predict_proba(scaled)[0]
            label    = THREAT_LABELS.get(pred_cls, "UNKNOWN")
            conf     = float(np.max(proba))
            with self._lock:
                self.stats["rf_predictions"][label] = self.stats["rf_predictions"].get(label, 0) + 1
            result["random_forest"] = {
                "predicted_class": pred_cls,
                "label":           label,
                "confidence":      round(conf * 100, 1),
                "probabilities":   {THREAT_LABELS[i]: round(float(p) * 100, 1) for i, p in enumerate(proba)},
            }

        # ── LSTM Autoencoder ──
        if self.lstm_model and seq and len(seq) >= self.WINDOW:
            try:
                seq_np = np.array(seq[-self.WINDOW:], dtype=np.float32)
                seq_scaled = self.scaler.transform(seq_np).reshape(1, self.WINDOW, -1)
                reconstructed = self.lstm_model.predict(seq_scaled, verbose=0)
                mse = float(np.mean((seq_scaled - reconstructed) ** 2))
                threshold_base = 0.05
                threshold = threshold_base * self.rl_agent.threshold_multiplier
                lstm_anomaly = bool(mse > threshold)
                if lstm_anomaly:
                    with self._lock:
                        self.stats["lstm_anomalies"] += 1
                result["lstm"] = {
                    "reconstruction_error": round(mse, 6),
                    "threshold":            round(threshold, 6),
                    "anomaly":              lstm_anomaly,
                    "label":                "시계열 이상" if lstm_anomaly else "정상 패턴",
                }
            except Exception as e:
                result["lstm"] = {"error": str(e)}

        # ── 종합 판단 (FP 완화: 다중 모델 합의 필요) ──
        threats = []
        if_anomaly   = result.get("isolation_forest", {}).get("anomaly", False)
        lstm_anomaly = result.get("lstm", {}).get("anomaly", False)
        rf_label     = result.get("random_forest", {}).get("label", "NORMAL")
        rf_conf      = result.get("random_forest", {}).get("confidence", 0)

        # RF 신뢰도 80% 이상일 때만 위협으로 간주
        rf_hit = (rf_label != "NORMAL" and rf_conf >= 80)

        if if_anomaly:   threats.append("IF이상")
        if rf_hit:       threats.append(rf_label)
        if lstm_anomaly: threats.append("LSTM이상")

        # 최소 2개 모델이 합의해야 실제 위협 판정
        overall_severity = "NORMAL"
        if len(threats) >= 2:
            overall_severity = "HIGH"
            if "DDOS" in threats or "MALWARE_C2" in threats:
                overall_severity = "CRITICAL"
        elif len(threats) == 1:
            # 단일 모델만 탐지 시 LOW (주의 수준)
            overall_severity = "LOW"

        result["summary"] = {
            "severity":  overall_severity,
            "threats":   threats,
            "verdict":   "위협 탐지됨" if threats else "정상",
        }
        return result

    # ──────────────────── 피처 추출 ────────────────────

    @staticmethod
    def _extract_features(stats: dict) -> np.ndarray:
        total = max(stats.get("total_packets", 1), 1)
        tcp   = stats.get("tcp_packets",  0)
        udp   = stats.get("udp_packets",  0)
        icmp  = stats.get("icmp_packets", 0)
        byt   = max(stats.get("total_bytes", 1), 1)

        return np.array([
            float(stats.get("packets_per_sec", 0)),
            float(stats.get("bytes_per_sec",   0)),
            tcp  / total,
            udp  / total,
            icmp / total,
            float(stats.get("unique_src_ips", 1)),
            float(stats.get("unique_dst_ports", 1)),
            byt / total,
        ], dtype=np.float32)

    # ──────────────────── RL 보상 ────────────────────

    @staticmethod
    def _compute_reward(result, action) -> float:
        reward = 0.0
        threats = result.get("summary", {}).get("threats", [])
        if threats:
            reward += 5.0
            if action == 0:  # 임계값 낮춤 → 올바른 선택
                reward += 2.0
        else:
            if action == 2:  # 임계값 높임 → 오탐 방지
                reward += 1.0
            elif action == 0:  # 정상인데 임계값 낮춤 → 패널티
                reward -= 2.0
        return reward
