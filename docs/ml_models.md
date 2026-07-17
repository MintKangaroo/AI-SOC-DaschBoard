# 자체 구축 AI 모델

Claude API 없이 **직접 훈련한 4종 모델**로 실시간 이상탐지·위협분류·시계열 이상·적응형 임계값 조정을 수행합니다.

## 모델 스택

| # | 모델 | 종류 | 라이브러리 | 역할 |
|---|---|---|---|---|
| 1 | Isolation Forest | 비지도 이상탐지 | scikit-learn | 정상 트래픽 프로파일과의 이격도 점수 |
| 2 | Random Forest | 지도 분류 | scikit-learn | 6개 클래스 (NORMAL / DDOS / PORT_SCAN / BRUTE_FORCE / DATA_EXFIL / MALWARE_C2) |
| 3 | LSTM Autoencoder | 딥러닝 시계열 | TensorFlow/Keras | 30초 슬라이딩 윈도우 재구성 오차 |
| 4 | Q-Learning | 강화학습 | 자체 구현 | 오탐 피드백 기반 임계값 배율 튜닝 |

## 입력 피처

`FEATURE_NAMES` (총 8개):

- `pps`: 초당 패킷 수
- `bps`: 초당 바이트 수
- `tcp_ratio` / `udp_ratio` / `icmp_ratio`: 프로토콜 비율
- `unique_src`: 고유 출발지 IP 수
- `unique_dst_port`: 고유 목적지 포트 수
- `avg_pkt_size`: 평균 패킷 크기

## 학습

- 앱 시작 시 `packet_analyzer.get_stats()` 값을 3초 주기로 모델에 공급
- 시드 데이터(합성) 1000개 × 6클래스로 초기 fit
- 모델은 `data/models/` 아래에 저장:
  - `isolation_forest.pkl`
  - `random_forest.pkl`
  - `lstm_autoencoder.keras`
  - `q_table.pkl`

## 강화학습 세부

`ThresholdQLearner`:

- **상태**: 27개 (최근 오탐율 × 최근 알림량 × 현재 임계값)
- **행동**: 3개 (임계값 배율 감소 / 유지 / 증가)
- **보상**:
  - 정탐(TP) → `+5`
  - 오탐(FP) → `-3`
  - 과다 알림 → `-10`
- **정책**: ε-탐욕 (초기 ε=0.3 → 감쇠)

## API 엔드포인트

- `GET /api/ml/status` — 모델 상태 + RL 임계값
- `POST /api/ml/analyze` — 수동 분석 트리거
- `GET /api/ml/log?limit=20` — 분석 로그
- `POST /api/ml/feedback` — `{is_false_positive: bool}` 피드백 제출

## UI 연동

`ML 분석` 패널:

- Random Forest 확률 분포 (막대)
- LSTM 재구성 오차 + 임계값 (라인)
- Isolation Forest 점수 이력 (라인)
- Q-Learning 임계값 배율 이력 (라인) + ε, 마지막 행동 표시
- 사용자 피드백 버튼 (`정탐` / `오탐`)

## 데모 fallback

scikit-learn 또는 TensorFlow가 설치되어 있지 않아도 앱은 동작하며,
해당 모델은 "unavailable"로 표시되고 나머지 모델만 활성화됩니다.
