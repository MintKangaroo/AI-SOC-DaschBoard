# CLAUDE.md — SOC 대시보드 프로젝트 컨텍스트

## 프로젝트 개요

Flask 기반 실시간 보안관제(SOC) 대시보드.  
Claude AI(claude-sonnet-4-6)를 통합하여 보안 이벤트를 자동 분석하고 대응 권고를 제공합니다.

## 기술 스택

- **백엔드**: Flask 3.x, Flask-SocketIO (threading 모드), Flask-CORS
- **AI**: Anthropic SDK (claude-sonnet-4-6), 비동기 큐 기반 분석
- **패킷 분석**: PyShark (캡처), Scapy (패킷 조작), 데모 fallback 포함
- **로그 분석**: win32evtlog (Sysmon), 데모 fallback 포함
- **해시**: hashlib (MD5, SHA1, SHA256, SHA512)
- **지도**: Leaflet.js + ip-api.com GeoIP
- **프론트**: Bootstrap 5, Chart.js, DataTables, Socket.IO

## 코드 작성 규칙

- 모든 모듈은 **데모 fallback** 필수 — 실제 환경(Npcap, Sysmon 등) 없이도 실행 가능해야 함
- SocketIO emit은 항상 **threading-safe** (deque, Lock 사용)
- 각 모듈은 독립적: `start()` / `stop()` / `get_*()` 인터페이스 유지
- 외부 시스템 연동 패널은 `/api/integrations/{system}` 엔드포인트 규칙 따름
- 프론트엔드 차트 갱신은 `animation: false` — 실시간 성능 우선

## 주요 파일

| 파일 | 역할 |
|------|------|
| `app.py` | Flask 앱 팩토리, 서비스 초기화, SocketIO 이벤트 |
| `config.py` | 환경변수 기반 설정 (python-dotenv) |
| `modules/packet_analyzer.py` | PyShark/Scapy 패킷 캡처, 통계, SocketIO emit |
| `modules/threat_detector.py` | DDoS/포트스캔/악성코드 탐지, Alert 객체 관리 |
| `modules/hash_checker.py` | 해시 계산 + 악성 DB 비교 |
| `modules/sysmon_parser.py` | Windows Sysmon 이벤트 파싱 |
| `modules/ai_analyst.py` | Claude API 연동, 비동기 분석 큐, 챗봇 |
| `modules/ml_analyst.py` | 자체 AI 모델(IF/RF/LSTM/Q-Learning) 분석·학습·피드백 |
| `modules/mitre_attack.py` | MITRE ATT&CK 14 Tactic × Technique 매핑 및 카운트 |
| `modules/geoip.py` | 공격 IP GeoIP 조회, 공격 지도 스트림 |
| `api/routes.py` | API 라우트 집계자 (도메인 파일 임포트만) |
| `api/_common.py` | 공용 헬퍼 (`api_bp`, `get_services`, `_mitre`) |
| `api/{detection,analysis,monitoring,scan,response}_routes.py` | 도메인별 REST 엔드포인트 (모두 `api_bp` 공유) |
| `templates/dashboard.html` | 레이아웃·사이드바 (패널은 `templates/panels/*.html` include) |
| `templates/panels/*.html` | 패널별 UI 조각 (Jinja include) |
| `static/js/dash/01~10-*.js` | 패널별 JS (원본 순서대로 `<script>` 로드) |

## 외부 시스템 연동 확장 방법

새 시스템(예: 방화벽) 연동 시:

1. `modules/` 에 새 파서 모듈 추가 (`start()`, `stop()`, `get_events()` 구현)
2. `app.py` 에서 서비스 초기화 및 `app.{name}` 등록
3. 알맞은 `api/{도메인}_routes.py` 에 `/api/integrations/{name}` 엔드포인트 추가
4. `templates/panels/{name}.html` 패널 추가 + `dashboard.html` 에 `{% include %}` 및 사이드바 링크
5. `static/js/dash/` 에 패널 JS 추가(스크립트 태그 등록) + `showPanel()` 훅에 `load{Name}()` 연결
6. 모듈 헬스에 표시하려면 `modules/system_health.py` 의 `SPECS` 에 한 줄 추가

## AI 분석 흐름

```
위협 탐지 → Alert 생성 → SocketIO emit("new_alert")
  → JS에서 CRITICAL/HIGH면 socket.emit("request_ai_analysis")
  → ai_analyst._do_analyze_alert() → Claude API 호출
  → SocketIO emit("ai_analysis") → UI 업데이트
```

## 자체 ML 분석 흐름

```
packet_analyzer.get_stats() → ml_analyst.feed_traffic() (3초 주기)
  → analyze_now(): IF + RF + LSTM + Q-Learning 병렬 실행
  → SocketIO emit("ml_analysis") → ML 패널 차트 갱신
  → 사용자 피드백 (FP 버튼) → Q-Learning 보상 → 임계값 자동 튜닝
```

## MITRE ATT&CK 매핑 흐름

```
threat_detector._add_alert()   → mitre_tracker.map_threat(threat_type, ...)
sysmon_parser._record_event()  → mitre_tracker.map_sysmon_event(event_id, ...)
  → hits[(tactic, technique)] += 1
  → SocketIO emit("mitre_hit") → 매트릭스 셀 실시간 강조(hit-low/med/high)
```

## 환경 변수 (.env)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `ANTHROPIC_API_KEY` | - | Claude AI API 키 |
| `DEMO_MODE` | True | 가상 데이터 사용 여부 |
| `CAPTURE_INTERFACE` | 자동 | 패킷 캡처 인터페이스 |
| `DDOS_PACKET_THRESHOLD` | 1000 | DDoS 탐지 임계값(pps) |
| `PORT_SCAN_THRESHOLD` | 20 | 포트스캔 탐지 임계값(포트/초) |
