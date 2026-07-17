# 모듈 상세 설명

모든 모듈은 `modules/` 아래 있으며 `start()` / `stop()` / `get_*()` 인터페이스와 **데모 fallback**을 갖는다.
SocketIO emit은 `deque`·`Lock`으로 스레드 안전하게 처리한다.

## ① 수집 · SIEM

| 모듈 | 클래스 | 역할 | 핵심 이벤트/API |
|------|--------|------|-----------------|
| `packet_analyzer` | PacketAnalyzer | PyShark/Scapy 패킷 캡처, pps/bps·Top Talkers 통계 | `packet_update` |
| `sysmon_parser` | SysmonParser | Windows Sysmon 이벤트 파싱, Metasploit 탐지 | `sysmon_update` · `sysmon_alert` |
| `access_log_parser` | AccessLogCollector | 자동매매 봇 access log 수집·정규화, 침해 프로브 분류 | `classify_request()` |
| `authlog_parser` | AuthLogMonitor | `/var/log/auth.log` tail, SSH 브루트포스 탐지 | `report_alert("BRUTE_FORCE")` |
| `net_monitor` | NetworkMonitor | psutil 활성 연결·리스닝 포트·대역폭, 서비스 헬스체크 | `net_event` · `net_status` |

## ② 탐지 · Detection Engineering

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `threat_detector` | ThreatDetector | DDoS·포트스캔·C2 탐지, **신뢰도 스코어링**, Alert 관리 | `_confidence()` · `analyze_packet()` · `report_alert()` |
| `sigma_engine` | SigmaEngine | Sigma 표준 룰 로드·평가(field 수정자·condition 파서) | `sigma_match`, 룰 파일 추가로 확장 |
| `edr` | EDRSensor | psutil 프로세스 IOA(리버스셸·웹셸·마이너·스캐너), 안전 종료 | `edr_detection` · `kill_process()`(simulate 기본) |
| `hash_checker` | HashChecker | MD5/SHA256 악성 DB 대조, EICAR | `scan_file()` |
| `mitre_attack` | MitreTracker | 위협·Sysmon → 14 Tactic × Technique 매핑 | `map_threat()` · `mitre_hit` |

## ③ 위협 인텔 · 분석

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `ip_reputation` | IPReputation | AbuseIPDB 조회(캐시·데모 fallback), 정탐 근거 강화 | `check(ip)`, 사설/자기IP 제외 |
| `threat_intel` | ThreatIntel | 악성 IP/URL 피드 관리·매칭 | `_parse_ip_list()` |
| `ml_analyst` | MLAnalyst | IF·RF·LSTM·Q-Learning 병렬 분석·학습·피드백 | `ml_analysis`, FP 피드백→임계값 튜닝 |
| `ai_analyst` | AIAnalyst | Claude 비동기 분석 큐·대응 권고·챗봇·리포트 텍스트 | `ai_analysis` · `generate_text()` |
| `decision_support` | DecisionSupport | 위협 그룹핑 + 정오탐 학습 prior | `get_recommendations()` |

## ④ 대응 · SOAR

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `soar` | SOAREngine | AI 트리아지(정탐 에스컬레이션/오탐 종결), 자동 차단, TTL·allowlist | `soar_action`, `_is_blockable()` 안전장치 |
| `incidents` | IncidentManager | 알림 케이스화·상태 추적 | `get_incidents()` |
| `notifier` | Notifier | ntfy 푸시(정탐·차단만, 쿨다운) | `notify_true_positive()` · `notify_block()` |
| `daily_report` | DailyReport | 전 모듈 지표 집계 → Claude 브리핑(규칙 fallback) | `report_status` |

## ⑤ 취약점 관리 · 검증

| 모듈 | 클래스 | 역할 | 핵심 |
|------|--------|------|------|
| `vuln_scanner` | VulnScanner | 포트·서비스·CVE 스캔(nmap/vulners·소켓), **apt 교차검증** | `vulnscan_host`, `_cross_validate()`, 원격은 ansible |
| `web_fuzzer` | WebFuzzer | 엔드포인트 견고성 퍼징(5xx·행·입력반사) | `fuzz_finding`, 사설 대상만·GET 전용·rate-limit |
| `patch_manager` | PatchManager | 다중 서버 Ansible 일괄 명령/패치, dry-run 기본 | `patch_job`, 파괴적 명령 blocklist |
| `purple_team` | PurpleTeam | 7종 모의공격을 실제 탐지엔진에 주입해 커버리지 검증 | `run_all()`, RFC5737 TEST-NET 출발지 |

## 플랫폼

| 모듈 | 클래스 | 역할 |
|------|--------|------|
| `auth` | AuthManager | 로그인(pbkdf2), IP별 브루트포스 락아웃, 세션 |
| `geoip` | AttackMapTracker | GeoIP 조회, 공격 지도 스트림(`map_attack`) |
| `alert_store` | AlertStore | 알림 영속화·조회 |
| `system_info` | — | 호스트/인터페이스 정보 |

## 확장 방법 (새 시스템 연동)

1. `modules/` 에 새 파서 모듈 추가 — `start()`·`stop()`·`get_*()` 구현 + 데모 fallback
2. `app.py` 에서 초기화 후 `app.<name>` 등록, `<name>.start(demo=demo)` 호출
3. `api/routes.py` 에 `/api/...` 엔드포인트 추가
4. `templates/dashboard.html` 에 사이드바 링크 + 패널 추가
5. `static/js/dashboard.js` 에 `socket.on(...)` 수신 + 렌더 함수, 패널 switch에 `load<Name>()` 배선
6. `tests/` 에 파싱·판정·안전장치 단위 테스트 추가 (네트워크·외부실행 없이)
