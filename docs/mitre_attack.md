# MITRE ATT&CK 매트릭스 매핑

SOC 대시보드는 탐지된 모든 이벤트를 **MITRE ATT&CK Enterprise Matrix**의 14개 Tactic과 주요 Technique에 자동 매핑합니다.

## 구조

- **Tactic**: 공격자의 의도(Why). 14개 (정찰 → 영향)
- **Technique**: 그 의도를 달성하기 위한 방법(How).

```
Reconnaissance → Resource Development → Initial Access → Execution
  → Persistence → Privilege Escalation → Defense Evasion
  → Credential Access → Discovery → Lateral Movement → Collection
  → Command & Control → Exfiltration → Impact
```

## 매핑 대상

### 1. 위협 탐지 (`threat_detector`)

| threat_type | Tactic | Technique |
|---|---|---|
| `DDOS` | TA0040 Impact | T1498 Network DoS |
| `PORT_SCAN` | TA0043 Reconnaissance | T1046 Network Service Discovery |
| `PORT_SCAN` | TA0007 Discovery | T1018 Remote System Discovery |
| `BRUTE_FORCE` | TA0006 Credential Access | T1110 Brute Force |
| `MALWARE_BEACON` | TA0011 C2 | T1071 / T1105 |
| `DATA_EXFIL` | TA0010 Exfiltration | T1048 / T1041 |
| `ARP_SPOOFING` | TA0008 Lateral Movement | T1021 |
| `DNS_TUNNELING` | TA0011 C2 | T1572 Protocol Tunneling |

### 2. Sysmon 이벤트 (`sysmon_parser`)

| Event ID | 의미 | Tactic / Technique |
|---|---|---|
| 1 | 프로세스 생성 | TA0002 / T1059 |
| 3 | 네트워크 연결 | TA0011 / T1071 |
| 6 | 드라이버 로드 | TA0005 / T1562 |
| 10 | 프로세스 접근 (lsass) | TA0006 / T1003 |
| 11 | 파일 생성 | TA0009 / T1005 |
| 12/13 | 레지스트리 | TA0003 / T1547 |
| 22 | DNS 쿼리 | TA0011 / T1071 |
| 25 | 프로세스 변조 | TA0005 / T1055 |

### 3. 의심 프로세스 키워드

프로세스명 또는 메시지에 아래 키워드가 포함되면 추가 매핑됩니다.

| 키워드 | 추가 매핑 |
|---|---|
| mimikatz, procdump | T1003 OS Credential Dumping |
| meterpreter, cobalt | T1071 Application Layer Protocol |
| psexec | T1021 Remote Services |
| powershell, empire | T1059 Command/Scripting |

## 구현

- **`modules/mitre_attack.py`**: `MitreTracker` 클래스
  - `map_threat(threat_type, src_ip, dst_ip, description)`
  - `map_sysmon_event(event_id, process, message)`
  - `get_matrix()` · `get_recent()` · `get_top_techniques()`
  - SocketIO `mitre_hit` 이벤트 emit

## API 엔드포인트

- `GET /api/mitre/matrix` — 전체 매트릭스 + 셀별 카운트
- `GET /api/mitre/recent?limit=50` — 최근 매핑 이벤트
- `GET /api/mitre/top?top=10` — 가장 많이 탐지된 Technique

## UI 렌더링

대시보드 `MITRE ATT&CK` 패널 (`#panel-mitre`):

- **14개 열 그리드**: Tactic별 Technique 카드 세로 배치
- **강조 등급**:
  - `hit-low` (1-2건): 붉은 테두리
  - `hit-med` (3-9건): 붉은 배경
  - `hit-high` (10+건): 강한 빨강 + `pulseRed` 애니메이션
- **실시간 갱신**: `mitre_hit` SocketIO 이벤트로 해당 셀이 `hit-flash` 애니메이션 후 카운트 증가

## 확장

새 탐지 유형을 추가할 때 `THREAT_MAPPING` 딕셔너리에 한 줄 추가하면 됩니다.

```python
THREAT_MAPPING["RANSOMWARE"] = [("TA0040", "T1486")]
```
