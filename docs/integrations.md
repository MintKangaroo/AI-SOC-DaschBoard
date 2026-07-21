# 외부 시스템 연동 가이드

## VirusTotal

`VIRUSTOTAL_API_KEY`를 설정하면 SOAR의 `PB-MALWARE-ENRICH` 플레이북이
악성코드·EDR·Sigma 알림에서 MD5/SHA1/SHA256을 추출해 VirusTotal API v3의
기존 파일 리포트를 조회한다.

- `x-apikey` 헤더로 인증해 `GET /api/v3/files/{hash}`를 호출한다.
- 파일은 업로드하지 않으며 조회 결과는 기본 6시간 캐시한다.
- 네트워크/API 오류로 실행이 실패하면 대시보드의 `실패 단계 재시도` 버튼 또는
  `POST /api/soar/executions/{id}/retry`로 해시 조회부터 다시 실행할 수 있다.
- 완료 이력은 `data/soar_executions.db`에 저장되며 재시작 후 최근 100건을
  복원한다. 재시도 실행에는 원본 ID(`retry_of`)와 시도 횟수(`attempt`)가 남는다.
- 차단·트리아지처럼 부작용이 있는 플레이북은 중복 대응 방지를 위해 이 재시도
  API의 대상이 아니다.

### SOAR 차단 승인 게이트

기본 설정에서는 자동·수동 IP 차단이 즉시 실행되지 않고 `PB-BLOCK-APPROVAL`
실행으로 전환된다. AI 관제 센터의 승인 큐 또는 SOAR 상세 탭에서 승인·거절·
취소할 수 있으며, 승인한 로그인 사용자와 사유·시각은 실행 이력과 감사 로그에
남는다. 승인 요청은 기본 15분 후 만료된다.

```dotenv
SOAR_APPROVAL_REQUIRED=True
SOAR_APPROVAL_TIMEOUT_MINUTES=15
```

API에서는 `POST /api/soar/executions/{id}/approval`에
`{"decision":"approve|reject|cancel", "reason":"..."}`를 전송한다. 승인된
경우에만 방화벽 실행 경로로 진입하며 안전 목록 검사는 승인 요청 전에도 적용된다.
- API 키 또는 해시가 없으면 단계가 `건너뜀`으로 표시되고 기존 트리아지는 계속된다.
- SOAR 실행 현황에서 대기·진행·완료·건너뜀·실패 상태를 실시간 확인한다.
- SOAR의 `EICAR 연결 테스트` 버튼은 안전한 테스트 해시로 인증·응답 파싱을 검증한다.
- 조회 결과는 알림 상세에 영속 저장되고 정탐 인시던트 승격 시 타임라인에도 기록된다.

---

현재 대시보드에는 다음 시스템의 빈 패널이 준비되어 있습니다.  
아래 가이드에 따라 실제 데이터를 연결할 수 있습니다.

---

## 방화벽 연동

### 지원 예정 시스템
- Palo Alto Networks (PAN-OS)
- Fortinet FortiGate
- Cisco ASA / Firepower
- pfSense / OPNsense

### 연동 방법 (Syslog)

```python
# modules/firewall_parser.py 생성 예시
import socket

class FirewallParser:
    def start_syslog_listener(self, port=514):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))
        # UDP Syslog 수신 루프
        while self.running:
            data, addr = sock.recvfrom(65535)
            self._parse_syslog(data.decode('utf-8', errors='ignore'))
```

### API 엔드포인트

```
POST /api/integrations/firewall
Content-Type: application/json

{
  "src_ip": "203.0.113.1",
  "dst_ip": "192.168.1.10",
  "dst_port": 443,
  "action": "DENY",
  "rule": "block-external-ssh",
  "timestamp": "2024-01-15T14:30:25Z"
}
```

---

## IPS/IDS 연동

### 지원 예정 시스템
- Snort 3
- Suricata
- Zeek (Bro)

### Suricata EVE JSON 파싱

```python
# Suricata의 eve.json 파일 tail
import json, time

def tail_eve_json(path="/var/log/suricata/eve.json"):
    with open(path, 'r') as f:
        f.seek(0, 2)  # 파일 끝으로
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            event = json.loads(line)
            if event.get('event_type') == 'alert':
                yield event
```

---

## 백신 서버 연동

### AhnLab V3 (API 예시)

```python
import requests

class AntivirusConnector:
    def __init__(self, server_url, api_key):
        self.base = server_url
        self.headers = {"X-API-Key": api_key}

    def get_detections(self, since=None):
        r = requests.get(
            f"{self.base}/api/v1/detections",
            headers=self.headers,
            params={"since": since}
        )
        return r.json()
```

---

## EDR 연동

### CrowdStrike Falcon API

```python
from falconpy import EventStreams

class EDRConnector:
    def stream_events(self, api_key, api_secret):
        falcon = EventStreams(
            client_id=api_key,
            client_secret=api_secret
        )
        # 실시간 탐지 이벤트 스트리밍
```

---

## SIEM 연동

### Elastic SIEM

```python
from elasticsearch import Elasticsearch

class SIEMConnector:
    def __init__(self, hosts):
        self.es = Elasticsearch(hosts)

    def query_alerts(self, index="siem-signals-*"):
        return self.es.search(
            index=index,
            body={"query": {"match_all": {}}, "size": 100}
        )
```

### Splunk REST API

```bash
curl -k -u admin:password \
  https://splunk-server:8089/services/search/jobs \
  -d "search=search index=security earliest=-1h"
```

---

## 연동 패널 활성화 방법

1. `modules/` 에 파서 모듈 생성 (`start()`, `stop()`, `get_events()` 구현)
2. `app.py` 에 서비스 등록:
   ```python
   from modules.firewall_parser import FirewallParser
   app.firewall = FirewallParser(socketio)
   app.firewall.start()
   ```
3. `api/routes.py` 에 엔드포인트 추가
4. `templates/dashboard.html` 의 빈 패널 교체:
   - `panel-firewall` 안의 `.empty-panel` 을 실제 테이블로 교체
5. `static/js/dashboard.js` 에 SocketIO 이벤트 핸들러 추가
