# 위협 탐지 규칙

## 현재 구현된 탐지 규칙

### 네트워크 기반 탐지

| 규칙 ID | 이름 | 조건 | 심각도 | 임계값 변경 |
|---------|------|------|--------|------------|
| NET-001 | DDoS SYN Flood | 동일 IP 1초 내 1,000+ pps | CRITICAL | `DDOS_PACKET_THRESHOLD` |
| NET-002 | 포트 스캔 | 동일 IP 1초 내 20+ 고유 포트 | HIGH | `PORT_SCAN_THRESHOLD` |
| NET-003 | 내부 자료 대량 유출 | 내부 IP가 비허용 외부 목적지로 기본 5분 내 500MB+ 전송 | HIGH/CRITICAL | `DATA_EXFIL_*` 설정 및 allowlist 지원 |
| NET-004 | ARP 스푸핑 | 게이트웨이 MAC 위장 | MEDIUM | - |
| NET-005 | DNS 터널링 | 비정상 DNS 쿼리 길이/빈도 | MEDIUM | - |

### 호스트 기반 탐지 (Sysmon)

| 이벤트 ID | 탐지 내용 | 심각도 |
|-----------|-----------|--------|
| 의심 프로세스 | mimikatz, meterpreter, cobalt strike 등 | CRITICAL/HIGH |
| 의심 경로 실행 | %TEMP%, %APPDATA%, Public 폴더에서 실행 | HIGH |
| lsass 접근 | Event ID 10 + lsass.exe 대상 | CRITICAL |
| WMI 지속성 | Event ID 19/20/21 | HIGH |
| 프로세스 변조 | Event ID 25 | CRITICAL |
| 원격 스레드 생성 | Event ID 8 | HIGH |
| 드라이버 로드 | Event ID 6 (미서명) | HIGH |

### 파일/해시 기반 탐지

| 규칙 | 조건 | 심각도 |
|------|------|--------|
| 악성 해시 MD5 | `data/malicious_hashes.txt` DB 매칭 | CRITICAL |
| 악성 해시 SHA256 | `data/malicious_hashes.txt` DB 매칭 | CRITICAL |

---

## 탐지 규칙 추가 방법

### 새 네트워크 탐지 규칙

`modules/threat_detector.py` 의 `analyze_packet()` 메서드에 추가:

```python
def analyze_packet(self, src_ip, dst_ip, dst_port, proto, length):
    # 기존 코드...

    # 새 규칙 예시: 의심 포트 접근
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337}
    if dst_port in SUSPICIOUS_PORTS:
        self._add_alert(Alert(
            "MALWARE_BEACON", "HIGH", src_ip, dst_ip,
            f"의심 포트 접근: {dst_port} (C2 포트)",
            {"port": dst_port},
        ))
```

### 새 악성 해시 추가

`data/malicious_hashes.txt` 에 한 줄 추가:
```
sha256,<SHA256_해시>,<악성코드_이름>
```

### 탐지 임계값 조정

`.env` 파일에서 조정:
```env
DDOS_PACKET_THRESHOLD=500    # 더 민감하게 (기본: 1000)
PORT_SCAN_THRESHOLD=10       # 더 민감하게 (기본: 20)
```

---

## 오탐(False Positive) 관리

1. **알림 상태 변경**: `ACK` → 확인됨, `CLOSED` → 오탐 종료
2. **AI 분석 활용**: 각 알림의 AI 분석 버튼으로 진위 판단 요청
3. **화이트리스트 추가** (향후 구현):
   - `data/whitelist_ips.txt`: 차단 제외 IP
   - `data/whitelist_hashes.txt`: 정상 파일 해시

---

## MITRE ATT&CK 매핑

| 탐지 규칙 | ATT&CK Technique |
|-----------|-----------------|
| DDoS | T1498 - Network Denial of Service |
| 포트 스캔 | T1046 - Network Service Discovery |
| Mimikatz | T1003 - OS Credential Dumping |
| lsass 접근 | T1003.001 - LSASS Memory |
| ARP 스푸핑 | T1557.002 - ARP Cache Poisoning |
| DNS 터널링 | T1071.004 - DNS C2 |
| WMI 지속성 | T1546.003 - WMI Event Subscription |
| 데이터 유출 | T1048 - Exfiltration Over Alternative Protocol |
