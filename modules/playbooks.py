"""
SOAR 플레이북 카탈로그 — 각 자동대응 플레이북의 '실행 단계(runbook)' 정의.

SOAREngine 은 트리거를 만나면 해당 플레이북을 실행하고, 여기 정의된 단계
순서(탐지 → 강화 → 판정 → 격리/대응 → 통보 → 사후)를 따른다. 이 모듈은
선언적 정의(데이터)만 두고, 실제 실행/기록은 soar.py 가 담당한다.

각 step:
  key    : 단계 식별자
  label  : 화면 표기
  kind   : detect | enrich | decide | contain | notify | followup (단계 유형=색상)
"""

# 플레이북 id → 실행 단계 정의
PLAYBOOK_STEPS = {
    "PB-AI-TRIAGE": [
        {"key": "intake",  "label": "HIGH/CRITICAL 알림 수신",           "kind": "detect"},
        {"key": "enrich",  "label": "IP 평판·위협그룹 prior 보강",       "kind": "enrich"},
        {"key": "ai",      "label": "Claude AI 정탐/오탐 판정",          "kind": "decide"},
        {"key": "verdict", "label": "오탐→자동종결+ML피드백 / 정탐→ACK", "kind": "contain"},
        {"key": "notify",  "label": "정탐 확정 시 인시던트 승격·폰 통보", "kind": "notify"},
    ],
    "PB-AUTO-BLOCK": [
        {"key": "gate",    "label": "정탐 + CRITICAL + 외부 IP + 신뢰도 80↑", "kind": "detect"},
        {"key": "safety",  "label": "안전장치 검사(사설·Tailscale·자기자신 제외)", "kind": "decide"},
        {"key": "block",   "label": "방화벽 차단(TTL 자동 만료)",         "kind": "contain"},
        {"key": "log",     "label": "감사 로그 기록",                     "kind": "followup"},
    ],
    "PB-BRUTE-BLOCK": [
        {"key": "match",   "label": "BRUTE_FORCE 알림 · 외부 출발지",     "kind": "detect"},
        {"key": "safety",  "label": "안전장치 검사",                      "kind": "decide"},
        {"key": "block",   "label": "즉시 방화벽 차단",                   "kind": "contain"},
        {"key": "log",     "label": "감사 로그 기록",                     "kind": "followup"},
    ],
    "PB-HONEYPOT-BLOCK": [
        {"key": "hit",     "label": "허니팟 유인 서비스 접촉 감지",        "kind": "detect"},
        {"key": "score",   "label": "접촉=고신뢰 침해지표(입력 시 CRITICAL)", "kind": "decide"},
        {"key": "block",   "label": "출발지 IP 방화벽 차단",              "kind": "contain"},
        {"key": "log",     "label": "감사 로그 + 인시던트 연계",          "kind": "followup"},
    ],
    "PB-SIEM-SCANNER": [
        {"key": "probe",   "label": "동일 IP 프로브 반복 카운트",         "kind": "detect"},
        {"key": "thresh",  "label": "3회 이상 도달 판정",                 "kind": "decide"},
        {"key": "block",   "label": "스캐너 IP 차단",                     "kind": "contain"},
        {"key": "log",     "label": "감사 로그 기록",                     "kind": "followup"},
    ],
    "PB-IOC-BLOCK": [
        {"key": "match",   "label": "위협 인텔 IoC(악성 IP) 매칭",        "kind": "detect"},
        {"key": "block",   "label": "즉시 차단",                         "kind": "contain"},
        {"key": "log",     "label": "감사 로그 기록",                     "kind": "followup"},
    ],
    "PB-CORRELATED-ESCALATE": [
        {"key": "corr",    "label": "SIEM 상관관계 규칙 발동",            "kind": "detect"},
        {"key": "assess",  "label": "다중벡터/침투진행 위험도 산정",       "kind": "decide"},
        {"key": "escalate","label": "상관 알림 생성 → 인시던트 승격",      "kind": "contain"},
        {"key": "notify",  "label": "고위험 시 폰 통보",                  "kind": "notify"},
    ],
    "MANUAL": [
        {"key": "analyst", "label": "분석가 수동 조치(차단/해제)",         "kind": "contain"},
        {"key": "log",     "label": "감사 로그 기록",                     "kind": "followup"},
    ],
}

# 단계 유형 → 한글 표기(범례용)
STEP_KIND_KO = {
    "detect":   "탐지",
    "enrich":   "강화",
    "decide":   "판정",
    "contain":  "대응",
    "notify":   "통보",
    "followup": "사후",
}


def steps_for(pb_id):
    """플레이북 id 의 단계 정의 반환(없으면 빈 리스트)."""
    return [dict(s) for s in PLAYBOOK_STEPS.get(pb_id, [])]
