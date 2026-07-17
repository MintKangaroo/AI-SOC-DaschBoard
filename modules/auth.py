"""
대시보드 인증 모듈

- 단일 관리자 계정(사용자명 + 비밀번호 해시) 검증
- IP별 로그인 시도 제한(브루트포스 방어) — N회 실패 시 일정 시간 잠금
- 비밀번호는 평문 저장 안 함: 평문이 주어지면 시작 시 pbkdf2 해시로 변환

werkzeug.security(Flask 의존성)만 사용 — 추가 패키지 불필요.
"""
import time
import threading

from werkzeug.security import generate_password_hash, check_password_hash


class AuthManager:
    def __init__(self, username, password=None, password_hash=None,
                 max_attempts=5, window=300, lockout=300):
        self.username = username
        if password_hash:
            self.password_hash = password_hash
        elif password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None          # 비밀번호 미설정 → 로그인 불가
        self.max_attempts = max_attempts       # window 내 최대 실패 횟수
        self.window = window                   # 실패 집계 구간(초)
        self.lockout = lockout                 # 잠금 시간(초)
        self._lock = threading.Lock()
        self._fails = {}                       # ip → [실패 timestamp]
        self._locked_until = {}                # ip → 잠금 해제 시각

    @property
    def configured(self):
        return bool(self.password_hash)

    def is_locked(self, ip):
        with self._lock:
            return self._locked_until.get(ip, 0) > time.time()

    def lock_remaining(self, ip):
        with self._lock:
            return max(0, int(self._locked_until.get(ip, 0) - time.time()))

    def verify(self, username, password, ip="?"):
        """반환: (성공여부, 사유코드)  사유: ok | bad | locked | no_password"""
        if self.is_locked(ip):
            return False, "locked"
        if not self.password_hash:
            return False, "no_password"

        ok = (username == self.username
              and check_password_hash(self.password_hash, password or ""))
        with self._lock:
            if ok:
                self._fails.pop(ip, None)
                self._locked_until.pop(ip, None)
                return True, "ok"
            now = time.time()
            fails = [t for t in self._fails.get(ip, []) if now - t < self.window]
            fails.append(now)
            self._fails[ip] = fails
            if len(fails) >= self.max_attempts:
                self._locked_until[ip] = now + self.lockout
                self._fails[ip] = []
                return False, "locked"
        return False, "bad"
