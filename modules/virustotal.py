"""VirusTotal v3 해시 평판 조회. 파일 업로드 없이 기존 리포트만 조회한다."""
import re
import threading
import time

import requests

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


class VirusTotalClient:
    def __init__(self, config=None):
        config = config or {}
        self.api_key = (config.get("VIRUSTOTAL_API_KEY") or "").strip()
        self.timeout = float(config.get("VIRUSTOTAL_TIMEOUT", 8))
        self.cache_ttl = float(config.get("VIRUSTOTAL_CACHE_HOURS", 6)) * 3600
        self._cache = {}
        self._lock = threading.Lock()

    @property
    def active(self):
        return bool(self.api_key)

    def status(self):
        with self._lock:
            return {"active": self.active, "cache_entries": len(self._cache),
                    "mode": "hash_lookup_only", "uploads": False}

    def lookup_hash(self, value):
        value = (value or "").strip().lower()
        if not _HASH_RE.fullmatch(value):
            return {"ok": False, "status": "invalid_hash", "hash": value}
        if not self.active:
            return {"ok": False, "status": "not_configured", "hash": value}
        with self._lock:
            cached = self._cache.get(value)
            if cached and time.time() - cached[0] < self.cache_ttl:
                return {**cached[1], "cached": True}
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{value}",
                             headers={"x-apikey": self.api_key}, timeout=self.timeout)
            if r.status_code == 404:
                result = {"ok": True, "status": "not_found", "hash": value,
                          "malicious": 0, "suspicious": 0, "harmless": 0,
                          "undetected": 0, "verdict": "UNKNOWN"}
            else:
                r.raise_for_status()
                attrs = (r.json().get("data") or {}).get("attributes") or {}
                stats = attrs.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                result = {"ok": True, "status": "found", "hash": value,
                          "sha256": attrs.get("sha256"), "name": attrs.get("meaningful_name"),
                          "type": attrs.get("type_description"), "malicious": malicious,
                          "suspicious": suspicious, "harmless": int(stats.get("harmless", 0)),
                          "undetected": int(stats.get("undetected", 0)),
                          "verdict": "MALICIOUS" if malicious else
                                     "SUSPICIOUS" if suspicious else "CLEAN",
                          "link": f"https://www.virustotal.com/gui/file/{attrs.get('sha256') or value}"}
        except requests.RequestException as e:
            result = {"ok": False, "status": "error", "hash": value,
                      "error": type(e).__name__}
        with self._lock:
            self._cache[value] = (time.time(), result)
        return result
