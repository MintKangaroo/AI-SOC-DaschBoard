"""
시스템/네트워크 정보 수집 모듈
내 PC의 공인/사설 IP, OS, CPU, 메모리, 네트워크 인터페이스 등 '내 정보'를 반환.
외부 라이브러리가 없어도 동작하도록 데모 fallback 포함.
"""
import os
import sys
import socket
import platform
import getpass
import uuid
import time
import json
from datetime import datetime

try:
    import urllib.request as _urlreq
except Exception:
    _urlreq = None

try:
    import psutil  # optional
except Exception:
    psutil = None


_PUBLIC_IP_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
]

_cache = {"public_ip": None, "geo": None, "ts": 0}
_CACHE_TTL = 300  # 5분


def _fetch(url, timeout=3):
    if _urlreq is None:
        return None
    try:
        req = _urlreq.Request(url, headers={"User-Agent": "SOC-Dashboard/1.0"})
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def get_public_ip(force=False):
    now = time.time()
    if not force and _cache["public_ip"] and (now - _cache["ts"]) < _CACHE_TTL:
        return _cache["public_ip"]
    for ep in _PUBLIC_IP_ENDPOINTS:
        raw = _fetch(ep)
        if not raw:
            continue
        if raw.startswith("{"):
            try:
                raw = json.loads(raw).get("ip", "")
            except Exception:
                raw = ""
        if raw:
            _cache["public_ip"] = raw
            _cache["ts"] = now
            return raw
    return None


def get_geo_info(ip=None):
    if ip is None:
        ip = get_public_ip()
    if not ip:
        return None
    raw = _fetch(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query,timezone,lat,lon", timeout=4)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return None


def _get_private_ips():
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET:
                ip = sockaddr[0]
                if ip not in ips and not ip.startswith("127."):
                    ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and primary not in ips:
            ips.insert(0, primary)
    except Exception:
        pass
    return ips


def _get_interfaces():
    """네트워크 인터페이스 목록. psutil 있으면 상세, 없으면 간단히."""
    if psutil is None:
        ifaces = []
        for ip in _get_private_ips():
            ifaces.append({"name": "default", "ipv4": ip, "mac": None, "is_up": True})
        return ifaces
    out = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = ipv6 = mac = None
            for a in addr_list:
                fam = getattr(a, "family", None)
                if fam == socket.AF_INET:
                    ipv4 = a.address
                elif fam == socket.AF_INET6:
                    if not ipv6:
                        ipv6 = a.address
                elif str(fam).endswith("AF_LINK") or str(fam).endswith("AF_PACKET") or int(getattr(fam, "value", -1)) == -1:
                    mac = a.address
            st = stats.get(name)
            out.append({
                "name": name,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "is_up": bool(st and st.isup),
                "speed_mbps": getattr(st, "speed", None) if st else None,
            })
    except Exception:
        pass
    return out


def _get_mac():
    try:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except Exception:
        return None


def _get_resources():
    res = {
        "cpu_percent": None,
        "cpu_count": os.cpu_count(),
        "mem_total_mb": None,
        "mem_used_mb": None,
        "mem_percent": None,
        "disk_total_gb": None,
        "disk_used_gb": None,
        "disk_percent": None,
        "boot_time": None,
        "uptime_sec": None,
    }
    if psutil is None:
        return res
    try:
        res["cpu_percent"] = psutil.cpu_percent(interval=0.2)
        vm = psutil.virtual_memory()
        res["mem_total_mb"] = round(vm.total / (1024 * 1024))
        res["mem_used_mb"] = round(vm.used / (1024 * 1024))
        res["mem_percent"] = vm.percent
        du = psutil.disk_usage(os.path.abspath(os.sep))
        res["disk_total_gb"] = round(du.total / (1024 ** 3), 1)
        res["disk_used_gb"] = round(du.used / (1024 ** 3), 1)
        res["disk_percent"] = du.percent
        bt = psutil.boot_time()
        res["boot_time"] = datetime.fromtimestamp(bt).strftime("%Y-%m-%d %H:%M:%S")
        res["uptime_sec"] = int(time.time() - bt)
    except Exception:
        pass
    return res


def get_all():
    """대시보드 '내 정보' 탭에서 사용하는 통합 스냅샷."""
    hostname = socket.gethostname()
    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = hostname
    private_ips = _get_private_ips()
    public_ip = get_public_ip()
    geo = get_geo_info(public_ip) if public_ip else None
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": {
            "hostname": hostname,
            "fqdn": fqdn,
            "username": getpass.getuser(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version.split()[0],
            "mac": _get_mac(),
        },
        "network": {
            "private_ips": private_ips,
            "primary_private_ip": private_ips[0] if private_ips else None,
            "public_ip": public_ip,
            "geo": geo,
            "interfaces": _get_interfaces(),
        },
        "resources": _get_resources(),
    }
    return info
