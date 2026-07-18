# Layer: L1 积木层
# Contract: 选择/创建 curl_cffi TLS 指纹会话；UA 与 sec-ch-ua 与 impersonate 对齐。
# Boundary: 不含注册业务；探测失败回退可用指纹，由上层暴露 CF 错误。
# Why: chrome120 过旧易触发 CF challenge；指纹须与请求头一致。

from __future__ import annotations

import os
import re
from typing import Optional

from curl_cffi import requests

AUTH_BASE = "https://auth.openai.com"

# 优先新指纹；实测 auth.openai.com 上过新也可能 403，靠探测挑选。
IMPERSONATE_CANDIDATES = (
    "chrome146",
    "chrome142",
    "chrome136",
    "chrome133a",
    "chrome131",
    "chrome124",
    "chrome123",
    "chrome120",
)

# major -> (UA Chrome/x.0.0.0, sec-ch-ua)
_UA_PROFILES: dict[str, tuple[str, str]] = {
    "146": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        '"Google Chrome";v="146", "Chromium";v="146", "Not A(Brand";v="24"',
    ),
    "142": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        '"Google Chrome";v="142", "Chromium";v="142", "Not A(Brand";v="24"',
    ),
    "136": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        '"Google Chrome";v="136", "Chromium";v="136", "Not A(Brand";v="24"',
    ),
    "133": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        '"Google Chrome";v="133", "Chromium";v="133", "Not A(Brand";v="24"',
    ),
    "131": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        '"Google Chrome";v="131", "Chromium";v="131", "Not A(Brand";v="24"',
    ),
    "124": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        '"Google Chrome";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
    ),
    "123": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        '"Google Chrome";v="123", "Chromium";v="123", "Not-A.Brand";v="99"',
    ),
    "120": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        '"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"',
    ),
}


def _proxy_dict(proxy: str = "") -> Optional[dict[str, str]]:
    proxy = (proxy or "").strip()
    if not proxy:
        proxy = (os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY") or "").strip()
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _major_from_impersonate(impersonate: str) -> str:
    m = re.search(r"(\d{2,3})", impersonate or "")
    return m.group(1) if m else "131"


def ua_for_impersonate(impersonate: str) -> str:
    major = _major_from_impersonate(impersonate)
    if major in _UA_PROFILES:
        return _UA_PROFILES[major][0]
    return _UA_PROFILES["131"][0]


def sec_ch_ua_for_impersonate(impersonate: str) -> str:
    major = _major_from_impersonate(impersonate)
    if major in _UA_PROFILES:
        return _UA_PROFILES[major][1]
    return _UA_PROFILES["131"][1]


def is_cloudflare_challenge(resp) -> bool:
    if resp is None:
        return False
    try:
        status = int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    headers = getattr(resp, "headers", None) or {}
    mitigated = str(headers.get("cf-mitigated") or headers.get("Cf-Mitigated") or "").lower()
    if mitigated == "challenge":
        return True
    text = str(getattr(resp, "text", "") or "").lower()
    if status in (403, 503) and (
        "just a moment" in text
        or "attention required" in text
        or "cf-chl-" in text
        or "__cf_chl_" in text
        or "challenges.cloudflare.com" in text
    ):
        return True
    return False


def list_available_impersonates() -> list[str]:
    """过滤本机 curl_cffi 实际支持的候选。"""
    available: list[str] = []
    for imp in IMPERSONATE_CANDIDATES:
        try:
            s = requests.Session(impersonate=imp)
            s.close()
            available.append(imp)
        except Exception:
            continue
    env = (os.getenv("IMPERSONATE") or os.getenv("CURL_IMPERSONATE") or "").strip()
    if env and env not in available:
        try:
            s = requests.Session(impersonate=env)
            s.close()
            available.insert(0, env)
        except Exception:
            pass
    return available or ["chrome120"]


def pick_impersonate(proxy: str = "") -> str:
    """探测能打开 auth.openai.com 且非 CF 挑战页的指纹。

    Contract: 全失败时返回最新可用指纹（默认 chrome146/列表首项），
    让上层请求暴露真实 403，而不是静默用过时 chrome120。
    """
    forced = (os.getenv("IMPERSONATE") or os.getenv("CURL_IMPERSONATE") or "").strip()
    candidates = list_available_impersonates()
    if forced:
        if forced in candidates:
            candidates = [forced] + [c for c in candidates if c != forced]
        else:
            candidates = [forced] + candidates

    proxies = _proxy_dict(proxy)
    last_err = "no candidates"
    for imp in candidates:
        try:
            with requests.Session(impersonate=imp, proxies=proxies) as s:
                res = s.get(f"{AUTH_BASE}/", timeout=20, allow_redirects=True)
                if is_cloudflare_challenge(res):
                    last_err = f"{imp}->cf_challenge/{res.status_code}"
                    continue
                if int(getattr(res, "status_code", 0) or 0) < 400:
                    return imp
                last_err = f"{imp}->{res.status_code}"
        except Exception as exc:
            last_err = f"{imp}->{exc}"
    fallback = candidates[0]
    print(f"[!] impersonate 探测未完全成功 ({last_err})，使用 {fallback}")
    return fallback


def create_session(proxy: str = "", impersonate: str = "") -> requests.Session:
    imp = impersonate or pick_impersonate(proxy)
    return requests.Session(impersonate=imp, proxies=_proxy_dict(proxy))
