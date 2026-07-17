# Layer: L1 积木层
# Contract: 向 sentinel 请求 PoW，返回 openai-sentinel-token 头值。
# Boundary: 单次外部 HTTP；失败返回空串，由调用方决定是否重试。
# Why: create_account 等步骤只带 c 或误用 so-token 会 400。

from __future__ import annotations

import base64
import json
import random
import time
import uuid
from typing import Any, Optional

from curl_cffi import requests

SENTINEL_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
SEC_CH_UA = '"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"'


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500_000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: str, ua: str):
        self.device_id = device_id
        self.user_agent = ua
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime(
                "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
                time.gmtime(),
            ),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            random.random(),
            "plugins-undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    def requirements_token(self) -> str:
        data = self._config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def pow_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


def build_sentinel_token(
    *,
    device_id: str,
    flow: str,
    proxies: Any = None,
    session: Any = None,
    ua: str = USER_AGENT,
) -> Optional[str]:
    """返回 openai-sentinel-token 头字符串；失败返回 None。"""
    gen = SentinelTokenGenerator(device_id, ua)
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": ua,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    body = json.dumps({"p": gen.requirements_token(), "id": device_id, "flow": flow})
    try:
        if session is not None:
            resp = session.post(SENTINEL_URL, data=body, headers=headers, timeout=20)
        else:
            resp = requests.post(
                SENTINEL_URL,
                data=body,
                headers=headers,
                proxies=proxies,
                impersonate="chrome120",
                timeout=20,
            )
        data = resp.json() if getattr(resp, "text", None) else {}
    except Exception:
        return None

    token = str((data or {}).get("token") or "").strip()
    if getattr(resp, "status_code", 0) != 200 or not token:
        return None

    pow_data = (data or {}).get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.pow_token(
            str(pow_data.get("seed") or ""),
            str(pow_data.get("difficulty") or "0"),
        )
    else:
        p_value = gen.requirements_token()

    return json.dumps(
        {"p": p_value, "t": "", "c": token, "id": device_id, "flow": flow},
        separators=(",", ":"),
    )
