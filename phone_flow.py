# Layer: L2 流程层
# Contract: add_phone 页完成 Tiger SMS 取号 + OpenAI 发码/校验，返回下一页 type。
# Boundary: L2 -> L1(PhoneService) + OpenAI HTTP；不负责 create_account。
# Why: 从 chatgpt.py 拆出，避免注册主流程继续膨胀。

from __future__ import annotations

import json
import os
from typing import Any, Optional

from phone_service import PhoneService, TigerSmsError
from sentinel import build_sentinel_token

AUTH_BASE = "https://auth.openai.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def _snip(resp, n: int = 280) -> str:
    try:
        return (getattr(resp, "text", None) or "")[:n]
    except Exception:
        return ""


def _json_headers(referer: str, device_id: str) -> dict[str, str]:
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": AUTH_BASE,
        "referer": referer,
        "oai-device-id": device_id,
        "user-agent": UA,
    }


def _nav_headers(referer: str = "") -> dict[str, str]:
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "user-agent": UA,
    }
    if referer:
        headers["referer"] = referer
    return headers


def _sentinel(
    *,
    device_id: str,
    proxies: Any = None,
    session: Any = None,
) -> str:
    return (
        build_sentinel_token(
            device_id=device_id,
            flow="authorize_continue",
            proxies=proxies,
            session=session,
            ua=UA,
        )
        or ""
    )


def openai_phone_send(
    session,
    *,
    device_id: str,
    phone_e164: str,
    proxies: Any = None,
) -> tuple[bool, str, dict]:
    """POST /api/accounts/add-phone/send。

    Contract: body.phone_number 为完整 E.164（如 +1304...）。
    Why: 页面输入框只显示本地号、+1 由 UI 自填，但提交到 API 的
    form value 仍是 react-phone-number-input 的 E.164；只传 10 位会
    invalid_phone_number。
    """
    headers = _json_headers(f"{AUTH_BASE}/add-phone", device_id)
    # 只走 add-phone/send；phone-otp/send 不接受 phone_number（已绑号后重发）
    body_variants = (
        {"phone_number": phone_e164, "channel": "sms"},
        {"phone_number": phone_e164},
    )
    last_page = ""
    last_data: dict = {}
    for body_obj in body_variants:
        body = json.dumps(body_obj)
        resp = session.post(
            f"{AUTH_BASE}/api/accounts/add-phone/send",
            headers=headers,
            data=body,
            timeout=30,
        )
        if resp.status_code != 200:
            headers["openai-sentinel-token"] = _sentinel(
                device_id=device_id, proxies=proxies, session=session
            )
            resp = session.post(
                f"{AUTH_BASE}/api/accounts/add-phone/send",
                headers=headers,
                data=body,
                timeout=30,
            )
        try:
            data = resp.json() or {}
        except Exception:
            data = {}
        last_data = data if isinstance(data, dict) else {}
        last_page = str((last_data.get("page") or {}).get("type") or "")
        if resp.status_code == 200:
            return True, last_page, last_data
        print(
            f"[!] phone send add-phone/send body={body_obj} "
            f"-> {resp.status_code} {_snip(resp)}"
        )
    return False, last_page, last_data


def openai_phone_validate(
    session,
    *,
    device_id: str,
    code: str,
    proxies: Any = None,
) -> tuple[bool, str, dict]:
    """POST /api/accounts/phone-otp/validate。"""
    headers = _json_headers(f"{AUTH_BASE}/phone-verification", device_id)
    body = json.dumps({"code": code})
    paths = (
        "/api/accounts/phone-otp/validate",
        "/api/accounts/phone/otp/validate",
    )
    last_page = ""
    last_data: dict = {}
    for path in paths:
        resp = session.post(
            f"{AUTH_BASE}{path}",
            headers=headers,
            data=body,
            timeout=30,
        )
        if resp.status_code != 200:
            headers["openai-sentinel-token"] = _sentinel(
                device_id=device_id, proxies=proxies, session=session
            )
            resp = session.post(
                f"{AUTH_BASE}{path}",
                headers=headers,
                data=body,
                timeout=30,
            )
        try:
            data = resp.json() or {}
        except Exception:
            data = {}
        last_data = data if isinstance(data, dict) else {}
        last_page = str((last_data.get("page") or {}).get("type") or "")
        if resp.status_code == 200:
            continue_url = str(last_data.get("continue_url") or "").strip()
            if continue_url:
                try:
                    session.get(
                        continue_url,
                        headers=_nav_headers(f"{AUTH_BASE}/phone-verification"),
                        timeout=15,
                        allow_redirects=True,
                    )
                except Exception:
                    pass
            return True, last_page, last_data
        print(f"[!] phone validate {path} -> {resp.status_code} {_snip(resp)}")
    return False, last_page, last_data


def handle_add_phone(
    session,
    *,
    device_id: str,
    proxies: Any = None,
    max_number_attempts: int = 3,
    code_wait_seconds: int = 120,
) -> Optional[str]:
    """add_phone：取号 → 发短信 → 收码 → 校验。

    Contract: 成功返回下一页 page.type；失败返回 None。
    Risk: 失败路径 setStatusV2=8 尽力取消；2 分钟内可能 EARLY_CANCEL_DENIED。
    """
    try:
        phone_svc = PhoneService()
    except Exception as exc:
        print(f"[Error] PhoneService 初始化失败: {exc}")
        return None

    attempts = max(1, int(os.getenv("TIGER_SMS_NUMBER_RETRIES") or max_number_attempts))
    wait_s = int(os.getenv("TIGER_SMS_POLL_SECONDS") or code_wait_seconds)

    for i in range(1, attempts + 1):
        activation = None
        try:
            print(
                f"[*] Tiger SMS 取号 ({i}/{attempts}) "
                f"service={phone_svc.service} country={phone_svc.country}"
            )
            activation = phone_svc.get_number()
            phone_e164 = activation.e164
            print(
                f"[*] 号码 activation_id={activation.activation_id} "
                f"e164={phone_e164} national={activation.national_number} "
                f"cost={activation.activation_cost}"
            )
        except TigerSmsError as exc:
            print(f"[Error] 取号失败: {exc}")
            continue
        except Exception as exc:
            print(f"[Error] 取号异常: {exc}")
            continue

        try:
            ok, page_after_send, _raw = openai_phone_send(
                session,
                device_id=device_id,
                phone_e164=phone_e164,
                proxies=proxies,
            )
            if not ok:
                print("[Error] OpenAI 提交手机号失败，取消该号")
                phone_svc.cancel(activation.activation_id)
                continue
            print(f"[*] 已提交手机号 page={page_after_send or '?'}")

            print(f"[*] 等待短信验证码 (≤{wait_s}s)...")
            code = phone_svc.wait_code(
                activation.activation_id, max_wait_seconds=wait_s
            )
            if not code:
                print("[Error] 短信验证码超时，取消该号")
                phone_svc.cancel(activation.activation_id)
                continue
            print(f"[*] 收到短信验证码: {code}")

            ok, page_after, _raw = openai_phone_validate(
                session,
                device_id=device_id,
                code=code,
                proxies=proxies,
            )
            if not ok:
                print("[Error] 手机验证码校验失败，取消该号")
                phone_svc.cancel(activation.activation_id)
                continue

            phone_svc.complete(activation.activation_id)
            print(f"[*] 手机验证通过 page={page_after or '?'}")
            return page_after or "about_you"
        except Exception as exc:
            print(f"[Error] 手机验证流程异常: {exc}")
            if activation is not None:
                try:
                    phone_svc.cancel(activation.activation_id)
                except Exception:
                    pass

    return None
