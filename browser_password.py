# Layer: L1 积木层（浏览器密码页）
# Contract: 在已打开的 create-account/password 页填密并提交；拦截 /user/register 响应。
# Boundary: 仅操作 Playwright page；不负责 OEP/SMS。
# Why: CF 通过后 curl 调 register 易 account_creation_failed；DOM+页内上下文更稳。

from __future__ import annotations

import json
from typing import Any, Optional


def page_looks_like_password(url: str, title: str = "") -> bool:
    u = (url or "").lower()
    t = (title or "").lower()
    return (
        "create-account/password" in u
        or "/password" in u
        or "create a password" in t
        or "create password" in t
    )


def submit_password_on_page(
    page: Any,
    *,
    password: str,
    email: str = "",
    timeout_ms: int = 45_000,
) -> tuple[bool, int, str, str]:
    """在密码页填密并提交。

    Returns:
        (ok, http_status_or_0, raw_or_note, final_url)
    """
    url = str(page.url or "")
    title = ""
    try:
        title = page.title() or ""
    except Exception:
        title = ""
    print(f"[*] password page url={url} title={title!r}")

    # 拦截 register 响应
    register_status = 0
    register_body = ""

    def _on_response(resp: Any) -> None:
        nonlocal register_status, register_body
        try:
            rurl = str(resp.url or "")
            if "/api/accounts/user/register" not in rurl:
                return
            register_status = int(resp.status or 0)
            try:
                register_body = resp.text() or ""
            except Exception:
                register_body = ""
            print(f"[*] intercepted register -> {register_status} {register_body[:220]}")
        except Exception:
            pass

    page.on("response", _on_response)

    try:
        # 填所有 password 输入（含确认密码）
        inputs = page.locator('input[type="password"]')
        count = inputs.count()
        if count == 0:
            # 有的实现 type=text + autocomplete
            inputs = page.locator(
                'input[name*="password" i], input[autocomplete="new-password"]'
            )
            count = inputs.count()
        if count == 0:
            return False, 0, "no_password_input", str(page.url or "")

        for i in range(count):
            el = inputs.nth(i)
            try:
                el.wait_for(state="visible", timeout=5000)
                el.click(timeout=3000)
                el.fill("")
                el.fill(password)
            except Exception as exc:
                print(f"[!] fill password input[{i}] failed: {exc}")

        # 若仍有 email 输入框
        if email:
            for sel in (
                'input[type="email"]',
                'input[name*="email" i]',
                'input[autocomplete="username"]',
            ):
                loc = page.locator(sel)
                if loc.count() > 0:
                    try:
                        if loc.first.is_visible():
                            loc.first.fill(email)
                    except Exception:
                        pass

        # 点继续
        clicked = False
        for sel in (
            'button[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("继续")',
            'button:has-text("Next")',
            'button:has-text("Create")',
            '[data-testid*="continue" i]',
        ):
            loc = page.locator(sel)
            try:
                if loc.count() > 0 and loc.first.is_enabled():
                    loc.first.click(timeout=5000)
                    clicked = True
                    break
            except Exception:
                continue
        if not clicked:
            page.keyboard.press("Enter")

        # 等导航或 register 响应
        page.wait_for_timeout(1500)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 15000))
        except Exception:
            pass
        page.wait_for_timeout(1500)

        final_url = str(page.url or "")
        try:
            final_title = page.title() or ""
        except Exception:
            final_title = ""
        print(f"[*] after password submit url={final_url} title={final_title!r}")

        # 页面错误文案
        err_text = ""
        try:
            err_text = page.locator(
                '[role="alert"], .error, [class*="error" i], [data-error]'
            ).first.inner_text(timeout=1000)
        except Exception:
            err_text = ""
        if err_text:
            print(f"[!] password page error text: {err_text[:200]}")

        if register_status == 200:
            return True, 200, register_body, final_url
        if register_status and register_status != 200:
            return False, register_status, register_body or err_text, final_url

        # 无拦截到 API 时，用 URL 判断
        fl = final_url.lower()
        if any(
            x in fl
            for x in (
                "email-verification",
                "email-otp",
                "about-you",
                "add-phone",
                "phone",
                "consent",
            )
        ):
            return True, 200, "navigated_without_capture", final_url
        if "password" not in fl and page_looks_like_password(url, title):
            return True, 200, "left_password_page", final_url

        return False, register_status or 0, register_body or err_text or "still_on_password", final_url
    finally:
        try:
            page.remove_listener("response", _on_response)
        except Exception:
            pass


def register_via_page_fetch(
    page: Any,
    *,
    email: str,
    password: str,
    headers: dict[str, str],
) -> tuple[int, Any, str]:
    """页内 fetch /api/accounts/user/register。"""
    # 多种 body：OpenAI 前端版本不完全一致
    bodies = (
        {"username": email, "password": password},
        {"password": password},
        {"username": {"value": email, "kind": "email"}, "password": password},
    )
    last_status, last_data, last_text = 0, None, ""
    for body in bodies:
        payload = {
            "url": "https://auth.openai.com/api/accounts/user/register",
            "method": "POST",
            "headers": dict(headers or {}),
            "body": json.dumps(body),
        }
        # 确保 content-type
        hdrs = payload["headers"]
        if not any(k.lower() == "content-type" for k in hdrs):
            hdrs["Content-Type"] = "application/json"
        result = page.evaluate(
            """async ({url, method, headers, body}) => {
                const init = {method, headers: headers || {}, credentials: 'include'};
                if (body !== null && body !== undefined && method !== 'GET' && method !== 'HEAD') {
                    init.body = body;
                }
                const resp = await fetch(url, init);
                const text = await resp.text();
                return {status: resp.status, text};
            }""",
            payload,
        )
        status = int((result or {}).get("status") or 0)
        text = str((result or {}).get("text") or "")
        data = None
        try:
            data = json.loads(text) if text else None
        except Exception:
            data = None
        print(f"[*] page_fetch register body_keys={list(body.keys())} -> {status} {text[:180]}")
        last_status, last_data, last_text = status, data, text
        if status == 200:
            return status, data, text
    return last_status, last_data, last_text
