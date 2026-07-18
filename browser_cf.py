# Layer: L1 积木层
# Contract: 有头浏览器打开 URL、等待 Cloudflare 挑战消失、导出 cookie/UA。
# Boundary: 仅 Playwright 浏览器生命周期；不负责 OEP/SMS/建号业务。
# Why: 机房 VDS 上 curl/curl_cffi 常被 CF challenge，真浏览器可过 managed 挑战。
# Risk: 无显示环境需 xvfb-run；CF 通过后 cookie 绑定浏览器指纹，关键 API 优先页内 fetch。

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

try:
    from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright
except ImportError:  # pragma: no cover
    Browser = Any  # type: ignore
    BrowserContext = Any  # type: ignore
    Page = Any  # type: ignore
    Playwright = Any  # type: ignore
    sync_playwright = None  # type: ignore


@dataclass
class BrowserBootstrapResult:
    cookies: list[dict[str, Any]]
    user_agent: str
    final_url: str
    oai_did: str


def _require_playwright() -> None:
    if sync_playwright is None:
        raise RuntimeError(
            "未安装 playwright。请执行: pip install playwright && playwright install chrome"
            " （或 playwright install chromium）"
        )


def _is_cf_title_or_body(title: str, body: str) -> bool:
    t = (title or "").lower()
    b = (body or "").lower()
    return (
        "just a moment" in t
        or "just a moment" in b
        or "attention required" in t
        or "enable javascript and cookies to continue" in b
        or "cf-chl-" in b
    )


class BrowserCfSession:
    """有头 Chrome/Chromium：过 CF 后供注册流程复用 cookie 或页内 fetch。"""

    def __init__(
        self,
        *,
        proxy: str = "",
        headless: bool = False,
        channel: str = "",
        timeout_ms: int = 120_000,
    ) -> None:
        _require_playwright()
        self.proxy = (proxy or "").strip()
        self.headless = bool(headless)
        self.channel = (
            channel
            or os.getenv("BROWSER_CHANNEL")
            or "chrome"
        ).strip()
        self.timeout_ms = int(
            os.getenv("BROWSER_CF_TIMEOUT_MS") or timeout_ms
        )
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self.user_agent = ""

    def __enter__(self) -> "BrowserCfSession":
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def start(self) -> None:
        if self._page is not None:
            return
        self._pw = sync_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--no-default-browser-check",
                "--no-first-run",
            ],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}

        browser = None
        last_err: Exception | None = None
        # 优先系统 Chrome（更像真人）；失败再 chromium
        for channel in (self.channel, "chromium", ""):
            try:
                kw = dict(launch_kwargs)
                if channel and channel != "chromium":
                    kw["channel"] = channel
                browser = self._pw.chromium.launch(**kw)
                print(f"[*] browser launched channel={channel or 'chromium'} headless={self.headless}")
                break
            except Exception as exc:
                last_err = exc
                continue
        if browser is None:
            raise RuntimeError(f"无法启动浏览器: {last_err}")

        self._browser = browser
        self._context = browser.new_context(
            locale="en-US",
            viewport={"width": 1280, "height": 800},
        )
        self._page = self._context.new_page()
        self.user_agent = self._page.evaluate("() => navigator.userAgent") or ""

    def close(self) -> None:
        for obj in (self._context, self._browser):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass
        self._context = None
        self._browser = None
        self._page = None
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
            self._pw = None

    @property
    def page(self) -> Any:
        if self._page is None:
            raise RuntimeError("browser not started")
        return self._page

    def open_and_wait_cf_clear(self, url: str) -> BrowserBootstrapResult:
        """打开 URL，等到 CF 挑战消失。

        Contract: 超时抛 RuntimeError；成功返回 cookies + UA + oai-did。
        """
        self.start()
        page = self.page
        print(f"[*] browser open: {url[:120]}...")
        page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)

        deadline = time.time() + self.timeout_ms / 1000.0
        last_title = ""
        while time.time() < deadline:
            try:
                last_title = page.title() or ""
                body_snip = page.locator("body").inner_text(timeout=2000)[:500]
            except Exception:
                last_title = ""
                body_snip = ""

            if not _is_cf_title_or_body(last_title, body_snip):
                # 再稳一点：标题不是挑战且页面可交互
                print(f"[*] CF 已通过 title={last_title!r}")
                break
            print(f"[*] 等待 Cloudflare 挑战... title={last_title!r}")
            page.wait_for_timeout(1500)
        else:
            raise RuntimeError(
                f"Cloudflare 挑战超时（{self.timeout_ms}ms），title={last_title!r}。"
                " 可在有显示环境手动点一次，或换 IP/开有头模式。"
            )

        # 给 CF 写 cookie 一点时间
        page.wait_for_timeout(800)
        cookies = self._context.cookies()
        oai_did = ""
        for c in cookies:
            if c.get("name") == "oai-did" and c.get("value"):
                oai_did = str(c["value"])
                break
        return BrowserBootstrapResult(
            cookies=list(cookies),
            user_agent=self.user_agent,
            final_url=page.url,
            oai_did=oai_did,
        )

    def apply_cookies_to_curl_session(self, session: Any) -> None:
        """把浏览器 cookie 灌进 curl_cffi Session。

        Risk: CF clearance 常与浏览器 TLS 绑定；若后续仍 403，应改用 page_fetch_json。
        """
        if self._context is None:
            return
        for c in self._context.cookies():
            name = c.get("name")
            value = c.get("value")
            if not name:
                continue
            domain = (c.get("domain") or "").lstrip(".") or None
            path = c.get("path") or "/"
            try:
                if domain:
                    session.cookies.set(name, value, domain=domain, path=path)
                else:
                    session.cookies.set(name, value, path=path)
            except Exception:
                try:
                    session.cookies.set(name, value)
                except Exception:
                    pass

    def page_fetch_json(
        self,
        *,
        url: str,
        method: str = "POST",
        headers: Optional[dict[str, str]] = None,
        body: Any = None,
    ) -> tuple[int, Any, str]:
        """在页面上下文 fetch（与过 CF 的浏览器同一指纹）。

        Contract: 返回 (status, json_or_none, raw_text)。
        """
        page = self.page
        hdrs = dict(headers or {})
        # 浏览器自动带 cookie；去掉可能冲突的
        for k in list(hdrs.keys()):
            if k.lower() == "cookie":
                hdrs.pop(k)
        payload = {
            "url": url,
            "method": (method or "GET").upper(),
            "headers": hdrs,
            "body": body if isinstance(body, str) or body is None else json.dumps(body),
        }
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
        data: Any = None
        try:
            data = json.loads(text) if text else None
        except Exception:
            data = None
        return status, data, text
