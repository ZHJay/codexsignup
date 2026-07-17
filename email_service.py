# Layer: L1 积木层
# Contract: 经 Outlook Email Plus /api/external/* 领取邮箱、取验证码、释放/完成租约。
# Boundary: 不直连 mail.tm / Cloudflare Temp Mail；上游契约固定为 X-API-Key + pool claim。
# Why: 与 gptsignup 共用 OEP 邮箱池中台，避免临时邮箱域名风控与协议分叉。

from __future__ import annotations

import os
import re
import time
import uuid
from typing import Any

import requests
from dotenv import load_dotenv


def _looks_like_date(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False
    if len(digits) == 4:
        n = int(digits)
        return 1900 <= n <= 2099
    if len(digits) == 8:
        year, month, day = int(digits[:4]), int(digits[4:6]), int(digits[6:8])
        return 1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31
    return False


def _normalize_mail_text(text: str) -> str:
    if not text:
        return ""
    if "<" in text and ">" in text:
        text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", text)
        text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = text.replace("&nbsp;", " ").replace("&amp;", "&")
        text = text.replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"\s+", " ", text).strip()


def extract_verification_code(text: str) -> str | None:
    """本地兜底抽码；主路径优先走 OEP verification-code。

    Why: OpenAI 正文是「temporary verification code to continue:\\n\\n303470」，
    码在关键词后换行，不是 `code: 123456` 同行格式。
    """
    if not text:
        return None
    raw = text.strip()
    plain = _normalize_mail_text(text)

    openai_like = re.search(
        r"(?is)(?:temporary\s+)?verification\s+code(?:\s+to\s+continue)?(.{0,80}?)(\d{4,8})\b",
        plain,
    )
    if openai_like and not _looks_like_date(openai_like.group(2)):
        return openai_like.group(2)

    delim = r"\s*(?:[:：]|\bis\b|是|为|です)[\s:：]*"
    cn_ja_ko_kw = r"验证码|认证码|确认码|認証コード|인증\s*코드|코드"
    en_kw = r"verification\s*code|confirm(?:ation)?\s*code|security\s*code|passcode|OTP|pin\s*code"
    all_kw = f"{cn_ja_ko_kw}|{en_kw}"
    patterns = [
        re.compile(rf"\bcode{delim}(\d{{4,12}})\b", re.I),
        re.compile(rf"(?:{all_kw}){delim}(\d{{4,12}})\b", re.I),
        re.compile(rf"\bcode{delim}([A-Za-z0-9-]{{4,12}})\b", re.I),
        re.compile(rf"(?:{all_kw}){delim}([A-Za-z0-9-]{{4,12}})\b", re.I),
    ]
    for source in (plain, raw):
        for pattern in patterns:
            match = pattern.search(source)
            if match and match.group(1) and not _looks_like_date(match.group(1).replace("-", "")):
                return match.group(1)
    standalone = re.search(r"(?:^|\s)(\d{4,12})(?:\s|$|\.|,)", plain, re.M)
    if standalone and not _looks_like_date(standalone.group(1)):
        return standalone.group(1)
    return None


class EmailService:
    """Outlook Email Plus 邮箱池适配。"""

    def __init__(self) -> None:
        load_dotenv()
        self.base_url = (
            os.getenv("OEP_BASE_URL")
            or os.getenv("MAIL_BASE_URL")
            or ""
        ).rstrip("/")
        if self.base_url and not self.base_url.startswith("http"):
            self.base_url = f"https://{self.base_url}"

        self.api_key = (
            os.getenv("OEP_API_KEY")
            or os.getenv("MAIL_API_KEY")
            or os.getenv("MAIL_ADMIN_PASSWORD")
            or ""
        ).strip()
        self.provider = (os.getenv("OEP_PROVIDER") or "outlook").strip()
        self.project_key = (os.getenv("OEP_PROJECT_KEY") or "codex_register").strip()
        self.caller_id = (
            os.getenv("OEP_CALLER_ID") or os.getenv("HOSTNAME") or "codex_register"
        ).strip()

        # Why: 分组移动走管理端 /login 会话，不是 X-API-Key 对外池接口。
        self.admin_password = (
            os.getenv("OEP_ADMIN_PASSWORD")
            or os.getenv("OEP_LOGIN_PASSWORD")
            or ""
        ).strip()
        self.group_success = (os.getenv("OEP_GROUP_SUCCESS") or "GPT success").strip()
        self.group_failure = (os.getenv("OEP_GROUP_FAILURE") or "Garbage").strip()

        if not self.base_url:
            raise ValueError("Missing: OEP_BASE_URL (or MAIL_BASE_URL)")
        if not self.api_key:
            raise ValueError("Missing: OEP_API_KEY")
        if self.provider == "cloudflare_temp_mail":
            raise ValueError(
                "OEP_PROVIDER=cloudflare_temp_mail 已弃用；请改用 outlook/imap 等长期邮箱池"
            )

        self._headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # email -> lease metadata
        self._leases: dict[str, dict[str, Any]] = {}
        # 管理端会话 + 分组名→id 缓存
        self._admin_session: requests.Session | None = None
        self._group_id_cache: dict[str, int] = {}

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _ensure_admin_session(self) -> requests.Session | None:
        """POST /login + CSRF，建立管理端 cookie 会话。"""
        if not self.admin_password:
            return None
        if self._admin_session is not None:
            return self._admin_session
        session = requests.Session()
        session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )
        try:
            res = session.post(
                self._url("/login"),
                json={"password": self.admin_password},
                timeout=20,
            )
            payload = res.json() if res.content else {}
            if not payload.get("success"):
                print(f"[-] OEP 管理端登录失败: {payload.get('message') or res.status_code}")
                return None
            # Why: batch-update-group 等写接口要 X-CSRFToken，否则报「会话已失效」。
            csrf_res = session.get(self._url("/api/csrf-token"), timeout=20)
            csrf_payload = csrf_res.json() if csrf_res.content else {}
            token = csrf_payload.get("csrf_token")
            if token:
                session.headers["X-CSRFToken"] = str(token)
            self._admin_session = session
            return session
        except Exception as exc:
            print(f"[-] OEP 管理端登录异常: {exc}")
            return None

    def _invalidate_admin_session(self) -> None:
        self._admin_session = None

    def _resolve_group_id(self, group_name: str) -> int | None:
        name = (group_name or "").strip()
        if not name:
            return None
        if name in self._group_id_cache:
            return self._group_id_cache[name]
        session = self._ensure_admin_session()
        if session is None:
            return None
        try:
            res = session.get(self._url("/api/groups"), timeout=20)
            payload = res.json() if res.content else {}
            if not payload.get("success"):
                print(f"[-] 拉取 OEP 分组失败: {payload.get('message') or res.status_code}")
                return None
            for item in payload.get("groups") or []:
                gname = str(item.get("name") or "").strip()
                gid = item.get("id")
                if gname and gid is not None:
                    self._group_id_cache[gname] = int(gid)
            return self._group_id_cache.get(name)
        except Exception as exc:
            print(f"[-] 解析 OEP 分组异常: {exc}")
            return None

    def move_account_to_group(self, account_id: int | str, group_name: str) -> bool:
        """POST /api/accounts/batch-update-group（管理端 + CSRF）。

        Contract: 需要 OEP_ADMIN_PASSWORD；目标组不能是系统组。
        """
        if account_id is None or not group_name:
            return False
        group_id = self._resolve_group_id(group_name)
        if group_id is None:
            print(
                f"[-] 无法移动账号 {account_id}：分组「{group_name}」不存在"
                f"{' 或未配置 OEP_ADMIN_PASSWORD' if not self.admin_password else ''}"
            )
            return False

        def _do_move(session: requests.Session) -> tuple[bool, str]:
            res = session.post(
                self._url("/api/accounts/batch-update-group"),
                json={"account_ids": [int(account_id)], "group_id": int(group_id)},
                timeout=20,
            )
            payload = res.json() if res.content else {}
            if payload.get("success"):
                return True, ""
            msg = str(
                (payload.get("error") or {}).get("message")
                or payload.get("message")
                or res.status_code
            )
            return False, msg

        session = self._ensure_admin_session()
        if session is None:
            return False
        try:
            ok, msg = _do_move(session)
            # CSRF/会话失效时重建一次
            if not ok and any(
                x in msg for x in ("CSRF", "会话", "session", "token", "登录")
            ):
                self._invalidate_admin_session()
                session = self._ensure_admin_session()
                if session is None:
                    print(f"[-] 移动分组失败 account_id={account_id}: {msg}")
                    return False
                ok, msg = _do_move(session)
            if ok:
                print(f"[*] 邮箱 account_id={account_id} → 分组「{group_name}」")
            else:
                print(
                    f"[-] 移动分组失败 account_id={account_id} group={group_name}: {msg}"
                )
            return ok
        except Exception as exc:
            print(f"[-] 移动分组异常: {exc}")
            return False

    def create_email(self) -> tuple[str | None, str | None]:
        """领取邮箱：POST /api/external/pool/claim-random。

        返回 (claim_token, email)，保持调用方解构兼容。
        """
        task_id = f"codex-{uuid.uuid4().hex[:16]}"
        body: dict[str, Any] = {
            "caller_id": self.caller_id,
            "task_id": task_id,
            "provider": self.provider,
        }
        if self.project_key:
            body["project_key"] = self.project_key
        try:
            res = requests.post(
                self._url("/api/external/pool/claim-random"),
                headers=self._headers,
                json=body,
                timeout=20,
            )
            payload = res.json() if res.content else {}
            if not payload.get("success"):
                print(
                    f"[-] 领取邮箱失败: {payload.get('code')} - {payload.get('message')}"
                )
                return None, None
            data = payload.get("data") or {}
            email = data.get("email")
            claim_token = data.get("claim_token")
            account_id = data.get("account_id")
            if not email or not claim_token or account_id is None:
                print(f"[-] 领取邮箱失败: 响应缺字段 - {data}")
                return None, None
            self._leases[email] = {
                "account_id": account_id,
                "claim_token": claim_token,
                "caller_id": self.caller_id,
                "task_id": task_id,
            }
            return claim_token, email
        except Exception as exc:
            print(f"[-] 领取邮箱失败: {exc}")
            return None, None

    def fetch_verification_code(self, email: str, max_attempts: int = 40) -> str | None:
        """优先 OEP verification-code；失败再读 messages 本地抽码。"""
        if email not in self._leases:
            print(f"[-] 无法获取验证码: 未找到租约 ({email})")
            return None

        interval = 2
        params = {
            "email": email,
            "since_minutes": 15,
            "folder": "inbox",
        }
        for attempt in range(max_attempts):
            try:
                res = requests.get(
                    self._url("/api/external/verification-code"),
                    headers=self._headers,
                    params=params,
                    timeout=20,
                )
                payload = res.json() if res.content else {}
                if payload.get("success"):
                    data = payload.get("data") or {}
                    code = data.get("code") or data.get("verification_code")
                    if code:
                        return str(code).replace("-", "")
                code = self._fetch_code_from_messages(email)
                if code:
                    return code
            except Exception:
                pass
            time.sleep(interval)
            if attempt > 0 and attempt % 5 == 0:
                interval = min(interval + 1, 5)
        return None

    def _fetch_code_from_messages(self, email: str) -> str | None:
        res = requests.get(
            self._url("/api/external/messages"),
            headers=self._headers,
            params={"email": email, "top": 10, "since_minutes": 30},
            timeout=20,
        )
        payload = res.json() if res.content else {}
        if not payload.get("success"):
            return None
        data = payload.get("data") or {}
        emails = data.get("emails") or data.get("messages") or []
        # OEP list 摘要字段是 content_preview；详情才有 content
        fields = (
            "subject",
            "content_preview",
            "content",
            "html_content",
            "text",
            "html",
        )
        for mail in emails:
            for field in fields:
                code = extract_verification_code(str(mail.get(field) or ""))
                if code:
                    return code.replace("-", "")
            msg_id = mail.get("id")
            if not msg_id:
                continue
            detail = self._fetch_message_detail(email, str(msg_id))
            if not detail:
                continue
            for field in fields:
                code = extract_verification_code(str(detail.get(field) or ""))
                if code:
                    return code.replace("-", "")
        return None

    def _fetch_message_detail(self, email: str, message_id: str) -> dict[str, Any] | None:
        try:
            res = requests.get(
                self._url(f"/api/external/messages/{message_id}"),
                headers=self._headers,
                params={"email": email},
                timeout=20,
            )
            payload = res.json() if res.content else {}
            if not payload.get("success"):
                return None
            data = payload.get("data")
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def complete_email(
        self,
        address: str,
        *,
        result: str = "success",
        detail: str = "",
        group_name: str | None = None,
    ) -> bool:
        """任务成功/终态：POST /api/external/pool/claim-complete。

        Contract: 默认**不**移分组；调用方在整轮注册结束后显式传入 group_name。
        """
        return self._finish(
            address,
            mode="complete",
            result=result,
            detail=detail,
            group_name=group_name,
        )

    def delete_email(self, address: str, *, group_name: str | None = None) -> bool:
        """中途放弃：POST /api/external/pool/claim-release。

        Contract: 默认不移分组；需要时由调用方传入 group_name。
        """
        return self._finish(address, mode="release", group_name=group_name)

    def finalize_registration(
        self,
        address: str,
        *,
        outcome: str,
        detail: str = "",
    ) -> bool:
        """整轮注册结束后的唯一收尾：池状态 + 分组移动。

        outcome:
          - success → claim-complete(success) + GPT success
          - blocked → claim-complete(provider_blocked) + Garbage
          - failure → claim-release + Garbage
        """
        if outcome == "success":
            return self.complete_email(
                address,
                result="success",
                detail=detail or "codex_registered",
                group_name=self.group_success,
            )
        if outcome == "blocked":
            return self.complete_email(
                address,
                result="provider_blocked",
                detail=detail or "provider_blocked",
                group_name=self.group_failure,
            )
        return self.delete_email(
            address,
            group_name=self.group_failure,
        )

    def _finish(
        self,
        address: str,
        *,
        mode: str,
        result: str = "success",
        detail: str = "",
        group_name: str | None = None,
    ) -> bool:
        if not address:
            return False
        lease = self._leases.pop(address, None)
        if not lease:
            return False
        body = {
            "account_id": lease["account_id"],
            "claim_token": lease["claim_token"],
            "caller_id": lease["caller_id"],
            "task_id": lease["task_id"],
        }
        ok = False
        try:
            if mode == "complete":
                body["result"] = result
                if detail:
                    body["detail"] = detail
                path = "/api/external/pool/claim-complete"
            else:
                body["reason"] = detail or "registration_aborted"
                path = "/api/external/pool/claim-release"
            res = requests.post(
                self._url(path),
                headers=self._headers,
                json=body,
                timeout=20,
            )
            payload = res.json() if res.content else {}
            ok = bool(payload.get("success"))
        except Exception:
            ok = False

        # Boundary: 仅当调用方显式要求时才移组（整轮结束后）。
        if group_name:
            try:
                self.move_account_to_group(lease["account_id"], group_name)
            except Exception as exc:
                print(f"[-] 分组移动跳过: {exc}")
        return ok
