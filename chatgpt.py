import json
import os
import re
import time
import uuid
import random
import string
import secrets
import hashlib
import base64
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Any, Dict, Optional
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests
from curl_cffi.requests import Session

from email_service import EmailService
from phone_flow import handle_add_phone
from sentinel import build_sentinel_token

# 配置输出目录和请求UA
OUT_DIR = Path(__file__).parent.resolve()
AUTH_BASE = "https://auth.openai.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ========== 1. OpenAI OAuth2 授权与环境生成模块 ==========

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
# 原注册路径：Codex CLI client
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

# 仅这些 page 允许继续走注册步骤；login_* 再调 register 必 400 invalid_auth_step。
_SIGNUP_PAGE_TYPES = frozenset(
    {
        "create_account_password",
        "email_otp_verification",
    }
)
_DIRTY_PAGE_TYPES = frozenset(
    {
        "login_password",
        "login",
        "login_email_verification",
        "email_otp_verification_with_code",
    }
)

def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    special = "!@#$%^&*.-"
    base = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(special),
    ]
    base += [random.choice(alphabet + special) for _ in range(12)]
    random.shuffle(base)
    return "".join(base)

def _random_name() -> str:
    # Why: about-you 更吃真实英文名；随机字母串更容易被拒。
    return random.choice(
        ["James", "Robert", "John", "Michael", "Emma", "Olivia", "Neo", "Liam"]
    )

def _random_birthdate() -> str:
    return (
        f"{random.randint(1985, 2005):04d}-"
        f"{random.randint(1, 12):02d}-"
        f"{random.randint(1, 28):02d}"
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

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())

def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)

def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)

def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "","state": "","error": "","error_description": ""}
    if "://" not in candidate:
        if candidate.startswith("?"): candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate: candidate = f"http://{candidate}"
        elif "=" in candidate: candidate = f"http://localhost/?{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values
    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()
    code = get1("code"); state = get1("state")
    error = get1("error"); error_description = get1("error_description")
    if code and not state and "#" in code:
        code, state = code.split("#",1)
    if not error and error_description:
        error, error_description = error_description, ""
    return {"code": code,"state": state,"error": error,"error_description": error_description}

def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2: return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii")).decode("utf-8"))
    except: return {}

def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw: return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try: return json.loads(base64.urlsafe_b64decode((raw + pad).encode("ascii")).decode("utf-8"))
    except: return {}

def _to_int(v: Any) -> int:
    try: return int(v)
    except: return 0

def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200: raise RuntimeError(f"token exchange failed: {resp.status}")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token exchange failed: {exc.code}") from exc

@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str

def generate_oauth_url(*, email: str = "") -> OAuthStart:
    """Codex CLI OAuth 入口（原注册路径）。"""
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "screen_hint": "signup",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    if email:
        params["login_hint"] = email
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=DEFAULT_REDIRECT_URI,
    )

def _set_device_cookie(session, device_id: str) -> None:
    for domain in (".auth.openai.com", "auth.openai.com", ".chatgpt.com", "chatgpt.com"):
        try:
            session.cookies.set("oai-did", device_id, domain=domain, path="/")
        except Exception:
            pass

def _page_type_from_resp(resp) -> str:
    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    return str((data.get("page") or {}).get("type") or "")

def _retire_dirty_email(email_service: EmailService, email: str, page_type: str) -> bool:
    """脏号 complete(provider_blocked) 冻结出池，避免 release 回 available 再踩。"""
    try:
        return bool(
            email_service.complete_email(
                email,
                result="provider_blocked",
                detail=f"not_signup_page:{page_type or 'empty'}",
            )
        )
    except Exception:
        return False

def fetch_sentinel_token(*, flow: str, did: str, proxies: Any = None, session: Any = None) -> Optional[str]:
    """返回完整 openai-sentinel-token 头（含 PoW p 字段）。"""
    return build_sentinel_token(
        device_id=did,
        flow=flow,
        proxies=proxies,
        session=session,
        ua=UA,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    """提取重定向中的 Code 并换取最终的 Access / Refresh Token"""
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        raise RuntimeError(f"oauth error: {cb['error']}")
    if not cb["code"] or not cb["state"]:
        raise ValueError("callback missing code/state")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ========== 2. 核心注册与提取流程 ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    # Boundary: 邮箱只走 OEP 池 claim/complete/release，不再创建 mail.tm 临时地址。
    email_service = EmailService()
    email = None
    finished = False

    print("[*] 初始化请求，从 Outlook Email Plus 领取邮箱...")
    try:
        _claim_token, email = email_service.create_email()
        if not email:
            print("[Error] 领取 OEP 邮箱失败")
            return None

        password = _gen_password()
        print(f"[*] 成功获取邮箱: {email}")
        print(f"[*] 生成高强度密码: {password}")

        # 原路径：Codex CLI OAuth 注册并提取 token
        oauth = generate_oauth_url(email=email)
        print("[*] 使用 Codex client 注册...")

        # 第一步：进入 OAuth
        resp = s.get(
            oauth.auth_url,
            headers=_nav_headers("https://chatgpt.com/"),
            timeout=30,
            allow_redirects=True,
        )
        did = str(s.cookies.get("oai-did") or "").strip() or str(uuid.uuid4())
        _set_device_cookie(s, did)
        print(f"[*] device_id={did}")

        # 第二步：authorize_continue
        sentinel = fetch_sentinel_token(
            flow="authorize_continue", did=did, proxies=proxies, session=s
        )
        signup_headers = _json_headers(f"{AUTH_BASE}/create-account", did)
        if sentinel:
            signup_headers["openai-sentinel-token"] = sentinel
        signup_resp = s.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            headers=signup_headers,
            data=json.dumps(
                {"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}
            ),
            timeout=30,
        )
        if signup_resp.status_code != 200:
            print(f"[Error] 提交邮箱失败: {signup_resp.status_code} {_snip(signup_resp)}")
            return None

        page_type = _page_type_from_resp(signup_resp)
        print(f"[*] authorize/continue page={page_type or '?'}")

        # Why: login_password 等页再调 register 必 invalid_auth_step 400。
        if page_type in _DIRTY_PAGE_TYPES or page_type not in _SIGNUP_PAGE_TYPES:
            if _retire_dirty_email(email_service, email, page_type):
                finished = True
            print(
                f"[Error] 邮箱不可注册: page={page_type or 'empty'} "
                f"(已从池冻结/释放；换新邮箱重试)"
            )
            return None

        # 第三步：仅在 create_account_password 时设密
        if page_type != "email_otp_verification":
            register_headers = _json_headers(f"{AUTH_BASE}/create-account/password", did)
            reg_body = json.dumps({"username": email, "password": password})
            reg_resp = s.post(
                f"{AUTH_BASE}/api/accounts/user/register",
                headers=register_headers,
                data=reg_body,
                timeout=30,
            )
            if reg_resp.status_code != 200:
                register_headers["openai-sentinel-token"] = (
                    fetch_sentinel_token(
                        flow="username_password_create",
                        did=did,
                        proxies=proxies,
                        session=s,
                    )
                    or ""
                )
                reg_resp = s.post(
                    f"{AUTH_BASE}/api/accounts/user/register",
                    headers=register_headers,
                    data=reg_body,
                    timeout=30,
                )
            if reg_resp.status_code != 200:
                print(
                    f"[Error] 设置密码失败: {reg_resp.status_code} {_snip(reg_resp)}"
                )
                return None
            print("[*] password set")

            s.get(
                f"{AUTH_BASE}/api/accounts/email-otp/send",
                headers=_nav_headers(f"{AUTH_BASE}/create-account/password"),
                timeout=15,
            )
        else:
            print("[*] 已在 OTP 页，跳过设密")

        # 第四步：提取验证码
        print("[*] 正在等待 OEP 验证码...")
        code = email_service.fetch_verification_code(email)
        if not code:
            print("[Error] 验证码等待超时或提取失败")
            return None
        print(f"[*] 成功提取验证码: {code}")

        # 第五步：校验验证码
        validate_headers = _json_headers(f"{AUTH_BASE}/email-verification", did)
        code_resp = s.post(
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            headers=validate_headers,
            data=json.dumps({"code": code}),
            timeout=30,
        )
        if code_resp.status_code != 200:
            validate_headers["openai-sentinel-token"] = (
                fetch_sentinel_token(
                    flow="authorize_continue", did=did, proxies=proxies, session=s
                )
                or ""
            )
            code_resp = s.post(
                f"{AUTH_BASE}/api/accounts/email-otp/validate",
                headers=validate_headers,
                data=json.dumps({"code": code}),
                timeout=30,
            )
        if code_resp.status_code != 200:
            print(f"[Error] 验证码校验失败: {code_resp.status_code} {_snip(code_resp)}")
            return None

        try:
            otp_data = code_resp.json() or {}
        except Exception:
            otp_data = {}
        page_type = str((otp_data.get("page") or {}).get("type") or "")
        continue_after_otp = str(otp_data.get("continue_url") or "").strip()
        if continue_after_otp:
            try:
                s.get(
                    continue_after_otp,
                    headers=_nav_headers(f"{AUTH_BASE}/email-verification"),
                    timeout=15,
                    allow_redirects=True,
                )
            except Exception:
                pass
        print(f"[*] after OTP page={page_type or '?'}")
        if page_type == "add_phone":
            # Why: Codex 路径常见 add_phone；接 Tiger SMS 自动过手机验证。
            next_page = handle_add_phone(
                s, device_id=did, proxies=proxies
            )
            if not next_page:
                print("[Error] 手机验证失败（取号/收码/校验均未通过）")
                return None
            page_type = next_page
            print(f"[*] after phone page={page_type or '?'}")

        # 第六步：about-you + create_account
        if page_type not in ("email_otp_verification", "add_phone"):
            try:
                s.get(
                    f"{AUTH_BASE}/about-you",
                    headers=_nav_headers(f"{AUTH_BASE}/email-verification"),
                    timeout=15,
                    allow_redirects=True,
                )
            except Exception:
                pass

            create_headers = _json_headers(f"{AUTH_BASE}/about-you", did)
            create_sentinel = fetch_sentinel_token(
                flow="oauth_create_account", did=did, proxies=proxies, session=s
            )
            if create_sentinel:
                create_headers["openai-sentinel-token"] = create_sentinel
            user_info = {"name": _random_name(), "birthdate": _random_birthdate()}
            create_resp = s.post(
                f"{AUTH_BASE}/api/accounts/create_account",
                headers=create_headers,
                data=json.dumps(user_info),
                timeout=30,
                allow_redirects=False,
            )
            if create_resp.status_code not in (200, 302, 303):
                body = _snip(create_resp)
                if "registration_disallowed" in body:
                    print(
                        "[Error] registration_disallowed：邮箱域名或 IP 被拒，"
                        f"换 OEP 池内账号/代理后重试。 raw={body}"
                    )
                else:
                    print(f"[Error] 账户信息填写失败: {create_resp.status_code} {body}")
                return None
            print("[*] create_account ok")

        # 第七步：选择工作区 Workspace
        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            print("[Error] 缺少 oai-client-auth-session")
            return None
        auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id") or "").strip()
        if not workspace_id:
            print("[Error] 未拿到 workspace_id")
            return None

        select_resp = s.post(
            f"{AUTH_BASE}/api/accounts/workspace/select",
            headers={
                "referer": f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
                "origin": AUTH_BASE,
                "oai-device-id": did,
                "accept": "application/json",
                "user-agent": UA,
            },
            data=json.dumps({"workspace_id": workspace_id}),
            timeout=30,
        )
        if select_resp.status_code != 200:
            print(f"[Error] workspace/select 失败: {select_resp.status_code} {_snip(select_resp)}")
            return None

        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()

        # 第八步：拦截重定向，提取 Codex Token
        current_url = continue_url
        for _ in range(8):
            if not current_url:
                break
            if "code=" in current_url and "state=" in current_url:
                token_json = submit_callback_url(
                    callback_url=current_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )
                try:
                    email_service.complete_email(
                        email, result="success", detail="codex_registered"
                    )
                except Exception:
                    pass
                finished = True
                return token_json, email, password

            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""
            if final_resp.status_code not in [301, 302, 303, 307, 308] or not location:
                break
            current_url = urllib.parse.urljoin(current_url, location)

        print("[Error] 未能在重定向链中捕获到最终 Token")
        return None

    except Exception as e:
        print(f"[Error] 运行时异常: {e}")
        return None
    finally:
        # 失败/中断：释放租约，避免邮箱卡在 claimed
        if email and not finished:
            try:
                email_service.delete_email(email)
            except Exception:
                pass


# ========== 3. 主程序轮询与保存 ==========

def main():
    parser = argparse.ArgumentParser(description="OpenAI Codex 自动注册脚本 (Outlook Email Plus)")
    parser.add_argument("--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890")
    parser.add_argument("--once", action="store_true", help="只运行一次")
    args = parser.parse_args()

    count = 0
    print("========================================")
    print("OpenAI Codex 注册机 (OEP 邮箱池 + Token 提取)")
    print("========================================")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<")
        run_result = run(args.proxy)

        if run_result:
            token_json, email, password = run_result
            fname_email = email.replace("@", "_")

            # 保存机制 1：单独保存 Token JSON 文件
            tokens_dir = OUT_DIR / "tokens"
            tokens_dir.mkdir(parents=True, exist_ok=True)
            file_path = tokens_dir / f"token_{fname_email}_{int(time.time())}.json"
            file_path.write_text(token_json, encoding="utf-8")
            print(f"[OK] 成功获取 Token！已保存至: {file_path}")

            # 保存机制 2：汇总账号密码信息
            acc_file = tokens_dir / "accounts.txt"
            with open(acc_file, "a", encoding="utf-8") as f:
                f.write(f"{email}----{password}\n")
            print(f"[OK] 账号已追加至: {acc_file}")

        else:
            print("[-] 本次注册流程断开。")

        if args.once:
            break

        wait_time = random.randint(5, 15)
        print(f"[*] 冷却 {wait_time} 秒...")
        time.sleep(wait_time)

if __name__ == "__main__":
    main()
