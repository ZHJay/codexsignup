# Layer: L1 积木层
# Contract: Tiger SMS v2 取号 / 轮询验证码 / 完成或取消激活。
# Boundary: 仅对接 handler_api.php 的 *V2 动作；不触碰 OpenAI 会话。
# Why: 与 EmailService 对称，把 SMS 供应商细节从注册流程中拆出。

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from dotenv import load_dotenv


DEFAULT_BASE_URL = "https://api.tiger-sms.com/stubs/handler_api.php"
DEFAULT_SERVICE = "dr"
DEFAULT_COUNTRY = 1001
# setStatusV2: 6=完成扣费确认, 8=取消退款（-1 同 8）
STATUS_COMPLETE = 6
STATUS_CANCEL = 8


@dataclass(frozen=True)
class PhoneActivation:
    """单次号码激活租约。"""

    activation_id: str
    phone_number: str  # 供应商原始串，通常含国家码无 +
    country_phone_code: Optional[int]
    activation_cost: Optional[float]
    raw: dict[str, Any]

    @property
    def digits(self) -> str:
        return "".join(ch for ch in self.phone_number if ch.isdigit())

    @property
    def e164(self) -> str:
        """完整 E.164（含 +）；日志/调试用，不直接喂 OpenAI 表单。"""
        digits = self.digits
        if not digits:
            return self.phone_number
        if self.phone_number.strip().startswith("+"):
            return f"+{digits}"
        code = self.country_phone_code
        if code is not None:
            code_s = str(code)
            if digits.startswith(code_s):
                return f"+{digits}"
            return f"+{code_s}{digits}"
        return f"+{digits}"

    @property
    def national_number(self) -> str:
        """去掉国家码的本地号。

        Why: GPT 注册选美国区时国家码 +1 已由页面自动填写，
        再拼 +1 / 前导 1 会被当成重复区号。
        """
        digits = self.digits
        if not digits:
            return self.phone_number.strip()
        code = self.country_phone_code
        # US VIP(1001) / 美国 常见 countryPhoneCode=1；缺省时也按 1 剥
        code_s = str(code) if code is not None else "1"
        if digits.startswith(code_s) and len(digits) > len(code_s):
            return digits[len(code_s) :]
        return digits


class TigerSmsError(RuntimeError):
    """Tiger SMS 调用失败（含业务错误码）。"""

    def __init__(self, message: str, *, payload: Any = None):
        super().__init__(message)
        self.payload = payload


class PhoneService:
    """Tiger SMS v2 适配。

    Contract:
    - get_number: getNumberV2，扣余额租号
    - wait_code: getStatusV2 轮询 sms.code
    - complete / cancel: setStatusV2(6/8)
    """

    def __init__(self) -> None:
        load_dotenv()
        self.api_key = (os.getenv("TIGER_SMS_API_KEY") or "").strip()
        self.base_url = (
            os.getenv("TIGER_SMS_BASE_URL") or DEFAULT_BASE_URL
        ).strip()
        self.service = (os.getenv("TIGER_SMS_SERVICE") or DEFAULT_SERVICE).strip()
        country_raw = (os.getenv("TIGER_SMS_COUNTRY") or str(DEFAULT_COUNTRY)).strip()
        try:
            self.country = int(country_raw)
        except ValueError as exc:
            raise ValueError(f"Invalid TIGER_SMS_COUNTRY: {country_raw}") from exc

        max_price_raw = (os.getenv("TIGER_SMS_MAX_PRICE") or "").strip()
        self.max_price: Optional[float] = None
        if max_price_raw:
            self.max_price = float(max_price_raw)

        if not self.api_key:
            raise ValueError("Missing: TIGER_SMS_API_KEY")

        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    def _call(self, action: str, **params: Any) -> tuple[int, Any]:
        query: dict[str, Any] = {
            "action": action,
            "api_key": self.api_key,
            **{k: v for k, v in params.items() if v is not None},
        }
        resp = self._session.get(self.base_url, params=query, timeout=30)
        text = (resp.text or "").strip()
        # Risk: 429/401 可能是纯文本；V2 成功多为 JSON。
        try:
            data: Any = resp.json() if text else {}
        except Exception:
            data = text
        return resp.status_code, data

    def resolve_max_price(self) -> Optional[float]:
        """用 getPricesV2 的 saleAveragePrice 作 maxPrice，降低 NO_NUMBERS。"""
        if self.max_price is not None:
            return self.max_price
        try:
            status, data = self._call(
                "getPricesV2", service=self.service, country=self.country
            )
            if status != 200 or not isinstance(data, dict):
                return None
            # shape: { "1001": { "dr": { "saleAveragePrice": 0.0399, "prices": {...}}}}
            country_key = str(self.country)
            node = (data.get(country_key) or data.get(self.country) or {}).get(
                self.service
            ) or {}
            avg = node.get("saleAveragePrice")
            prices = node.get("prices") or {}
            floor = None
            if isinstance(prices, dict) and prices:
                try:
                    floor = min(float(k) for k in prices.keys())
                except Exception:
                    floor = None
            if avg is None and floor is None:
                return None
            # Invariant: maxPrice 不得低于当前最低可售桶，否则 WRONG_MAX_PRICE。
            candidates = [float(x) for x in (avg, floor) if x is not None]
            return max(candidates) if candidates else None
        except Exception:
            return None

    def get_number(self) -> PhoneActivation:
        """购买号码：getNumberV2。"""
        max_price = self.resolve_max_price()
        status, data = self._call(
            "getNumberV2",
            service=self.service,
            country=self.country,
            maxPrice=max_price,
        )
        if status != 200 or not isinstance(data, dict):
            raise TigerSmsError(
                f"getNumberV2 failed status={status} data={data!r}", payload=data
            )
        if data.get("title") or (
            "activationId" not in data and "phoneNumber" not in data
        ):
            title = data.get("title") or data.get("details") or "UNKNOWN"
            raise TigerSmsError(f"getNumberV2 error: {title}", payload=data)

        activation_id = str(data.get("activationId") or "").strip()
        phone = str(data.get("phoneNumber") or "").strip()
        if not activation_id or not phone:
            raise TigerSmsError(
                f"getNumberV2 missing fields: {data!r}", payload=data
            )

        code_raw = data.get("countryPhoneCode")
        try:
            country_phone_code = int(code_raw) if code_raw is not None else None
        except Exception:
            country_phone_code = None

        cost_raw = data.get("activationCost")
        try:
            cost = float(cost_raw) if cost_raw is not None else None
        except Exception:
            cost = None

        return PhoneActivation(
            activation_id=activation_id,
            phone_number=phone,
            country_phone_code=country_phone_code,
            activation_cost=cost,
            raw=data,
        )

    def wait_code(
        self,
        activation_id: str,
        *,
        max_wait_seconds: int = 120,
        interval_seconds: float = 3.0,
    ) -> Optional[str]:
        """轮询 getStatusV2，直到 sms.code 出现或超时。"""
        deadline = time.time() + max(5, max_wait_seconds)
        while time.time() < deadline:
            try:
                status, data = self._call("getStatusV2", id=activation_id)
            except Exception:
                time.sleep(interval_seconds)
                continue
            if status == 404:
                return None
            if status == 200 and isinstance(data, dict):
                sms = data.get("sms")
                if isinstance(sms, dict):
                    code = str(sms.get("code") or "").strip()
                    if code:
                        return code
                # 兼容偶发扁平字段
                flat = str(data.get("code") or "").strip()
                if flat and data.get("verificationType") in (1, "1"):
                    return flat
            time.sleep(interval_seconds)
        return None

    def set_status(self, activation_id: str, status_code: int) -> bool:
        try:
            status, data = self._call(
                "setStatusV2", id=activation_id, status=status_code
            )
        except Exception:
            return False
        if status == 200 and isinstance(data, dict):
            if data.get("status") == "success":
                return True
            # BAD_STATUS 等
            return False
        # EARLY_CANCEL_DENIED 等：调用方视为尽力取消
        return False

    def complete(self, activation_id: str) -> bool:
        return self.set_status(activation_id, STATUS_COMPLETE)

    def cancel(self, activation_id: str) -> bool:
        return self.set_status(activation_id, STATUS_CANCEL)
