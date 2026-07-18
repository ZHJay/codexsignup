# OpenAI / ChatGPT 全自动注册机 & Token 提取器

基于 `curl_cffi` 的 Codex OAuth 注册脚本：自动注册并提取 `access_token` / `refresh_token`。

## 邮箱后端

**Outlook Email Plus** 邮箱池（`/api/external/*`），与 `gptsignup` 同源，不再使用 `mail.tm`。

| 步骤 | 接口 |
|------|------|
| 领取邮箱 | `POST /api/external/pool/claim-random` |
| 取验证码 | `GET /api/external/verification-code` |
| 成功回写 | `POST /api/external/pool/claim-complete` |
| 失败释放 | `POST /api/external/pool/claim-release` |

前置条件：在 Outlook Email Plus 管理面板导入可用的 **Outlook/IMAP 账号** 到邮箱池（`provider=outlook` 或 `imap`），并开启对外 API + 邮箱池。

## 手机验证（Tiger SMS v2）

OTP 后若出现 `add_phone`，自动：

1. `getNumberV2`（`service=dr`，`country=1001` 美国 VIP）取号  
2. `POST /api/accounts/add-phone/send` 提交完整 E.164（如 `+1304…`；UI 虽只显示本地号，API 要带国家码）  
3. `getStatusV2` 轮询短信码  
4. `POST /api/accounts/phone-otp/validate` 校验  
5. 成功 `setStatusV2 status=6`；超时/失败 `status=8` 取消，最多换号 3 次  

| 步骤 | Tiger SMS |
|------|-----------|
| 取号 | `getNumberV2` |
| 收码 | `getStatusV2` |
| 完成 | `setStatusV2` (`6`) |
| 取消 | `setStatusV2` (`8`) |

## 快速开始

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 填 OEP_* 与 TIGER_SMS_API_KEY
python chatgpt.py                  # 循环注册
python chatgpt.py --once           # 只跑一次
python chatgpt.py --once --proxy "http://127.0.0.1:7890"
# 方案 C：真浏览器过 CF（VDS 被 challenge 时）
playwright install chrome
xvfb-run -a python chatgpt.py --once --browser   # 无桌面
# python chatgpt.py --once --browser             # 有桌面/RDP
```

## 方案 C：真浏览器过 Cloudflare

当 `curl` 出现 `cf-mitigated: challenge` / `Just a moment` 时：

```bash
pip install -r requirements.txt
playwright install chrome
# Linux 无桌面
sudo apt-get install -y xvfb
xvfb-run -a python chatgpt.py --once --browser
```

流程：有头 Chrome 打开 OAuth → 等 CF 消失 → 页内 fetch 提交邮箱 → cookie 同步后续 API。

| 参数/环境变量 | 说明 |
|------|------|
| `--browser` / `USE_BROWSER=1` | 启用浏览器过 CF |
| `--browser-headless` / `BROWSER_HEADLESS=1` | 无头（通常更难过 CF） |
| `BROWSER_CHANNEL` | 默认 `chrome`，可改 `chromium` |
| `BROWSER_CF_TIMEOUT_MS` | 等 CF 超时毫秒，默认 `120000` |

## 环境变量

| 变量 | 说明 |
|------|------|
| `OEP_BASE_URL` | Outlook Email Plus 根地址；本机可用 `http://127.0.0.1:5001`，公网 `https://outlook.api4kimi8.org` |
| `OEP_API_KEY` | 对外 API Key（`X-API-Key`） |
| `OEP_PROVIDER` | 池筛选，默认 `outlook`；勿用 `cloudflare_temp_mail` |
| `OEP_PROJECT_KEY` | 项目隔离 key，默认 `codex_register` |
| `OEP_CALLER_ID` | 调用方标识 |
| `OEP_ADMIN_PASSWORD` | OEP **管理端登录密码**（移动分组用，不是 API Key） |
| `OEP_GROUP_SUCCESS` | 注册成功移入的分组名，默认 `GPT success` |
| `OEP_GROUP_FAILURE` | 注册失败移入的分组名，默认 `Garbage` |
| `OEP_CLAIM_GROUP` | **仅从此分组领取**，默认 `默认分组` |
| `OEP_CLAIM_GROUP_RETRIES` | 非目标组跳过重试次数，默认 `30` |
| `TIGER_SMS_API_KEY` | Tiger SMS API Key（必填，用于 add_phone） |
| `TIGER_SMS_SERVICE` | 默认 `dr` |
| `TIGER_SMS_COUNTRY` | 默认 `1001`（美国 VIP） |
| `TIGER_SMS_MAX_PRICE` | 可选；不填则取 `getPricesV2.saleAveragePrice` |
| `TIGER_SMS_POLL_SECONDS` | 收码超时秒数，默认 `120` |
| `TIGER_SMS_NUMBER_RETRIES` | 换号次数，默认 3 |
| `IMPERSONATE` | 可选，强制 TLS 指纹（如 `chrome146`）；默认自动探测 |

## 小站 Docker 部署（自动更新）

路径：`/home/ubuntu/codexsignup`  
镜像：`codexsignup:latest`  
触发：`push main` → GitHub Actions `deploy-small` → SSH 执行 `deploy/deploy.sh`

### 服务器 bootstrap（一次性）

```bash
# 小站
cd ~
git clone https://github.com/ZHJay/codexsignup.git codexsignup
cd codexsignup
cp .env.example .env
# 编辑 .env：OEP_* / TIGER_SMS_* / OEP_ADMIN_PASSWORD
# 同机 Docker 建议：
#   OEP_BASE_URL=http://outlook-email-plus:5000
chmod 600 .env
mkdir -p tokens && chmod 700 tokens
bash deploy/deploy.sh
```

### 手动跑一轮

```bash
cd ~/codexsignup
sudo docker compose --profile tools run --rm codexsignup --once
# 可选代理
sudo docker compose --profile tools run --rm -e PROXY=http://host:port codexsignup --once --proxy http://host:port
```

### GitHub Secrets（仓库 ZHJay/codexsignup）

| Secret | 值 |
|--------|-----|
| `SMALL_HOST` | 小站 IP |
| `SMALL_USER` | `ubuntu` |
| `SMALL_SSH_KEY` | 部署私钥全文 |
| `SMALL_DEPLOY_PATH` | `/home/ubuntu/codexsignup` |

之后每次 `git push origin main` 自动 `fetch + reset --hard + compose build`。

## 产出文件

注册成功后写入 `tokens/`：

* `accounts.txt`：`email----password`
* `token_[email]_[timestamp].json`：含 `access_token` / `refresh_token` / `id_token`

## 注意事项

1. `.env` 永不提交；本机/服务器单独维护。
2. 池空会报 `NO_AVAILABLE_ACCOUNT`：先在 OEP 管理面板导入账号。
3. 失败路径会自动 `claim-release`，避免邮箱卡在 claimed。
4. 注册成功 → 分组 `GPT success`；失败/脏号/中断 → 分组 `Garbage`（需配置 `OEP_ADMIN_PASSWORD`）。
5. 仅供学习研究。
