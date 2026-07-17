#!/usr/bin/env bash
# Layer: L2 流程层（服务器部署）
# Contract: 拉取 origin/main 后重建 codexsignup:latest；保留 .env 与 tokens。
# Risk: 使用 git reset --hard，服务器上对跟踪文件的本地改动会被丢弃。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BRANCH="${DEPLOY_BRANCH:-main}"
REMOTE="${DEPLOY_REMOTE:-origin}"

# Why: 小站 ubuntu 默认不在 docker 组，优先 sudo -n docker。
if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo -n docker info >/dev/null 2>&1; then
  DOCKER=(sudo -n docker)
else
  echo "[deploy] ERROR: 无法执行 docker（需要无密码 sudo 或 docker 组）" >&2
  exit 1
fi

compose() {
  if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
    "${DOCKER[@]}" compose "$@"
  else
    "${DOCKER[@]}"-compose "$@"
  fi
}

echo "[deploy] root=$ROOT branch=$BRANCH"

if [[ ! -d .git ]]; then
  echo "[deploy] ERROR: $ROOT 不是 git 仓库" >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  echo "[deploy] ERROR: 缺少 .env（不会从 Git 拉取）。请先在服务器写入 .env" >&2
  exit 1
fi

git remote get-url "$REMOTE" >/dev/null
git fetch --prune "$REMOTE"
git checkout "$BRANCH"
git reset --hard "${REMOTE}/${BRANCH}"

mkdir -p tokens
chmod 700 tokens || true
chmod 600 .env || true
chmod +x deploy/deploy.sh || true

echo "[deploy] building image codexsignup:latest ..."
compose build --pull codexsignup

git rev-parse --short HEAD > .deployed-revision
date -u +"%Y-%m-%dT%H:%M:%SZ" > .deployed-at

echo "[deploy] OK revision=$(cat .deployed-revision) at=$(cat .deployed-at)"
echo "[deploy] run example:"
echo "  ${DOCKER[*]} compose --profile tools run --rm codexsignup --once"
