#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""大肥鱼管理面板。

职责：
  * 展示 Docker / 容器 / 服务 / QQ 登录状态。
  * 执行三个固定动作：启动机器人、停止 AI 服务、关闭整套机器人。
  * 仅操作已有容器，不 build / pull / down / rm / 删卷。

安全边界：
  * 只监听 127.0.0.1:18100，不对外暴露。
  * 全部 /api/* 需要会话；POST 额外校验 Host / Origin / 自定义头。
  * 控制台令牌只在本机后端即时读取，不落日志、不进前端存储。
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ── 固定范围 ────────────────────────────────────────────────────────────────
PANEL_DIR = Path(__file__).resolve().parent
STATIC_DIR = PANEL_DIR / "static"
RUNTIME_DIR = PANEL_DIR / "runtime"

HOST = "127.0.0.1"
PORT = 18100
ORIGIN = f"http://{HOST}:{PORT}"

DOCKER_EXE = r"D:\deepseek_flash\DockerDesktop\resources\bin\docker.exe"
DESKTOP_EXE = r"D:\deepseek_flash\DockerDesktop\Docker Desktop.exe"

CONTAINER_SNOWLUMA = "snowluma"
CONTAINER_FISH_BOT = "fish-bot"
CONTAINERS = (CONTAINER_SNOWLUMA, CONTAINER_FISH_BOT)

# 宿主侧端口（compose 已固定绑定在 127.0.0.1）
PORT_DSH = 18080
PORT_BRIDGE = 13100
PORT_SNOWLUMA_WEBUI = 16082
PORT_NOVNC = 16081

CONSOLE_IDS = ("bridge", "dsh", "snowluma", "novnc")

# 容器内令牌来源（只经后端读取）
PATH_DSH_URL = "/data/dsh-url.txt"
PATH_DSH_LOG = "/data/dsh.log"
PATH_BRIDGE_TOKEN = "/data/bridge-state/console-token"
PATH_BRIDGE_CONFIG = "/data/bridge-config.json"

# SnowLuma WebUI：密码以 scrypt 存储，无法反推；但初始密码会打印到容器 stdout，
# 且可用 (密码 + 盐) 按同样参数复算哈希来证明它确实是当前有效密码。
PATH_SNOW_WEBUI_JSON = "/app/data/config/webui.json"
SNOW_LOGIN_URL = f"http://{HOST}:{PORT_SNOWLUMA_WEBUI}/api/login"
SNOW_SCRYPT = {"n": 16384, "r": 8, "p": 1, "dklen": 64}

# noVNC 扫码页：密码是明文存放在 vnc-password（root 600），由容器入口生成/复用。
# 它比 WebUI 密码简单——直接读出来交给前端即可。
PATH_VNC_PASSWORD = "/app/data/config/vnc-password"

COOKIE_NAME = "dafeiyu_panel"
SESSION_SUBJECT = b"dafeiyu-control-panel-session-v1"

DAEMON_WAIT_SECONDS = 180
PROBE_CACHE_SECONDS = 1.2
MAX_JOBS = 40
SERVICE_WAIT_SECONDS = 120
_PROBES = ThreadPoolExecutor(max_workers=6, thread_name_prefix="panel-probe")

NO_WINDOW = 0x08000000 if os.name == "nt" else 0

KIND_LABELS = {
    "start": "启动机器人",
    "stop_ai": "停止 AI 服务",
    "stop_all": "关闭整套机器人",
}

APP_TAG = "dafeiyu-control-panel"


# ── 日志（只写脱敏结果） ────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("panel")
    log.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        RUNTIME_DIR / "panel.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.propagate = False
    return log


LOG = setup_logging()


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def redact(text: str, limit: int = 400) -> str:
    """去掉疑似令牌再入日志 / 回传前端。"""
    if not text:
        return ""
    cleaned = re.sub(r"(?i)(token|authorization|password)\s*[=:]\s*\S+", r"\1=<已隐藏>", text)
    cleaned = re.sub(r"[A-Za-z0-9_\-]{32,}", "<已隐藏>", cleaned)
    return cleaned.strip()[:limit]


# ── 进程与文件工具 ──────────────────────────────────────────────────────────
def run_cmd(args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    """参数数组启动子进程，绝不拼接 shell。"""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=NO_WINDOW,
    )


def docker(args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    return run_cmd([DOCKER_EXE] + args, timeout=timeout)


def read_container_text(container: str, path: str, timeout: float = 20.0) -> str | None:
    """用 docker cp 读容器内文件（容器停止时同样有效），不启动新容器。

    docker cp 输出的是二进制 tar 流，必须按字节读取，不能走文本模式。
    """
    try:
        proc = subprocess.run(
            [DOCKER_EXE, "cp", f"{container}:{path}", "-"],
            capture_output=True,
            timeout=timeout,
            creationflags=NO_WINDOW,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            if not members:
                return None
            handle = tar.extractfile(members[0])
            return handle.read().decode("utf-8", "replace") if handle else None
    except Exception:
        return None


# ── HTTP 探测（禁用系统代理，避免误判） ─────────────────────────────────────
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_probe(url: str, timeout: float = 3.0, headers: dict | None = None) -> dict:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
            return {"reachable": True, "status": response.status, "body": body}
    except urllib.error.HTTPError as exc:
        # 有 HTTP 响应即说明端口在监听、服务在应答
        try:
            body = exc.read(65536).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"reachable": True, "status": exc.code, "body": body}
    except Exception as exc:
        return {"reachable": False, "status": None, "error": type(exc).__name__}


def port_open(port: int, timeout: float = 1.0) -> bool:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((HOST, port)) == 0
    finally:
        sock.close()


# ── Docker 状态 ────────────────────────────────────────────────────────────
_DAEMON_CACHE = {"at": 0.0, "value": None}


def docker_daemon(force: bool = False) -> dict:
    if not force and time.time() - _DAEMON_CACHE["at"] < PROBE_CACHE_SECONDS:
        return _DAEMON_CACHE["value"]
    try:
        proc = docker(["info", "--format", "{{.ServerVersion}}"], timeout=15)
        if proc.returncode == 0 and proc.stdout.strip():
            info = {"available": True, "version": proc.stdout.strip(), "error": None}
        else:
            info = {"available": False, "version": None, "error": redact(proc.stderr) or "Docker daemon 无响应"}
    except Exception as exc:
        info = {"available": False, "version": None, "error": f"Docker CLI 调用失败：{type(exc).__name__}"}
    _DAEMON_CACHE.update({"at": time.time(), "value": info})
    return info


STATUS_RE = re.compile(r"^(Up|Exited|Created|Restarting|Paused)\b", re.I)
EXIT_CODE_RE = re.compile(r"Exited \((\d+)\)")


def container_states() -> dict:
    """One inspect call returns real state, exit code and Docker health."""
    result = {name: {"state": "missing", "running": False, "exitCode": None, "health": None, "detail": "容器不存在"} for name in CONTAINERS}
    if not docker_daemon()["available"]:
        return {name: {"state": "unknown", "running": False, "exitCode": None, "health": None, "detail": "Docker 不可用"} for name in CONTAINERS}
    try:
        proc = docker(["inspect", *CONTAINERS], timeout=5)
        records = json.loads(proc.stdout or "[]")
        if not isinstance(records, list):
            raise ValueError()
        for record in records:
            name = record.get("Name", "").lstrip("/")
            if name not in result:
                continue
            state = record.get("State") or {}
            running = state.get("Running") is True
            health = (state.get("Health") or {}).get("Status") if running else None
            detail = "运行中" if running else "已停止"
            if health:
                detail += " · 健康检查 " + {"healthy": "正常", "unhealthy": "异常", "starting": "启动中"}.get(health, health)
            result[name] = {"state": state.get("Status", "unknown"), "running": running,
                            "exitCode": state.get("ExitCode") if not running else None,
                            "health": health, "detail": detail}
        if proc.returncode and not records and 'No such' not in proc.stderr:
            raise ValueError()
    except Exception as exc:
        return {name: {"state": "unknown", "running": False, "exitCode": None, "health": None, "detail": "容器查询失败：" + type(exc).__name__} for name in CONTAINERS}
    return result


# ── 令牌读取（即时、不缓存、不落前端） ──────────────────────────────────────
def read_dsh_url() -> tuple[str | None, str]:
    """返回 (宿主侧可用地址, 说明)。

    原文形如 http://<容器IP>:3080/?token=xxx。

    优先读 /data/dsh-url.txt；该文件可能因启动时序竞争而是空的（旧版 entrypoint
    在 DSH 打印地址之前就做了 grep），所以这里再兜底直接扫 dsh.log ——
    日志里那行才是权威来源，且 DSH 每次重启都会重新生成 token。
    """
    text = read_container_text(CONTAINER_FISH_BOT, PATH_DSH_URL)
    raw = ""
    source = "dsh-url.txt"
    if text and text.strip():
        raw = text.strip().splitlines()[0].strip()
    else:
        log_text = read_container_text(CONTAINER_FISH_BOT, PATH_DSH_LOG)
        if log_text:
            matches = re.findall(r"http://[^\s]*token=[^\s]+", log_text)
            if matches:
                raw = matches[-1]          # 取最后一次：重启后以最新 token 为准
                source = "dsh.log（回退）"

    if not raw:
        return None, "容器内未找到 DSH 访问地址（dsh-url.txt 为空且日志中无 token 行）"

    try:
        parts = urllib.parse.urlsplit(raw)
    except Exception:
        return None, "DSH 地址格式无法解析"
    if not parts.query:
        return None, "DSH 地址中缺少令牌参数"
    # 容器内地址对宿主不可达：统一改写到宿主映射端口，保留路径与查询参数
    host_url = urllib.parse.urlunsplit(("http", f"{HOST}:{PORT_DSH}", parts.path or "/", parts.query, ""))
    return host_url, f"来源：{source}，已按宿主映射端口改写"


def read_bridge_token() -> tuple[str | None, str]:
    """Match upstream priority: explicit config token, then generated state token."""
    raw = read_container_text(CONTAINER_FISH_BOT, PATH_BRIDGE_CONFIG, timeout=3)
    try:
        config = json.loads(raw or "{}")
        token = str(config.get("consoleToken") or "").strip()
        if token:
            return token, "来源：bridge-config.json"
    except (ValueError, AttributeError):
        pass
    token = read_container_text(CONTAINER_FISH_BOT, PATH_BRIDGE_TOKEN, timeout=3)
    if token and token.strip():
        return token.strip(), "来源：state/console-token"
    return None, "桥接控制台令牌不可用"


def bridge_snapshot() -> dict:
    token, _ = read_bridge_token()
    if not token:
        return {"_reporting": False, "_probeError": "console_token_unavailable"}
    probe = http_probe(f"http://{HOST}:{PORT_BRIDGE}/api/status", timeout=3,
                       headers={"x-console-token": token})
    status = probe.get("status")
    if status != 200:
        kind = "console_authentication_failed" if status == 401 else "console_host_rejected" if status == 403 else "console_unreachable"
        return {"_reporting": False, "_probeError": kind, "_httpStatus": status}
    try:
        value = json.loads(probe.get("body") or "")
        if not isinstance(value, dict) or type(value.get("dshReady")) is not bool:
            raise ValueError()
        return {**value, "_reporting": True}
    except (ValueError, TypeError):
        return {"_reporting": False, "_probeError": "invalid_status_response"}


ERROR_LABELS = {
    "authentication_failed": "DSH 鉴权失败（HTTP 401）",
    "host_rejected": "DSH 拒绝连接地址（HTTP 403）",
    "event_stream_disconnected": "DSH 事件流断开，正在重连",
    "unreachable": "DSH 服务不可达",
    "console_token_unavailable": "无法读取桥接控制台令牌",
    "console_authentication_failed": "桥接控制台鉴权失败",
    "console_host_rejected": "桥接控制台拒绝请求地址",
    "console_unreachable": "桥接控制台不可达",
    "invalid_status_response": "桥接返回的状态格式异常",
}


def snowluma_credential() -> tuple[str | None, dict | None, str]:
    """取出 SnowLuma 当前可用的登录密码，返回 (密码, 凭据状态, 说明)。

    WebUI 只存 scrypt 哈希，无法反推密码。初始密码由程序打印到容器 stdout，
    形如 `initial credentials: user=admin password=xxx`。取到后按同样参数
    复算 scrypt，只有与 webui.json 里的哈希一致才认为它仍然有效——这样就不会
    在密码已被用户改过、或日志是上一轮遗留时，拿一个过期密码去猜。
    """
    raw = read_container_text(CONTAINER_SNOWLUMA, PATH_SNOW_WEBUI_JSON)
    if not raw:
        return None, None, "无法读取 SnowLuma 凭据文件（容器可能未运行）"
    try:
        state = json.loads(raw)
    except Exception:
        return None, None, "SnowLuma 凭据文件无法解析"

    hash_hex = str(state.get("passwordHash") or "").lower()
    salt_hex = str(state.get("passwordSalt") or "")
    if not re.fullmatch(r"[0-9a-f]{128}", hash_hex) or not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
        return None, state, "SnowLuma 凭据文件格式异常"

    # 日志尾部可能被 QQ 崩溃转储（数 MB 栈信息）淹没，固定 --tail 取不到凭据行。
    # 因此先读一段尾巴，取不到再读全量；全量只在必要时付出代价。
    log_text = ""
    for tail in ("4000", "all"):
        try:
            proc = subprocess.run(
                [DOCKER_EXE, "logs", "--tail", tail, CONTAINER_SNOWLUMA],
                capture_output=True,
                timeout=40,
                creationflags=NO_WINDOW,
            )
        except Exception:
            return None, state, "读取 SnowLuma 日志失败"
        if proc.returncode != 0:
            return None, state, "读取 SnowLuma 日志失败"
        log_text = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
        if "initial credentials" in log_text:
            break

    # 只认最后一次打印的初始密码（重启会重新生成）
    matches = re.findall(r"initial credentials:\s*user=\S+\s+password=(\S+)", log_text)
    if not matches:
        return None, state, "日志中没有初始密码记录（可能已改过密码）"
    password = matches[-1]

    if not snowluma_password_matches(password, hash_hex, salt_hex):
        return None, state, "日志中的初始密码已被修改，当前密码未知"
    return password, state, "已用日志密码通过哈希校验"


def snowluma_password_matches(password: str, hash_hex: str, salt_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        got = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=SNOW_SCRYPT["n"],
            r=SNOW_SCRYPT["r"],
            p=SNOW_SCRYPT["p"],
            dklen=SNOW_SCRYPT["dklen"],
        )
        return hmac.compare_digest(got.hex(), hash_hex)
    except Exception:
        return False


def snowluma_login_url() -> tuple[str | None, str]:
    """让 SnowLuma WebUI 免密进入。

    关键事实（读前端源码确认，不是猜的）：
      前端启动时若未登录，会执行 Zn() —— 取地址里的 `?token=` 参数，然后把它
      当作 **password** 传给 POST /api/login（`se.login(n)` → `{password: n}`）。
      也就是说该参数承载的是「密码」，**不是**会话令牌；把 /api/login 返回的
      token 塞进去，前端会拿它当密码去登录并失败。

    所以这里直接放密码。先本地登录一次，仅用于确认密码有效并取得「是否需改密」
    的提示；登录失败则退回普通地址，避免给出一个无法自动登录的链接。
    """
    base = f"http://{HOST}:{PORT_SNOWLUMA_WEBUI}/"
    if not port_open(PORT_SNOWLUMA_WEBUI, timeout=1.5):
        return None, "SnowLuma WebUI 未响应（容器可能未运行）"

    password, state, note = snowluma_credential()
    if not password:
        return base, f"{note}；请手动登录"

    must_change = None
    payload = json.dumps({"password": password}).encode("utf-8")
    request = urllib.request.Request(
        SNOW_LOGIN_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=10) as response:
            result = json.loads(response.read(65536).decode("utf-8", "replace"))
        if result.get("success"):
            must_change = bool(result.get("mustChangePassword"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read(65536).decode("utf-8", "replace")).get("message") or ""
        except Exception:
            pass
        return base, f"自动登录校验失败（{detail or f'HTTP {exc.code}'}），请手动登录"
    except Exception as exc:
        # 校验只是锦上添花：网络异常时仍给出带密码的链接让浏览器自己试
        LOG.info("SnowLuma 预校验异常（不影响跳转）：%s", type(exc).__name__)
        result = {"success": True}

    if not result.get("success"):
        return base, f"自动登录校验失败（{result.get('message') or '未知原因'}），请手动登录"

    # 密码放 query：参数名必须是 token，值必须是密码
    url = f"{base}?token={urllib.parse.quote(password, safe='')}"
    if must_change:
        return url, "已自动登录；当前为初始密码，建议在页面内尽快修改"
    return url, "已自动登录"



# ── 综合状态 ───────────────────────────────────────────────────────────────
_STATUS_CACHE = {"at": 0.0, "value": None}
_STATUS_LOCK = threading.Lock()


def build_status() -> dict:
    daemon = docker_daemon()
    containers = container_states()

    fish_running = containers[CONTAINER_FISH_BOT]["running"]
    snow_running = containers[CONTAINER_SNOWLUMA]["running"]
    absent = {"reachable": False, "status": None}
    tasks = {
        "dsh": _PROBES.submit(http_probe, f"http://{HOST}:{PORT_DSH}/", 2.5) if fish_running else None,
        "bridge": _PROBES.submit(http_probe, f"http://{HOST}:{PORT_BRIDGE}/", 2.5) if fish_running else None,
        "snow": _PROBES.submit(http_probe, f"http://{HOST}:{PORT_SNOWLUMA_WEBUI}/", 2.5) if snow_running else None,
        "novnc": _PROBES.submit(port_open, PORT_NOVNC) if snow_running else None,
        "snapshot": _PROBES.submit(bridge_snapshot) if fish_running else None,
    }
    dsh_probe = tasks["dsh"].result() if tasks["dsh"] else absent
    bridge_probe = tasks["bridge"].result() if tasks["bridge"] else absent
    webui_probe = tasks["snow"].result() if tasks["snow"] else absent
    novnc_ok = tasks["novnc"].result() if tasks["novnc"] else False
    bridge_data = tasks["snapshot"].result() if tasks["snapshot"] else None
    reporting = bool(bridge_data and bridge_data.get("_reporting", True))
    diagnostics = (bridge_data.get("dsh") or {}) if reporting else {}
    error_kind = diagnostics.get("errorKind") or (bridge_data or {}).get("_probeError")
    qq = judge_qq(containers, bridge_data if reporting else None, novnc_ok)
    ready = bool(reporting and bridge_data.get("dshReady") and diagnostics.get("eventStreamConnected") is not False)
    overall_ready = bool(ready and qq["status"] == "online")
    status_unknown = not daemon.get("available") or any(c["state"] == "unknown" for c in containers.values())

    consoles_ready = {
        "bridge": bool(containers[CONTAINER_FISH_BOT]["running"] and bridge_probe.get("reachable")),
        "dsh": bool(containers[CONTAINER_FISH_BOT]["running"] and dsh_probe.get("reachable")),
        "snowluma": bool(containers[CONTAINER_SNOWLUMA]["running"] and webui_probe.get("reachable")),
        "novnc": bool(novnc_ok),
    }

    return {
        "app": APP_TAG,
        "time": now_iso(),
        "overall": {"state": "unknown" if status_unknown else "ready" if overall_ready else "degraded" if fish_running or snow_running else "stopped",
                    "label": "状态未知" if status_unknown else "机器人已就绪" if overall_ready else "连接尚未就绪" if fish_running or snow_running else "机器人已停止",
                    "detail": "Docker 或容器查询不可用，无法确认当前运行状态" if status_unknown else ERROR_LABELS.get(error_kind, "") or ("全部连接正常" if overall_ready else qq["detail"])},
        "docker": daemon,
        "containers": containers,
        "services": {
            "dsh": {
                "reachable": bool(dsh_probe.get("reachable")),
                "httpStatus": dsh_probe.get("status"),
                "note": "" if dsh_probe.get("reachable") else "端口 18080 无响应",
            },
            "bridge": {
                "reachable": bool(bridge_probe.get("reachable")),
                "httpStatus": bridge_probe.get("status"),
                "reporting": reporting,
                "ready": ready,
                "errorKind": error_kind,
                "errorLabel": ERROR_LABELS.get(error_kind, ""),
                "diagnostics": diagnostics,
                "dshReady": bool(bridge_data.get("dshReady")) if reporting else None,
                "note": "" if bridge_probe.get("reachable") else "端口 13100 无响应",
            },
            "snowlumaWebui": {
                "reachable": bool(webui_probe.get("reachable")),
                "httpStatus": webui_probe.get("status"),
            },
            "novnc": {"reachable": bool(novnc_ok)},
        },
        "qq": qq,
        "consoles": consoles_ready,
        "plugins": plugins_status(),
        "jobs": JOBS.running_summary(),
        "recent": JOBS.recent_summary(),
    }


def judge_qq(containers: dict, bridge_data: dict | None, novnc_ok: bool) -> dict:
    """严格分层：容器运行 ≠ QQ 在线。绝不用历史日志推断当前登录态。"""
    snow = containers[CONTAINER_SNOWLUMA]
    fish = containers[CONTAINER_FISH_BOT]

    if snow["state"] == "missing":
        return {"status": "unknown", "label": "未知", "detail": "snowluma 容器不存在，无法判断"}
    if not snow["running"]:
        return {"status": "not_running", "label": "未启动", "detail": "QQ 接入端容器未运行"}

    if bridge_data is None:
        if novnc_ok:
            return {
                "status": "unknown",
                "label": "未知",
                "detail": "桥接状态不可用，无法确认 QQ 登录；可打开扫码页检查",
            }
        return {"status": "unknown", "label": "未知", "detail": "AI 服务未启动，且扫码页不可达"}

    upstream = bridge_data.get("snowluma") or {}
    connected = upstream.get("connected")
    account_online = upstream.get("accountOnline")

    if connected is True and account_online is True:
        return {"status": "online", "label": "在线", "detail": "桥接已连接 SnowLuma，运行时报账号在线"}
    if connected is True and account_online is False:
        return {"status": "offline", "label": "已离线", "detail": "桥接已连接，但运行时报账号离线"}
    if connected is True:
        return {
            "status": "unknown",
            "label": "未知",
            "detail": "桥接已连接，但运行环境未上报账号在线状态",
        }
    if connected is False:
        return {
            "status": "upstream_disconnected",
            "label": "上游未连接",
            "detail": "请检查 OneBot 与 QQ 登录；不能仅凭连接失败判断需要扫码",
        }
    if not fish["running"]:
        return {"status": "unknown", "label": "未知", "detail": "AI 服务未启动，登录态无法确认"}
    return {"status": "unknown", "label": "未知", "detail": "桥接状态未包含上游连通信息"}


def cached_status() -> dict:
    with _STATUS_LOCK:
        if time.time() - _STATUS_CACHE["at"] < PROBE_CACHE_SECONDS and _STATUS_CACHE["value"]:
            return _STATUS_CACHE["value"]
        value = build_status()
        _STATUS_CACHE.update({"at": time.time(), "value": value})
        return value


# ── 任务管理 ───────────────────────────────────────────────────────────────
class JobManager:
    """后台任务：进度上报、同类复用、启停互斥。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._order: list[str] = []

    # ── 查询 ──
    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None  # 浅拷贝，steps 为同一列表

    def running_summary(self) -> list[dict]:
        with self._lock:
            return [
                {"id": job["id"], "kind": job["kind"], "label": KIND_LABELS.get(job["kind"], job["kind"])}
                for job in self._jobs.values()
                if job["status"] in ("queued", "running")
            ]

    def recent_summary(self) -> list[dict]:
        with self._lock:
            recent = list(self._jobs.values())[-5:][::-1]
            return [
                {
                    "id": job["id"],
                    "kind": job["kind"],
                    "label": KIND_LABELS.get(job["kind"], job["kind"]),
                    "status": job["status"],
                    "startedAt": job["startedAt"],
                    "finishedAt": job["finishedAt"],
                    "error": job["error"],
                    "steps": [{"label": s["label"], "state": s["state"], "detail": s["detail"]} for s in job["steps"]],
                }
                for job in recent
            ]

    # ── 提交 ──
    def submit(self, kind: str) -> tuple[dict | None, bool, str | None]:
        if kind not in KIND_LABELS:
            return None, False, "不支持的操作"
        with self._lock:
            for job in self._jobs.values():
                if job["status"] in ("queued", "running"):
                    if job["kind"] == kind:
                        return dict(job), False, None
                    return None, False, f"已有进行中的操作「{KIND_LABELS.get(job['kind'], job['kind'])}」，请等待结束"
            job = {
                "id": secrets.token_hex(6),
                "kind": kind,
                "label": KIND_LABELS[kind],
                "status": "queued",
                "startedAt": now_iso(),
                "finishedAt": None,
                "error": None,
                "steps": [],
            }
            self._jobs[job["id"]] = job
            self._order.append(job["id"])
            while len(self._order) > MAX_JOBS:
                self._jobs.pop(self._order.pop(0), None)
            job_id = job["id"]
        threading.Thread(target=self._run, args=(job_id, kind), daemon=True).start()
        return dict(job), True, None

    # ── 执行 ──
    def _step(self, job_id: str, label: str, state: str = "running", detail: str = "") -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for step in job["steps"]:
                if step["label"] == label and step["state"] == "running":
                    step["state"] = state
                    step["detail"] = detail
                    return
            job["steps"].append({"label": label, "state": state, "detail": detail})

    def _finish(self, job_id: str, status: str, error: str | None = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = status
            job["finishedAt"] = now_iso()
            job["error"] = error
            for step in job["steps"]:
                if step["state"] == "running":
                    step["state"] = "done" if status == "done" else "failed"
        if error:
            LOG.warning("任务 %s 失败：%s", job_id, redact(error))
        else:
            LOG.info("任务 %s 完成（%s）", job_id, status)

    def _run(self, job_id: str, kind: str) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["status"] = "running"
        try:
            if kind == "start":
                self._action_start(job_id)
            elif kind == "stop_ai":
                self._action_stop_ai(job_id)
            elif kind == "stop_all":
                self._action_stop_all(job_id)
            else:
                self._finish(job_id, "failed", "未知操作")
        except Exception as exc:
            self._finish(job_id, "failed", f"{type(exc).__name__}: {exc}")
        finally:
            _STATUS_CACHE.update({"at": 0.0, "value": None})
            _DAEMON_CACHE.update({"at": 0.0, "value": None})

    # ── 动作实现 ──
    def _ensure_containers(self, job_id: str) -> bool:
        states = container_states()
        missing = [name for name in CONTAINERS if states[name]["state"] == "missing"]
        if missing:
            self._step(job_id, "检查已有容器", "failed", f"缺失：{', '.join(missing)}")
            self._finish(
                job_id,
                "failed",
                f"容器 {', '.join(missing)} 不存在。管理面板不会自动重建，请按部署文档修复后再试。",
            )
            return False
        self._step(job_id, "检查已有容器", "done", "snowluma、fish-bot 均在")
        return True

    def _ensure_daemon(self, job_id: str) -> bool:
        self._step(job_id, "检查 Docker daemon")
        if docker_daemon(force=True)["available"]:
            self._step(job_id, "检查 Docker daemon", "done", "已就绪")
            return True
        self._step(job_id, "启动 Docker Desktop", "running", "正在拉起桌面端…")
        if not os.path.exists(DESKTOP_EXE):
            self._step(job_id, "启动 Docker Desktop", "failed", "未找到 Docker Desktop 可执行文件")
            self._finish(job_id, "failed", f"Docker Desktop 路径不存在：{DESKTOP_EXE}")
            return False
        try:
            subprocess.Popen(
                [DESKTOP_EXE],
                close_fds=True,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except Exception as exc:
            self._step(job_id, "启动 Docker Desktop", "failed", f"{type(exc).__name__}")
            self._finish(job_id, "failed", f"无法启动 Docker Desktop：{type(exc).__name__}")
            return False

        self._step(job_id, "等待 daemon 就绪", "running", f"最多等待 {DAEMON_WAIT_SECONDS} 秒")
        deadline = time.time() + DAEMON_WAIT_SECONDS
        while time.time() < deadline:
            time.sleep(3)
            if docker_daemon(force=True)["available"]:
                self._step(job_id, "等待 daemon 就绪", "done", "daemon 已可用")
                self._step(job_id, "启动 Docker Desktop", "done", "已拉起并等待就绪")
                return True
            remaining = int(deadline - time.time())
            self._step(job_id, "等待 daemon 就绪", "running", f"剩余约 {remaining} 秒")
        self._step(job_id, "等待 daemon 就绪", "failed", "超时")
        self._finish(job_id, "failed", f"Docker daemon 在 {DAEMON_WAIT_SECONDS} 秒内未就绪")
        return False

    def _docker_start(self, job_id: str, label: str, name: str) -> bool:
        self._step(job_id, label)
        proc = docker(["start", name], timeout=90)
        if proc.returncode == 0:
            self._step(job_id, label, "done", redact(proc.stdout) or "已启动")
            return True
        self._step(job_id, label, "failed", redact(proc.stderr) or "启动失败")
        return False

    def _docker_stop(self, job_id: str, label: str, name: str) -> bool:
        """Give supervised processes up to 35 seconds to stop; never delete volumes.

        Docker's timeout is an outer grace period. Internal supervisor timeouts
        still follow the gateway image's own configuration.
        """
        self._step(job_id, label)
        proc = docker(["stop", "--timeout", "35", name], timeout=110)
        if proc.returncode == 0:
            self._step(job_id, label, "done", "已停止")
            return True
        self._step(job_id, label, "failed", redact(proc.stderr) or "停止失败")
        return False

    def _wait_ready(self, job_id: str, label: str, probe, timeout: int = SERVICE_WAIT_SECONDS) -> bool:
        self._step(job_id, label)
        deadline = time.monotonic() + timeout
        detail = "等待服务响应"
        while time.monotonic() < deadline:
            ok, detail = probe()
            if ok:
                self._step(job_id, label, "done", detail)
                return True
            self._step(job_id, label, "running", detail)
            time.sleep(2)
        self._step(job_id, label, "failed", detail)
        self._finish(job_id, "failed", f"{label}超时：{detail}；容器保留，可修复后重试")
        return False

    def _action_start(self, job_id: str) -> None:
        if not self._ensure_daemon(job_id) or not self._ensure_containers(job_id):
            return
        if not self._docker_start(job_id, "启动 snowluma", CONTAINER_SNOWLUMA):
            self._finish(job_id, "failed", "snowluma 启动失败")
            return
        def gateway():
            result = http_probe(f"http://{HOST}:{PORT_SNOWLUMA_WEBUI}/", timeout=2)
            return result.get("reachable") and result.get("status", 500) < 500, "QQ 接入端管理服务已响应" if result.get("reachable") else "等待 SnowLuma 管理服务"
        if not self._wait_ready(job_id, "等待 SnowLuma 服务", gateway):
            return
        if not self._docker_start(job_id, "启动 fish-bot", CONTAINER_FISH_BOT):
            self._finish(job_id, "failed", "fish-bot 启动失败；snowluma 保持运行")
            return
        def ai():
            value = bridge_snapshot()
            diagnostic = value.get("dsh") or {}
            ok = value.get("dshReady") is True and diagnostic.get("eventStreamConnected") is not False
            kind = diagnostic.get("errorKind") or value.get("_probeError")
            return ok, "DSH 鉴权与桥接连接正常" if ok else ERROR_LABELS.get(kind, "等待 DSH 鉴权与事件流")
        if not self._wait_ready(job_id, "等待 AI 服务就绪", ai):
            return
        def qq_online():
            value = bridge_snapshot().get("snowluma") or {}
            return value.get("connected") is True and value.get("accountOnline") is True, "QQ 已在线" if value.get("accountOnline") else "等待 QQ 登录或 OneBot 连接，请打开扫码页检查"
        if not self._wait_ready(job_id, "确认 QQ 在线", qq_online, timeout=60):
            return
        self._step(job_id, "完成", "done", "容器、DSH 连接与 QQ 在线状态均已验证")
        self._finish(job_id, "done")

    def _action_stop_ai(self, job_id: str) -> None:
        if not self._ensure_containers(job_id):
            return
        if not self._ensure_daemon(job_id):
            return
        if not self._docker_stop(job_id, "停止 fish-bot", CONTAINER_FISH_BOT):
            self._finish(job_id, "failed", "fish-bot 停止失败，当前状态未改变")
            return
        self._step(job_id, "完成", "done", "AI 服务已停止；snowluma 与 QQ 进程保持运行")
        self._finish(job_id, "done")

    def _action_stop_all(self, job_id: str) -> None:
        if not self._ensure_containers(job_id):
            return
        if not self._ensure_daemon(job_id):
            return
        if not self._docker_stop(job_id, "停止 fish-bot", CONTAINER_FISH_BOT):
            self._finish(job_id, "failed", "fish-bot 停止失败，未继续停止 snowluma")
            return
        if not self._docker_stop(job_id, "停止 snowluma", CONTAINER_SNOWLUMA):
            self._finish(job_id, "failed", "fish-bot 已停止，但 snowluma 停止失败")
            return
        self._step(
            job_id,
            "完成",
            "done",
            "容器已停止（未删除，数据卷保留）；下次启动可能需要重新扫码登录",
        )
        self._finish(job_id, "done")


JOBS = JobManager()


# ── 会话 ───────────────────────────────────────────────────────────────────
class Session:
    def __init__(self) -> None:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        self.secret_file = RUNTIME_DIR / "session.secret"
        secret = ""
        if self.secret_file.exists():
            secret = self.secret_file.read_text(encoding="utf-8").strip()
        if len(secret) < 32:
            secret = secrets.token_hex(32)
            self.secret_file.write_text(secret, encoding="utf-8")
            try:
                os.chmod(self.secret_file, 0o600)
            except Exception:
                pass
        self.secret = secret
        self.cookie_value = hmac.new(secret.encode(), SESSION_SUBJECT, hashlib.sha256).hexdigest()

    def bootstrap_ok(self, supplied: str) -> bool:
        return bool(supplied) and hmac.compare_digest(supplied, self.secret)

    def cookie_ok(self, supplied: str) -> bool:
        return bool(supplied) and hmac.compare_digest(supplied, self.cookie_value)


SESSION = Session()


# ── HTTP 服务 ──────────────────────────────────────────────────────────────
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
}


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "DafeiyuPanel/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ── 基础 ──
    def log_message(self, fmt: str, *args) -> None:  # 不写标准错误，保持控制台干净
        return

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict, extra: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        return host in {f"{HOST}:{PORT}", f"localhost:{PORT}"}

    def _origin_ok(self) -> bool:
        origin = (self.headers.get("Origin") or "").strip().lower()
        return origin == ORIGIN.lower()

    def _cookie_session(self) -> str:
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            jar = SimpleCookie()
            jar.load(raw)
            morsel = jar.get(COOKIE_NAME)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _authed(self) -> bool:
        return SESSION.cookie_ok(self._cookie_session())

    # ── 路由 ──
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if not self._host_ok():
            self._json(403, {"error": "Host 不被允许"})
            return

        if path == "/api/ping":
            # 仅用于识别已有面板实例，不含任何敏感信息
            self._json(200, {"app": APP_TAG, "ok": True})
            return

        if path == "/":
            key = (query.get("k") or [""])[0]
            if key:
                if not SESSION.bootstrap_ok(key):
                    self._send(403, b"<h1>403</h1><p>bad bootstrap key</p>", "text/html; charset=utf-8")
                    return
                cookie = (
                    f"{COOKIE_NAME}={SESSION.cookie_value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800"
                )
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", cookie)
                for header, value in SECURITY_HEADERS.items():
                    self.send_header(header, value)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if not self._authed():
                self._send(
                    401,
                    "<h1>需要从启动入口进入</h1><p>请双击 start.bat，或使用终端里给出的引导链接。</p>".encode("utf-8"),
                    "text/html; charset=utf-8",
                )
                return
            self._serve_static("index.html")
            return

        if path in ("/app.css", "/app.js"):
            if not self._authed():
                self._json(401, {"error": "未授权"})
                return
            self._serve_static(path.lstrip("/"))
            return

        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return

        if not self._authed():
            self._json(401, {"error": "未授权"})
            return

        if path == "/api/status":
            self._json(200, cached_status())
            return

        match = re.fullmatch(r"/api/jobs/([0-9a-f]{6,32})", path)
        if match:
            job = JOBS.get(match.group(1))
            if not job:
                self._json(404, {"error": "任务不存在（可能是面板重启前提交的）"})
                return
            self._json(200, job)
            return

        self._json(404, {"error": "接口不存在"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if not self._host_ok():
            self._json(403, {"error": "Host 不被允许"})
            return
        if not self._origin_ok():
            self._json(403, {"error": "跨站请求被拒绝（Origin 不匹配）"})
            return
        if self.headers.get("X-Panel-Action") != "1":
            self._json(403, {"error": "缺少操作标记，请求被拒绝"})
            return
        if not self._authed():
            self._json(401, {"error": "未授权"})
            return
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            self._json(415, {"error": "只接受 application/json"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 8192:
            self._json(400, {"error": "请求体长度不合法"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(400, {"error": "请求体不是合法 JSON"})
            return

        if path == "/api/actions":
            action = str((body or {}).get("action") or "")
            job, created, error = JOBS.submit(action)
            if error:
                self._json(409, {"error": error})
                return
            self._json(202, {"job": job, "reused": not created})
            return

        match = re.fullmatch(r"/api/consoles/([a-z][a-z0-9_]{0,30})/open", path)
        if match:
            console_id = match.group(1)
            url, note = resolve_console(console_id)
            if not url:
                self._json(409, {"error": note})
                return
            self._json(200, {"id": console_id, "url": url, "note": note})
            return

        self._json(404, {"error": "接口不存在"})

    def do_HEAD(self) -> None:
        self.do_GET()

    def _serve_static(self, name: str) -> None:
        content_type = STATIC_FILES.get(name)
        if not content_type:
            self._json(404, {"error": "文件不存在"})
            return
        target = STATIC_DIR / name
        try:
            data = target.read_bytes()
        except Exception:
            self._json(500, {"error": "静态文件读取失败"})
            return
        self._send(200, data, content_type)


def novnc_url() -> tuple[str | None, str]:
    """noVNC 扫码页：读取明文密码并用 URL fragment 自动填入。

    为什么用 fragment（#）而不是 query（?）：
      * fragment 不会随请求发到服务器，也不进 Referer，泄露面最小；
      * noVNC 的 getConfigVar 优先读 hash、其次读 query，两种都支持。

    密码由容器入口生成并持久化在 vnc-password（root 600），重启后复用同一个值，
    因此这里直接读出来即可，不存在「猜密码」问题。
    """
    base = f"http://{HOST}:{PORT_NOVNC}/"
    if not port_open(PORT_NOVNC):
        return None, "noVNC 扫码页未响应（容器可能未运行）"

    raw = read_container_text(CONTAINER_SNOWLUMA, PATH_VNC_PASSWORD)
    if not raw or not raw.strip():
        return base, "未读到远程桌面密码，请在弹窗中手动输入"

    password = raw.strip()
    if len(password) > 128 or any(ch.isspace() for ch in password):
        return base, "远程桌面密码格式异常，请手动输入"

    fragment = urllib.parse.urlencode({"password": password, "autoconnect": "1"})
    return f"{base}#{fragment}", "已自动填入远程桌面密码"


def resolve_console(console_id: str) -> tuple[str | None, str]:
    """即时读取令牌并返回可跳转地址；不缓存、不写日志。"""
    if console_id == "snowluma":
        return snowluma_login_url()
    if console_id == "novnc":
        return novnc_url()
    if console_id == "dsh":
        url, note = read_dsh_url()
        if not url:
            return None, note
        return url, note
    if console_id == "bridge":
        token, note = read_bridge_token()
        if not token:
            return None, note
        return f"http://{HOST}:{PORT_BRIDGE}/?token={urllib.parse.quote(token, safe='')}", note
    # 外部插件：只允许注册表里登记过的 id，不接受任意 URL
    plugin = PLUGINS.get(console_id)
    if plugin:
        return resolve_plugin(plugin)
    return None, "未知入口"


# ── 外部插件接入 ───────────────────────────────────────────────────────────
# 设计要点：
#   * 只展示配置里显式登记的插件，端口/主机固定为 127.0.0.1，不接受任意域名跳转。
#   * 配置文件 plugins.json 放在仓库里（可入库），令牌等机密一律不写进去；
#     需要凭据的插件通过 tokenFile 指向容器内文件，由后端即时读取。
#   * 新增插件只改配置，不改代码。
PLUGINS_FILE = PANEL_DIR / "plugins.json"
_PLUGINS_CACHE = {"mtime": None, "value": {}}


def load_plugins() -> dict:
    """读取插件注册表；文件缺失或格式错误时返回空表，不影响主面板。"""
    try:
        stat = PLUGINS_FILE.stat()
    except OSError:
        return {}
    if _PLUGINS_CACHE["mtime"] == stat.st_mtime:
        return _PLUGINS_CACHE["value"]

    plugins: dict[str, dict] = {}
    try:
        raw = json.loads(PLUGINS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        LOG.warning("plugins.json 解析失败：%s", type(exc).__name__)
        return {}

    for item in (raw.get("plugins") or []):
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id") or "").strip()
        port = item.get("port")
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", pid):
            continue
        if not isinstance(port, int) or not (1 <= port <= 65535):
            continue
        plugins[pid] = {
            "id": pid,
            "name": str(item.get("name") or pid)[:40],
            "desc": str(item.get("desc") or "")[:80],
            "port": port,
            "path": str(item.get("path") or "/")[:120],
            "tokenFile": item.get("tokenFile"),      # 容器内路径或 null
            "container": item.get("container"),       # 由哪个容器提供
            "tokenQuery": str(item.get("tokenQuery") or "token")[:20],
            "tokenHeader": item.get("tokenHeader"),   # 若走请求头而非 query
        }
    _PLUGINS_CACHE.update({"mtime": stat.st_mtime, "value": plugins})
    return plugins


PLUGINS = load_plugins()


def plugin_container_running(plugin: dict) -> bool:
    """插件声明了容器就要求该容器运行；没声明则只看端口。"""
    name = plugin.get("container")
    if not name:
        return True
    state = container_states().get(name)
    return bool(state and state.get("running"))


def resolve_plugin(plugin: dict) -> tuple[str | None, str]:
    port = plugin["port"]
    path = plugin["path"] if plugin["path"].startswith("/") else "/" + plugin["path"]
    base = f"http://{HOST}:{port}{path}"

    if not plugin_container_running(plugin):
        return None, f"{plugin['name']} 的容器未运行"

    if not port_open(port):
        return base, "端口未监听，页面可能需要先启动该服务"

    token_file = plugin.get("tokenFile")
    if not token_file:
        return base, "无需令牌"

    container = plugin.get("container")
    if not container:
        return base, "未声明容器，无法读取令牌"

    token = read_container_text(container, str(token_file))
    if not token or not token.strip():
        return base, "未读到令牌，请手动登录"

    token = token.strip().splitlines()[0].strip()
    if len(token) > 256:
        return base, "令牌格式异常，请手动登录"

    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{plugin['tokenQuery']}={urllib.parse.quote(token, safe='')}", "已自动附加令牌"


def plugins_status() -> list[dict]:
    """给前端用的插件清单与可用性（不含任何凭据）。"""
    items = []
    for pid, plugin in PLUGINS.items():
        ready = bool(port_open(plugin["port"], timeout=0.6)) and plugin_container_running(plugin)
        items.append({
            "id": pid,
            "name": plugin["name"],
            "desc": plugin["desc"],
            "port": plugin["port"],
            "ready": ready,
        })
    return items


def main() -> int:
    # 不强制改标准输出编码：Windows 控制台走 WriteConsoleW，中文本身正常；
    # 强行转 UTF-8 反而会让 cmd 里出现乱码。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    # 已有实例识别：能 ping 通就打开原页面并退出，不启动第二个实例
    if port_open(PORT, timeout=1.0):
        probe = http_probe(f"{ORIGIN}/api/ping", timeout=2.0)
        if probe.get("reachable") and APP_TAG in str(probe.get("body") or ""):
            print("检测到面板已在运行，正在打开已有页面。")
            webbrowser.open(f"{ORIGIN}/?k={SESSION.secret}")
            return 0
        print(f"[错误] 端口 {PORT} 已被其他程序占用。")
        print("       本面板不会结束其他进程，也不会改用其他端口。请自行释放该端口后重试。")
        return 1

    try:
        server = ThreadingHTTPServer((HOST, PORT), PanelHandler)
    except OSError as exc:
        print(f"[错误] 无法监听 {HOST}:{PORT} —— {exc}")
        print("       端口冲突时请先释放端口；面板不会静默更换端口。")
        return 1
    server.daemon_threads = True

    print(f"大肥鱼管理面板已启动：{ORIGIN}/")
    print("若浏览器未自动打开，请手动访问上面的地址。")
    print("（首次进入需要使用带引导参数的链接，见下方）")
    print(f"引导链接：{ORIGIN}/?k={SESSION.secret}")
    LOG.info("面板启动，监听 %s:%s", HOST, PORT)
    if "--no-open" not in sys.argv:
        threading.Thread(target=lambda: webbrowser.open(f"{ORIGIN}/?k={SESSION.secret}"), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n面板已停止（机器人容器不受影响）。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
