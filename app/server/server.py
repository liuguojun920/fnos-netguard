#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络守卫 (app.netguard) — 后端服务

职责：
  1. 提供 JSON API 给前端面板（状态、配置、动作、日志）
  2. 内置定时调度器：按配置的时间段自动封锁/恢复（不依赖 systemd timer）
  3. 隧道管控：封锁窗口内自动停止 frp 等穿透进程，窗口结束后按记录恢复
  4. 调用 net-guard.sh 执行真正的 iptables 操作

仅使用 Python 标准库，兼容 Python 3.8+。
"""

import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.22"
AUTHOR = "带刀的文人"

ETC = os.environ.get("NETGUARD_ETC") or "/var/apps/app.netguard/etc"
VAR = os.environ.get("NETGUARD_VAR") or "/var/apps/app.netguard/var"
_here = os.path.dirname(os.path.abspath(__file__))          # .../server
DEST = os.environ.get("NETGUARD_DEST") or os.path.dirname(_here)   # .../target
PORT = int(os.environ.get("NG_PORT") or 53210)

SCRIPT = os.path.join(DEST, "server", "net-guard.sh")
WWW = os.path.join(_here, "www")
STATE_DIR = os.environ.get("NETGUARD_STATE") or "/var/lib/net-guard"
# 日志按天分片存放：net-guard-YYYY-MM-DD.log
LOG_DIR = os.environ.get("NETGUARD_LOGDIR") or os.path.join(VAR, "logs")
LEGACY_LOG = "/var/log/net-guard.log"   # 旧版单文件日志，启动时迁移进按日目录
LOG_PREFIX = "net-guard-"
LOG_SUFFIX = ".log"
CONF_JSON = os.path.join(ETC, "config.json")
CONF_SH = os.path.join(ETC, "net-guard.conf")
TUNNEL_STATE = os.path.join(VAR, "tunnels.json")
FN_STATE = os.path.join(VAR, "fnconnect.json")
MANUAL_FILE = os.path.join(VAR, "manual.json")
# 解除封锁时，脚本在拆规则之前把 NET_GUARD_IN 的计数器落盘到这里：
# 规则一拆，链和计数器就一起消失了，之后谁也读不到"这次到底拦了多少"。
LAST_COUNTS = os.path.join(STATE_DIR, "last-counts")
# 上一次封锁的最终统计（给面板在已放行状态下展示"上次拦了多少"）
LAST_SESSION_FILE = os.path.join(VAR, "last-session.json")
# 用户对手动「停止/恢复隧道、FN Connect」的意图记录：保持到下一个切换点，
# 期间调度器不得反向纠偏（修复手动恢复被 10 秒兜底撤销的问题）
TUNNEL_INTENT = os.path.join(VAR, "tunnel-intent.json")
FN_INTENT = os.path.join(VAR, "fn-intent.json")
LOG_KEEP_DAYS_DEFAULT = 15

# 面板密码：首次打开面板时创建，之后所有 /api/* 都要带 token
AUTH_FILE = os.path.join(ETC, "auth.json")
TOKEN_TTL = 12 * 3600
PW_MIN, PW_MAX = 8, 64
PBKDF2_ROUNDS = 120000

# 公网暴露检测用的外部 IP 查询源（取不到就跳过，不影响任何功能）
PUBLIC_IP_SERVICES = ("http://api.ipify.org", "http://ifconfig.me/ip",
                      "http://myip.ipip.net")
# 手动封锁的最长保持时间：即使没有任何定时切换点，也会在这个时限后自动解除，
# 避免用户在 strict（断网口）模式下误操作后彻底失联且无人兜底。
MANUAL_MAX_HOLD = 6 * 3600

DEFAULT_CONFIG = {
    "mode": "guard",              # guard=封入站保出站  soft=断外网  strict=断网口
    "schedule_enabled": True,
    "off_time": "00:05",
    "on_time": "06:00",
    "lan_v4": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
               "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"],
    "lan_v6": ["fe80::/10", "fd00::/8", "ff00::/8"],
    "guard_docker": True,
    "guard_forward": False,
    "drop_log": False,
    "protect_apt": True,
    "ping_targets": ["223.5.5.5", "119.29.29.29"],
    "tunnel_guard": False,
    "tunnel_services": ["frpc", "frps", "natapp", "cpolar", "nps", "phddns"],
    # 飞牛官方远程访问服务（FN Connect）：不同版本的服务/进程名不一致，全部探测
    "fnconnect_guard": False,
    "fnconnect_services": ["fn-connect", "trim_connect", "trim-connect", "fnconnect"],
    "log_keep_days": LOG_KEEP_DAYS_DEFAULT,
    # 企业微信机器人 Webhook（非必填）。填了才会推送封锁开始 / 结束 / 失败通知；
    # 面板只回显掩码，key 不落地到前端。
    "notify_webhook": "",
    # 来源校验白名单：用自家反向代理 / 自定义域名访问面板时，把该域名填进来。
    # 支持精确域名（my.example.com）和通配后缀（.example.com）。
    "csrf_allow_origins": [],
}

_cfg_lock = threading.RLock()
_action_lock = threading.Lock()
_auth_lock = threading.RLock()
_last_action = {"ts": 0, "msg": ""}


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def now_ts():
    return int(time.time())


# --------------------------------------------------------------------------
# 日志：按天分片存储 + 保留天数清理
# --------------------------------------------------------------------------
LOG_MAX_BYTES = 4 * 1024 * 1024      # 单日日志超过 4MB 才裁剪，避免撑满磁盘
LOG_KEEP_LINES = 600


def _ensure_log_dir():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass


def log_path(day=None):
    """返回指定日期（默认今天）的日志文件路径。"""
    day = day or datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, LOG_PREFIX + day + LOG_SUFFIX)


def _rotate_log(path):
    """裁剪单日日志：只保留最后若干行（本日志仅用于排障，不做审计）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.readlines()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("%s [app] 本日日志过长已裁剪，仅保留最近 %d 行\n"
                     % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), LOG_KEEP_LINES))
            fh.writelines(data[-LOG_KEEP_LINES:])
    except Exception:
        pass


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "%s [app] %s" % (ts, msg)
    print(line, flush=True)
    try:
        _ensure_log_dir()
        path = log_path()
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            _rotate_log(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def list_log_dates():
    """返回可用的日志日期（新→旧）与文件大小。"""
    out = []
    try:
        names = os.listdir(LOG_DIR)
    except Exception:
        return out
    for n in names:
        if not (n.startswith(LOG_PREFIX) and n.endswith(LOG_SUFFIX)):
            continue
        day = n[len(LOG_PREFIX):-len(LOG_SUFFIX)]
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", day):
            continue
        try:
            size = os.path.getsize(os.path.join(LOG_DIR, n))
        except Exception:
            size = 0
        out.append({"date": day, "size": size})
    out.sort(key=lambda x: x["date"], reverse=True)
    return out


def purge_logs(before_date):
    """清理 before_date（含该日）之前的日志。"""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(before_date or "")):
        return {"ok": False, "error": "日期格式应为 YYYY-MM-DD"}
    removed, freed = [], 0
    for item in list_log_dates():
        if item["date"] > before_date:
            continue
        path = log_path(item["date"])
        try:
            os.remove(path)
            removed.append(item["date"])
            freed += item["size"]
        except Exception:
            try:                       # 受限环境下删除失败时退化为清空
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("")
                removed.append(item["date"])
                freed += item["size"]
            except Exception:
                pass
    if removed:
        log("手动清理日志：%s 共 %d 个文件，释放 %.1f KB"
            % ("、".join(removed), len(removed), freed / 1024.0))
    return {"ok": True, "removed": removed, "freed": freed}


def auto_purge_logs(keep_days):
    """按保留天数清理过期日志，返回被删除的日期列表。"""
    try:
        keep = int(keep_days)
    except Exception:
        keep = LOG_KEEP_DAYS_DEFAULT
    keep = max(1, min(keep, 365))
    limit = (datetime.now() - timedelta(days=keep - 1)).strftime("%Y-%m-%d")
    return purge_logs(limit).get("removed") or []


def migrate_legacy_log():
    """把旧版本的单文件日志迁移进按日目录（只做一次）。"""
    try:
        if not os.path.exists(LEGACY_LOG) or os.path.getsize(LEGACY_LOG) == 0:
            return
        _ensure_log_dir()
        mtime = datetime.fromtimestamp(os.path.getmtime(LEGACY_LOG))
        target = log_path(mtime.strftime("%Y-%m-%d"))
        with open(LEGACY_LOG, "r", encoding="utf-8", errors="replace") as src:
            data = src.read()
        with open(target, "a", encoding="utf-8") as dst:
            dst.write(data)
        os.remove(LEGACY_LOG)
        log("已迁移旧版日志文件到 %s" % target)
    except Exception:
        pass


def run(cmd, timeout=30, env_extra=None):
    """执行命令，返回 (rc, stdout, stderr)。异常一律转成 rc=-1。"""
    env = os.environ.copy()
    env["NET_GUARD_CONF"] = CONF_SH
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace").strip(),
                p.stderr.decode("utf-8", "replace").strip())
    except FileNotFoundError:
        return (-1, "", "命令不存在: %s" % cmd[0])
    except subprocess.TimeoutExpired:
        return (-1, "", "命令超时(%ss): %s" % (timeout, " ".join(cmd)))
    except Exception as exc:                                   # noqa: BLE001
        return (-1, "", "执行失败: %s" % exc)


def _write_private(path, text):
    """写入仅属主可读的文件（0600）。

    配置文件里有企业微信机器人的 key，密码文件里有哈希与盐：两者都等同凭证，
    默认的 0644 会让本机任何账号都能读到。先写临时文件再原子替换，并在替换前
    收紧权限，避免出现“内容已就位但权限还是旧的”这一瞬间。
    """
    tmp = path + ".tmp"
    try:
        with io.open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except Exception:
        pass
    try:                       # 少数文件系统不支持原子替换，退化为直接写入
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, 0o600)
        return True
    except Exception:
        return False
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _write_json_atomic(path, data):
    """原子写 JSON 状态文件（tmp 写完再 os.replace 替换）。

    为什么必须原子写：直接 open(path,"w") 会先把文件清空再逐段写入，
    此刻进程若被 kill / 掉电，磁盘上就留下一份**截断的 JSON**。
    下次读它时 json.load 抛异常 → 读侧按「读不到」处理 → 记录直接丢失：
      - 手动封锁的覆盖记录丢了 → 调度器提前把网封回去；
      - 隧道 / FN Connect 的停止记录丢了 → 解除封锁时拉不回那些服务。

    os.replace 在同一文件系统内是原子的，读者要么看到旧内容、要么看到新内容，
    不会看到中间态。
    """
    tmp = path + ".tmp"
    try:
        ensure_dirs()
        with io.open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return False


def tighten_perms():
    """把已存在的凭证文件权限收紧到 0600（升级上来的旧文件也要覆盖）。"""
    for p in (CONF_JSON, AUTH_FILE):
        try:
            if os.path.exists(p):
                os.chmod(p, 0o600)
        except Exception:
            pass


def ensure_dirs():
    for d in (ETC, VAR, STATE_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass


# --------------------------------------------------------------------------
# 短缓存：状态接口每 5 秒被轮询一次，全部实时执行命令会白白派生几十个进程
# --------------------------------------------------------------------------
_cache = {}
_cache_ts = {}
_cache_lock = threading.Lock()


def cached(key, ttl, fn):
    now = time.time()
    with _cache_lock:
        if key in _cache and (now - _cache_ts.get(key, 0)) < ttl:
            return _cache[key]
    try:
        val = fn()
    except Exception:
        with _cache_lock:
            return _cache.get(key)
    with _cache_lock:
        _cache[key] = val
        _cache_ts[key] = now
    return val


# --------------------------------------------------------------------------
# 配置读写
# --------------------------------------------------------------------------
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONF_JSON, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if isinstance(saved, dict):
            for k, v in saved.items():
                if k in cfg:
                    cfg[k] = v
    except Exception:
        pass
    return cfg


def save_config(cfg):
    ensure_dirs()
    _write_private(CONF_JSON, json.dumps(cfg, ensure_ascii=False, indent=2))
    write_conf_sh(cfg)


def _sh_quote(value):
    """把任意字符串安全地嵌进 shell 的双引号里。

    这个文件会被 net-guard.sh 用 `.`（source）加载，而应用以 root 运行 ——
    所以这里一旦漏掉转义，用户可控的字符串就能变成 root 级命令执行。
    双引号内仍有特殊含义的字符：$ ` \\ " ！

    反斜杠放在最后转义（先处理反斜杠本身，否则会把后写的转义符再转义一遍）。
    """
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("$", "\\$")
    s = s.replace("`", "\\`")
    # 换行会截断单行赋值，直接剔除
    s = s.replace("\r", " ").replace("\n", " ")
    return s


def write_conf_sh(cfg):
    """把 JSON 配置翻译成 net-guard.sh 能 source 的 shell 配置。

    所有取值都经 _sh_quote 转义：这是 root 权限下防命令注入的最后一道关口，
    不能只依赖上层的 validate_config —— config.json 落在 NAS 本机，
    任何能改到该文件的人都能绕过入口校验直接改值。
    """
    def join(v):
        if isinstance(v, list):
            return " ".join(_sh_quote(x) for x in v)
        return _sh_quote(v)

    lines = [
        "# 由“网络守卫”应用自动生成，请勿手工编辑（会在下次保存时被覆盖）",
        'MODE="%s"' % _sh_quote(cfg["mode"]),
        'OFF_TIME="%s"' % _sh_quote(cfg["off_time"]),
        'ON_TIME="%s"' % _sh_quote(cfg["on_time"]),
        'LAN_V4="%s"' % join(cfg["lan_v4"]),
        'LAN_V6="%s"' % join(cfg["lan_v6"]),
        'PING_TARGETS="%s"' % join(cfg["ping_targets"]),
        'GUARD_DOCKER="%s"' % ("yes" if cfg["guard_docker"] else "no"),
        'GUARD_FORWARD="%s"' % ("yes" if cfg["guard_forward"] else "no"),
        'DROP_LOG="%s"' % ("yes" if cfg["drop_log"] else "no"),
        'PROTECT_APT="%s"' % ("yes" if cfg["protect_apt"] else "no"),
        # 网络恢复后由脚本侧拉回的服务：只要用户在管控 FN Connect，
        # 即便面板自身没来得及处理（重启、调度器未跑），脚本也会把它起回来。
        'RESTORE_SERVICES="%s"' % (join(cfg["fnconnect_services"])
                                   if cfg.get("fnconnect_guard") else ""),
        'STATE_DIR="%s"' % _sh_quote(STATE_DIR),
        'LOG_DIR="%s"' % _sh_quote(LOG_DIR),
        'LOG_FILE="%s"' % _sh_quote(log_path()),   # 脚本侧日志按天分片，与后端同一目录
        "",
    ]
    ensure_dirs()
    tmp = CONF_SH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    os.replace(tmp, CONF_SH)


def validate_config(raw, base):
    """把前端提交的数据校验并合并进现有配置；非法项直接忽略（保留旧值）。"""
    cfg = dict(base)
    if not isinstance(raw, dict):
        return cfg, []

    errs = []

    if "mode" in raw:
        if raw["mode"] in ("guard", "soft", "strict"):
            cfg["mode"] = raw["mode"]
        else:
            errs.append("mode 取值非法")

    for key in ("off_time", "on_time"):
        if key in raw:
            val = str(raw[key]).strip()
            if re.match(r"^([01]\d|2[0-3]):[0-5]\d$", val):
                cfg[key] = val
            else:
                errs.append("%s 必须是 HH:MM 格式" % key)

    for key in ("schedule_enabled", "guard_docker", "guard_forward",
                "drop_log", "protect_apt", "tunnel_guard", "fnconnect_guard"):
        if key in raw:
            cfg[key] = bool(raw[key])

    for key in ("lan_v4", "lan_v6"):
        if key in raw:
            val = raw[key]
            if isinstance(val, str):
                val = [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
            if not isinstance(val, list):
                errs.append("%s 格式非法" % key)
                continue
            good = []
            for item in val:
                try:
                    ipaddress.ip_network(str(item).strip(), strict=False)
                    good.append(str(item).strip())
                except Exception:
                    errs.append("网段无效：%s" % item)
            cfg[key] = good

    if "ping_targets" in raw:
        val = raw["ping_targets"]
        if isinstance(val, str):
            val = [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
        if isinstance(val, list):
            # 这些值会被写进 shell 配置并交给 ping 执行，必须限制成纯 IP/域名字符，
            # 否则可能构造出带分号、反引号的字符串形成命令注入。
            good = []
            for item in val:
                s = str(item).strip()
                if re.match(r"^[A-Za-z0-9._:-]{1,63}$", s) and ".." not in s:
                    good.append(s)
                else:
                    errs.append("探测目标无效（只允许 IP 或域名）：%s" % s)
            if good:
                cfg["ping_targets"] = good[:5]

    if "tunnel_services" in raw:
        val = raw["tunnel_services"]
        if isinstance(val, str):
            val = [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
        if isinstance(val, list):
            cfg["tunnel_services"] = [x for x in (str(s).strip() for s in val)
                                      if re.match(r"^[A-Za-z0-9_.-]{2,32}$", x)][:12]

    if "fnconnect_services" in raw:
        val = raw["fnconnect_services"]
        if isinstance(val, str):
            val = [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
        if isinstance(val, list):
            good = [x for x in (str(s).strip() for s in val)
                    if re.match(r"^[A-Za-z0-9_.-]{2,32}$", x)][:12]
            if good:
                cfg["fnconnect_services"] = good

    if "log_keep_days" in raw:
        try:
            days = int(raw["log_keep_days"])
        except Exception:
            days = 0
        if 1 <= days <= 365:
            cfg["log_keep_days"] = days
        else:
            errs.append("日志保留天数需在 1 - 365 天之间")

    if "notify_webhook" in raw:
        val = re.sub(r"[\s]+", "", str(raw.get("notify_webhook") or ""))
        cur = str(base.get("notify_webhook") or "").strip()
        if val and val == mask_webhook(cur):
            pass                    # 前端回传的就是掩码，说明没改：保留原值
        elif not val:
            cfg["notify_webhook"] = ""
        else:
            ok, err, info = parse_webhook(val)
            if ok:
                cfg["notify_webhook"] = info["url"]
            else:
                errs.append("企业微信机器人地址无效：%s" % err)

    if "csrf_allow_origins" in raw:
        val = raw["csrf_allow_origins"]
        if isinstance(val, str):
            val = [x.strip() for x in re.split(r"[\s,]+", val) if x.strip()]
        if isinstance(val, list):
            # 只收纯域名：带 scheme / 路径 / 空格的值不收，避免把来源校验放宽成任意值
            good = []
            for item in val:
                # 保留可选的前缀写法：".example.com"/"*.example.com" 表示整段后缀，
                # 只去掉尾部多余的点，不能把开头的点也吃掉（否则后缀匹配失效）。
                s = str(item).strip().lower().rstrip(".")
                if not s:
                    continue
                if (re.match(r"^(\*\.|\.)?[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$", s)
                        and ".." not in s):
                    good.append(s)
                else:
                    errs.append("来源域名无效（只填域名，如 nas.example.com）：%s" % s)
            cfg["csrf_allow_origins"] = good[:10]

    return cfg, errs


def local_subnets():
    """返回本机主网卡上的真实网段（如 192.168.1.0/24），用于放行规则的安全校验。"""
    nets = []
    rc, stdout, _ = run(["ip", "-o", "-f", "inet", "addr", "show"], timeout=8)
    if rc == 0:
        for line in stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    try:
                        nets.append(str(ipaddress.ip_network(parts[i + 1], strict=False)))
                    except Exception:
                        pass
    return nets


def covered_by(net_list, target):
    """target（IP 或网段）是否被 net_list 中某条放行规则覆盖。"""
    try:
        tgt = ipaddress.ip_network(str(target).strip(), strict=False)
    except Exception:
        return False
    for item in net_list or []:
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except Exception:
            continue
        if net.version != tgt.version:
            continue
        if net.supernet_of(tgt) or net == tgt:
            return True
    return False


def lan_warnings(cfg, client_ip=None):
    """检查放行网段是否仍然覆盖本机网段与当前访问者，避免把自己锁在门外。"""
    warns = []
    subnets = local_subnets()

    if cfg["mode"] == "guard":
        missed = [s for s in subnets if not covered_by(cfg["lan_v4"], s)]
        if missed:
            warns.append(
                "警告：放行规则已不覆盖本机网段 %s，局域网设备（含你现在的操作）"
                "可能无法连接 NAS。如已失联，请在 NAS 本地终端执行 "
                "net-guard on force 恢复。" % "、".join(missed[:3]))

        if client_ip and not covered_by(cfg["lan_v4"] + cfg["lan_v6"], client_ip):
            try:
                ipaddress.ip_address(client_ip)
                is_loop = ipaddress.ip_address(client_ip).is_loopback
            except Exception:
                is_loop = False
            if not is_loop:
                warns.append("警告：你当前的访问来源 %s 不在放行网段内，"
                             "保存后这个页面可能立刻无法访问。" % client_ip)
    return warns


# --------------------------------------------------------------------------
# 时间窗判定
# --------------------------------------------------------------------------
def hhmm_to_minutes(text):
    try:
        hh, mm = text.split(":")
        return int(hh) * 60 + int(mm)
    except Exception:
        return 0


def in_window(cfg, ts=None):
    """判断 ts 是否落在封锁窗口 [off_time, on_time) 内，支持跨零点。"""
    ts = ts or now_ts()
    dt = datetime.fromtimestamp(ts)
    cur = dt.hour * 60 + dt.minute
    off = hhmm_to_minutes(cfg["off_time"])
    on = hhmm_to_minutes(cfg["on_time"])
    if off == on:
        return False
    if off < on:
        return off <= cur < on
    return cur >= off or cur < on


def next_transition(cfg, ts=None):
    """返回下一次状态切换的时间戳与目标状态。"""
    ts = ts or now_ts()
    now = datetime.fromtimestamp(ts)
    off = hhmm_to_minutes(cfg["off_time"])
    on = hhmm_to_minutes(cfg["on_time"])

    candidates = []
    for day_offset in (0, 1):
        day = (now + timedelta(days=day_offset)).replace(second=0, microsecond=0)
        for minutes, label in ((off, "off"), (on, "on")):
            target = day.replace(hour=minutes // 60, minute=minutes % 60)
            if target.timestamp() > ts + 5:
                candidates.append((int(target.timestamp()), label))
    candidates.sort()
    if not candidates:
        return {"ts": None, "state": None, "in": None}
    nxt = candidates[0]
    return {"ts": nxt[0], "state": nxt[1], "in": nxt[0] - ts}


# --------------------------------------------------------------------------
# 状态采集
# --------------------------------------------------------------------------
def read_state():
    try:
        with open(os.path.join(STATE_DIR, "current"), "r", encoding="utf-8") as fh:
            val = fh.read().strip()
        return val if val in ("on", "off") else "unknown"
    except Exception:
        return "unknown"


def chain_active(chain, parent):
    rc, _, _ = run(["iptables", "-w", "-C", parent, "-j", chain], timeout=8)
    return rc == 0


def blocked_counts():
    """统计真正被丢弃的入站包数（NET_GUARD_IN 链上所有 DROP 行计数器之和）。

    注意：只有动作是 DROP 的规则才计入，LOG / RETURN / REJECT 不算——它们不是“被拦下”。
    ok=False 表示压根读不到计数（iptables 不可用 / 尚未封锁 / 链不存在），
    界面据此给出解释，而不是显示一个会误导人的 0。
    """
    out = {"v4": 0, "v6": 0, "ok": False, "src": "live"}
    for key, tool in (("v4", "iptables"), ("v6", "ip6tables")):
        rc, stdout, _ = run([tool, "-w", "-L", "NET_GUARD_IN", "-n", "-v"], timeout=8)
        if rc != 0:
            continue
        total = 0
        found = False
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            if "DROP" in line:
                found = True
                total += int(parts[0])
        if found:
            out[key] = total
            out["ok"] = True
    return out


def read_last_counts(max_age=7 * 86400):
    """读脚本在拆规则前落盘的计数（`v4 v6 时间戳`）。

    这条兜底专门给"链已经没了"的场景：解除封锁走的是脚本，脚本在 fw_purge 之前
    先把计数器写进 STATE_DIR/last-counts，所以即使 server 侧错过了实时采样
    （比如 cron / 命令行直接跑脚本、或进程重启过），也还能拿回准确数字。
    超过 max_age 的记录视为陈旧，宁可不说也不给旧数据。
    """
    try:
        with open(LAST_COUNTS, "r", encoding="utf-8") as fh:
            parts = fh.read().split()
        v4, v6, ts = int(parts[0]), int(parts[1]), int(parts[2])
    except Exception:
        return None
    if ts > now_ts() + 300 or now_ts() - ts > max_age:
        return None
    return {"v4": max(0, v4), "v6": max(0, v6), "ts": ts}


def counts_before_unblock():
    """解除封锁那一刻的计数：实时优先，脚本落盘兜底，都没有才算拿不到。

    调用时机很关键——必须在 net-guard.sh on 之前，那时链还在。
    """
    counts = blocked_counts()
    if counts.get("ok"):
        return counts
    last = read_last_counts()
    if last:
        return {"v4": last["v4"], "v6": last["v6"], "ok": True, "src": "last-counts"}
    return counts


# --------------------------------------------------------------------------
# 网卡实时流量（每 2 秒采样一次，给面板画出站 / 入站速率曲线）
# --------------------------------------------------------------------------
IO_INTERVAL = 2
IO_POINTS = 60
_io_lock = threading.Lock()
_io = {"iface": "", "last": None, "series": {"tx": [], "rx": []},
       "rate": {"tx": 0.0, "rx": 0.0}, "peak": {"tx": 0.0, "rx": 0.0},
       "readable": True,
       # 当日累计：/proc/net/dev 是开机以来的累计数，需要按天重新累计
       "day_date": "", "day_rx": 0, "day_tx": 0, "day_since": 0,
       "day_exact": False, "day_last": None}


def read_iface_bytes(iface=None):
    """从 /proc/net/dev 读累计收发字节数：(rx, tx)。iface 为空则取所有非 lo 网卡之和。"""
    path = os.environ.get("NETGUARD_NETDEV") or "/proc/net/dev"
    try:
        with open(path, "r") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return None
    rx = tx = 0
    hit = False
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        vals = rest.split()
        if len(vals) < 16:
            continue
        try:
            r, t = int(vals[0]), int(vals[8])
        except ValueError:
            continue
        if iface:
            if name == iface:
                return (r, t)
            continue
        if name == "lo":
            continue
        rx += r
        tx += t
        hit = True
    return (rx, tx) if hit else None


def io_sample(iface=None):
    """采一次样，把速率追加进环形缓冲。返回 True 表示这次采样有效。"""
    data = read_iface_bytes(iface)
    if data is None:
        with _io_lock:
            _io["readable"] = False
        return False
    rx_now, tx_now = data
    ts = time.time()
    _day_account(rx_now, tx_now, ts)
    with _io_lock:
        _io["readable"] = True
        last = _io["last"]
        _io["last"] = (ts, rx_now, tx_now)
        if not last:
            return False
        dt = ts - last[0]
        if dt <= 0:
            return False
        d_rx = rx_now - last[1]
        d_tx = tx_now - last[2]
        if d_rx < 0 or d_tx < 0:      # 计数器回环 / 网卡变了，丢掉这一拍
            return False
        rx_rate, tx_rate = d_rx / dt, d_tx / dt
        _io["rate"] = {"tx": tx_rate, "rx": rx_rate}
        for key, val in (("tx", tx_rate), ("rx", rx_rate)):
            arr = _io["series"][key]
            arr.append(round(val, 1))
            if len(arr) > IO_POINTS:
                arr.pop(0)
            if val > _io["peak"][key]:
                _io["peak"][key] = val
        return True


def io_snapshot():
    with _io_lock:
        iface = _io["iface"]
        tx = list(_io["series"]["tx"])
        rx = list(_io["series"]["rx"])
        rate = dict(_io["rate"])
        peak = dict(_io["peak"])
        readable = _io["readable"]
        ready = _io["last"] is not None
        day = {"date": _io["day_date"], "rx": int(_io["day_rx"]),
               "tx": int(_io["day_tx"]), "since": int(_io["day_since"]),
               "exact": bool(_io["day_exact"])}
    return {"iface": iface, "interval": IO_INTERVAL, "points": len(tx),
            "tx": tx, "rx": rx, "tx_rate": rate.get("tx", 0.0),
            "rx_rate": rate.get("rx", 0.0), "tx_peak": peak.get("tx", 0.0),
            "rx_peak": peak.get("rx", 0.0), "readable": readable,
            "ready": ready, "day": day}


def _boot_ts():
    """系统开机时刻；取不到返回 0（等于“开机时间未知”）。"""
    try:
        with open("/proc/uptime", "r") as fh:
            up = float(fh.read().split()[0])
        return time.time() - up
    except Exception:
        return 0.0


def _midnight_ts():
    """今天 00:00 的时间戳。"""
    now = datetime.now()
    return int(datetime(now.year, now.month, now.day).timestamp())


def _day_account(rx_now, tx_now, ts):
    """累计当日收发字节数，给面板展示「今日累计」。

    /proc/net/dev 提供的是开机以来的累计数，本身不带「今日」口径：
      - 若系统是今天零点之后才开机的，累计数就等于今日用量，可以直接取精确值；
      - 否则只能从面板开始采样时起累加 —— 这时把起算时间如实告知，
        不假装是全天口径。
    """
    today = datetime.now().strftime("%Y-%m-%d")
    boot = _boot_ts()
    exact = 0 < boot >= _midnight_ts()
    with _io_lock:
        if _io["day_date"] != today:          # 跨天（含首次采样）重置
            _io["day_date"] = today
            _io["day_rx"] = 0
            _io["day_tx"] = 0
            _io["day_since"] = ts
            _io["day_exact"] = bool(exact)
            _io["day_last"] = None
        last = _io["day_last"]
        _io["day_last"] = (rx_now, tx_now)
        if exact:
            _io["day_rx"] = rx_now
            _io["day_tx"] = tx_now
            _io["day_exact"] = True
            _io["day_since"] = _midnight_ts()
        elif last:
            d_rx = rx_now - last[0]
            d_tx = tx_now - last[1]
            if d_rx >= 0 and d_tx >= 0:       # 计数器回环/换网卡时丢掉这一拍
                _io["day_rx"] += d_rx
                _io["day_tx"] += d_tx


def io_loop():
    """后台采样线程：主网卡可能晚一步才知道，取不到就按“所有网卡”累计。"""
    while True:
        try:
            with _io_lock:
                iface = _io["iface"]
            if not iface:
                try:
                    iface = (net_info().get("iface") or "")
                except Exception:
                    iface = ""
                with _io_lock:
                    _io["iface"] = iface
            io_sample(iface or None)
        except Exception:
            pass
        time.sleep(IO_INTERVAL)


def net_info():
    info = {"iface": "", "gateway": "", "ipv4": [], "ipv6": [], "route": ""}
    rc, stdout, _ = run(["ip", "-o", "route", "show", "default"], timeout=8)
    if rc == 0 and stdout:
        info["route"] = stdout.splitlines()[0].strip()
        parts = stdout.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if len(parts) > idx + 1:
                info["iface"] = parts[idx + 1]
        if "via" in parts:
            idx = parts.index("via")
            if len(parts) > idx + 1:
                info["gateway"] = parts[idx + 1]

    rc, stdout, _ = run(["ip", "-o", "addr", "show", "scope", "global"], timeout=8)
    if rc == 0:
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
                addr = parts[3].split("/")[0]
                if parts[2] == "inet":
                    info["ipv4"].append(addr)
                else:
                    info["ipv6"].append(addr)
    return info


# --------------------------------------------------------------------------
# 面板密码（首次打开时创建，之后需登录）
# --------------------------------------------------------------------------
_tokens = {}
_auth_fails = {"n": 0, "until": 0}


def load_auth():
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("salt") and data.get("hash"):
            return data
    except Exception:
        pass
    return None


def auth_enabled():
    """是否已经设置过面板密码。"""
    return load_auth() is not None


def _pw_hash(password, salt, rounds):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), int(rounds))
    return dk.hex()


def set_password(password):
    salt = secrets.token_hex(16)
    rec = {"salt": salt,
           "hash": _pw_hash(password, salt, PBKDF2_ROUNDS),
           "rounds": PBKDF2_ROUNDS,
           "created": now_ts()}
    ensure_dirs()
    _write_private(AUTH_FILE, json.dumps(rec, ensure_ascii=False))
    log("面板密码已设置")
    return True


def check_password(password):
    rec = load_auth()
    if not rec:
        return False
    expect = _pw_hash(password, rec["salt"], rec.get("rounds") or PBKDF2_ROUNDS)
    return hmac.compare_digest(expect, rec["hash"])


def issue_token():
    tok = secrets.token_hex(24)
    now = now_ts()
    with _auth_lock:
        for k in [k for k, v in _tokens.items() if v < now]:
            _tokens.pop(k, None)
        _tokens[tok] = now + TOKEN_TTL
    return tok


def token_valid(tok):
    if not tok:
        return False
    with _auth_lock:
        exp = _tokens.get(tok)
    return bool(exp and exp > now_ts())


def drop_all_tokens():
    with _auth_lock:
        _tokens.clear()


def login_penalty():
    """连续失败 5 次冷却 60 秒，挡住在线爆破。"""
    now = now_ts()
    if now < _auth_fails["until"]:
        return False, "尝试过于频繁，请 %d 秒后再试" % (_auth_fails["until"] - now)
    return True, ""


def note_login_fail():
    _auth_fails["n"] += 1
    if _auth_fails["n"] >= 5:
        _auth_fails["until"] = now_ts() + 60
        _auth_fails["n"] = 0


# --------------------------------------------------------------------------
# 公网暴露检测：这个面板端口绝不能对外
# --------------------------------------------------------------------------
_rejected = {"count": 0, "last_ip": "", "last_ts": 0}


def is_public_addr(text):
    try:
        ip = ipaddress.ip_address(str(text).split("%")[0])
    except Exception:
        return False
    if ip.version == 4:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        if ip in ipaddress.ip_network("100.64.0.0/10"):   # 运营商级 NAT，不算真公网
            return False
        return True
    return bool(ip.is_global)


def detect_public_ip():
    """查询出口公网 IP；全部失败返回空串（不影响其它功能）。"""
    for url in PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netguard"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                body = resp.read(300).decode("utf-8", "replace")
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", body)
            if m:
                return m.group(1)
        except Exception:
            continue
    return ""


def tcp_reachable(host, port, timeout=3):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def exposure_check():
    """判断面板端口有没有可能被公网摸到。"""
    info = net_info()
    v4 = [a for a in info["ipv4"] if is_public_addr(a)]
    v6 = [a for a in info["ipv6"] if is_public_addr(a)]
    pub = cached("pubip", 3600, detect_public_ip) or ""
    reachable = tcp_reachable(pub, PORT) if pub else None

    risk = "none"
    if reachable is True:
        risk = "high"
        advice = ("从公网地址 %s 可以直接连到面板端口 %d —— 路由器上大概率存在端口转发 / "
                  "DMZ / UPnP 映射。请立刻删掉这条映射，面板只能在局域网内访问。" % (pub, PORT))
    elif v4 or v6:
        risk = "medium"
        advice = ("NAS 持有公网地址（%s），面板监听 0.0.0.0:%d。只要路由器上存在端口转发、"
                  "UPnP 或 IPv6 放行规则，面板就会暴露到公网。请不要做任何端口映射，"
                  "需要远程管理就用 VPN。" % ("、".join((v4 + v6)[:2]), PORT))
    else:
        advice = ("未发现直接暴露迹象（出口走 NAT）。仍请不要把 %d 端口做端口转发 / DMZ / "
                  "UPnP / frp 穿透 —— 本面板只允许局域网访问。" % PORT)

    return {"risk": risk, "advice": advice, "public_ip": pub,
            "direct_v4": v4, "direct_v6": v6, "self_reachable": reachable}


def security_snapshot():
    sec = dict(cached("exposure", 600, exposure_check) or {})
    sec["port"] = PORT
    sec["auth_required"] = auth_enabled()
    sec["rejected_public"] = _rejected["count"]
    sec["last_rejected_ip"] = _rejected["last_ip"]
    sec["last_rejected_ts"] = _rejected["last_ts"]
    if _rejected["count"] > 0:
        # 真有公网来源打进来了，比任何探测都更能说明问题
        sec["risk"] = "high"
        sec["advice"] = ("已拦截 %d 次来自公网的访问尝试（最近一次 %s）—— 说明这个端口很可能"
                         "已被端口映射 / DMZ / UPnP / 穿透暴露到公网。请立刻在路由器上删除对应"
                         "规则，并取消 frp 等穿透配置。" %
                         (_rejected["count"], _rejected["last_ip"] or "未知来源"))
    return sec


MODE_TEXT = {"guard": "封入站", "soft": "断外网", "strict": "断网口"}

# --------------------------------------------------------------------------
# 隧道（frp 等）管控
# --------------------------------------------------------------------------
_seen_procs = set()     # 本次运行期间见过的进程名：用于区分“已停止”和“未检测到”


def _proc_detail(name):
    """采集进程的可恢复信息：systemd 单元名、完整命令行、工作目录、运行用户、容器归属。"""
    import shlex
    info = {"unit": "", "cmdline": [], "cwd": "", "user": "", "container": ""}
    rc, out, _ = run(["systemctl", "list-unit-files", "--no-legend", "--no-pager", name],
                     timeout=8)
    if rc == 0 and (out or "").strip():
        unit = (out or "").strip().splitlines()[0].split()[0]
        if unit and "." in unit:
            info["unit"] = unit

    pid = ""
    rc2, out2, _ = run(["pgrep", "-a", "-x", name], timeout=6)
    if rc2 == 0 and (out2 or "").strip():
        first = (out2 or "").strip().splitlines()[0]
        parts = first.split(None, 1)
        if parts and parts[0].isdigit():
            pid = parts[0]
            if len(parts) > 1:
                try:
                    info["cmdline"] = shlex.split(parts[1])
                except Exception:
                    info["cmdline"] = parts[1].split()
    if not pid:
        rc3, out3, _ = run(["pgrep", "-f", "(^|/)%s([[:space:]]|$)" % re.escape(name)],
                           timeout=6)
        if rc3 == 0 and (out3 or "").strip():
            head = (out3 or "").strip().splitlines()[0].split()
            if head and head[0].isdigit():
                pid = head[0]
    if pid and pid.isdigit():
        try:
            with io.open("/proc/%s/cmdline" % pid, "rb") as fh:
                raw = fh.read().replace(b"\0", b" ")
                parts = [x for x in raw.decode("utf-8", "replace").split(" ") if x]
                if parts:
                    info["cmdline"] = parts
        except Exception:
            pass
        try:
            info["cwd"] = os.readlink("/proc/%s/cwd" % pid)
        except Exception:
            pass
        try:
            import pwd
            info["user"] = pwd.getpwuid(os.stat("/proc/%s" % pid).st_uid).pw_name
        except Exception:
            pass
        try:
            cg = io.open("/proc/%s/cgroup" % pid, encoding="utf-8",
                         errors="replace").read()
            if "docker" in cg or "kubepods" in cg or "containerd" in cg:
                info["container"] = "docker"
        except Exception:
            pass
    return info


def _respawn(name, info):
    """按记录下来的命令行尽量把进程重新拉起（用于非 systemd 管理的进程）。"""
    if (info or {}).get("container") == "docker":
        return False, "该进程运行在容器里，请手动重启对应容器"
    cmd = (info or {}).get("cmdline") or []
    if not cmd:
        return False, "没有记录到原始命令行，无法自动拉起"
    try:
        cwd = (info or {}).get("cwd") or "/"
        if not os.path.isdir(cwd):
            cwd = "/"
        devnull = open(os.devnull, "wb")
        kw = {"cwd": cwd, "start_new_session": True,
              "stdout": devnull, "stderr": subprocess.STDOUT}
        user = (info or {}).get("user") or ""
        if user and user != "root" and os.geteuid() == 0:
            try:
                import pwd
                pw = pwd.getpwnam(user)
                kw["user"] = pw.pw_name
                kw["group"] = pw.pw_gid
            except Exception:
                pass
        subprocess.Popen(cmd, **kw)
        time.sleep(1.5)
        if _proc_running(name):
            return True, "已按原始命令行重新拉起"
        return True, "已下发启动命令，请稍后看状态点是否转绿"
    except Exception as exc:
        return False, "启动失败：%s" % exc


def _gather_state_items(names):
    """停止前收集：哪些能靠 systemd 拉回、哪些要靠命令行重建。"""
    running = [i for i in probe_names(names) if i["running"]]
    state = {"services": [], "manual": [], "details": {}, "at": now_ts()}
    for item in running:
        detail = _proc_detail(item["name"])
        if item["type"] == "service" or detail.get("unit"):
            state["services"].append(item["name"])
        else:
            state["manual"].append(item["name"])
        state["details"][item["name"]] = detail
    return running, state


def _restore_items(state, names_for_probe):
    """按停止记录尽力恢复；systemctl 起不来时用记录的命令行重建。"""
    state = state or {}
    details = state.get("details") or {}
    restarted, failed = [], []
    for name in (state.get("services") or []) + (state.get("manual") or []):
        if name in restarted or name in [f["name"] for f in failed]:
            continue
        detail = details.get(name) or {}
        unit = detail.get("unit") or name
        rc, _, _ = run(["systemctl", "start", unit], timeout=30)
        if rc == 0:
            restarted.append(name)
            continue
        ok, why = _respawn(name, detail)
        if ok:
            restarted.append(name)
        else:
            failed.append({"name": name, "reason": why or "systemd 启动失败"})
    try:
        invalidate_probe(names_for_probe)
    except Exception:
        pass
    return {"restarted": restarted, "failed": failed}

def _proc_running(name):
    """按进程名判断是否在跑；先精确匹配，再匹配命令行里的可执行文件。"""
    rc, _, _ = run(["pgrep", "-x", name], timeout=6)
    if rc == 0:
        return True
    pattern = "(^|/)" + re.escape(name) + "([[:space:]]|$)"
    rc2, out2, _ = run(["pgrep", "-f", pattern], timeout=6)
    return rc2 == 0 and bool((out2 or "").strip())


def probe_names(names):
    """探测一组服务/进程名的运行状态。

    type: service=systemd 单元   process=独立进程   absent=系统上没找到
    running=True 显示为绿色，running=False 且确实存在显示为红色（已停止）。
    """
    out = []
    for name in names or []:
        rc, s, _ = run(["systemctl", "is-active", name], timeout=6)
        st = (s or "").strip() if rc == 0 else ""
        if st == "active":
            out.append({"name": name, "type": "service", "running": True,
                        "detail": "active"})
            continue
        if st in ("inactive", "failed", "activating", "deactivating",
                  "reloading", "auto-restart"):
            out.append({"name": name, "type": "service", "running": False,
                        "detail": st})
            continue
        if _proc_running(name):
            _seen_procs.add(name)
            out.append({"name": name, "type": "process", "running": True,
                        "detail": ""})
            continue
        if name in _seen_procs:
            out.append({"name": name, "type": "process", "running": False,
                        "detail": ""})
            continue
        out.append({"name": name, "type": "absent", "running": False,
                     "detail": ""})
    return out


def cached_probe(names):
    """状态每 5 秒被轮询一次，探测结果做短缓存，避免疯狂派生进程。"""
    key = ("probe", tuple(names or ()))
    return cached(key, 5, lambda: probe_names(names)) or []


def invalidate_probe(names):
    """服务被停/拉起后立刻失效缓存，避免界面还显示旧状态。"""
    with _cache_lock:
        _cache.pop(("probe", tuple(names or ())), None)


def tunnel_items(cfg):
    """隧道进程名全量状态（含未运行的）。"""
    return cached_probe(cfg["tunnel_services"])


def fn_items(cfg):
    """FN Connect 服务名全量状态。"""
    return cached_probe(cfg["fnconnect_services"])


def tunnel_probe(cfg):
    """仅返回正在运行的隧道（停止逻辑依赖它）。"""
    return [i for i in tunnel_items(cfg) if i["running"]]


def read_tunnel_state():
    try:
        with open(TUNNEL_STATE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def reset_tunnel_state():
    """清空停止记录。先尝试删除（Linux 正常路径），失败则写空对象。"""
    try:
        os.remove(TUNNEL_STATE)
        if not os.path.exists(TUNNEL_STATE):
            return
    except Exception:
        pass
    _write_json_atomic(TUNNEL_STATE, {})


def read_manual():
    """读取仍然有效的手动覆盖记录；过期或不存在返回 None。"""
    try:
        with open(MANUAL_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("state") in ("on", "off"):
            if int(data.get("until") or 0) > now_ts():
                return data
    except Exception:
        pass
    return None


def set_manual(state, until=None):
    """记录手动状态覆盖。state 为 None（或 until 缺省）表示清除。"""
    ensure_dirs()
    if state is None:
        try:
            os.remove(MANUAL_FILE)
            if not os.path.exists(MANUAL_FILE):
                return
        except Exception:
            pass
        # 原子写：清空也要走 tmp+replace，避免留下半截文件
        _write_json_atomic(MANUAL_FILE, {})
        return
    _write_json_atomic(MANUAL_FILE,
                        {"state": state, "until": int(until), "at": now_ts()})


def read_intent(path):
    """读取仍然有效的用户意图；过期或不存在返回 None。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("mode") in ("stopped", "running") \
                and int(data.get("until") or 0) > now_ts():
            return data
    except Exception:
        pass
    return None


def set_intent(path, mode, cfg):
    """记录用户意图，保持到下一个定时切换点（无定时则 6 小时）。"""
    ensure_dirs()
    _write_json_atomic(path,
                        {"mode": mode, "until": manual_hold_until(cfg), "at": now_ts()})


def clear_intent(path):
    try:
        os.remove(path)
    except Exception:
        pass


def manual_hold_until(cfg):
    """手动封锁保持到：下一次定时切换点；没有定时则 6 小时，且无论如何不超过 6 小时。"""
    limit = now_ts() + MANUAL_MAX_HOLD
    if cfg.get("schedule_enabled"):
        nxt = next_transition(cfg)
        if nxt.get("ts"):
            # 面板上会同时给出「覆盖到期」和「下一次定时动作」两个时间，长的一端
            # 由 6 小时兜底，避免一次手滑把 NAS 锁到第二天早上。
            return min(int(nxt["ts"]), limit)
    return limit


def stop_tunnels(cfg):
    """停止隧道；记录 systemd 服务（可拉回）与其它进程（按命令行重建）。"""
    # 这里必须实时探测：缓存里最多有 5 秒的旧状态，可能让“停止”扑空
    names = cfg["tunnel_services"]
    running, state = _gather_state_items(names)
    invalidate_probe(names)
    if not running:
        return {"stopped": [], "note": "没有检测到运行中的隧道进程"}

    for name in state["services"]:
        run(["systemctl", "stop", name], timeout=25)
    for name in state["manual"]:
        run(["pkill", "-x", name], timeout=10)
        run(["pkill", "-f", "(^|/)%s([[:space:]]|$)" % re.escape(name)], timeout=10)

    ensure_dirs()
    _write_json_atomic(TUNNEL_STATE, state)

    log("已停止隧道：服务=%s 其它进程=%s" % (state["services"], state["manual"]))
    note = ""
    if state["manual"]:
        note = "%s 不是 systemd 服务，恢复时会按停止前的命令行尝试重新拉起" % \
               "、".join(state["manual"])
    return {"stopped": state["services"] + state["manual"], "note": note}


def read_fn_state():
    try:
        with open(FN_STATE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def reset_fn_state():
    try:
        os.remove(FN_STATE)
        if not os.path.exists(FN_STATE):
            return
    except Exception:
        pass
    _write_json_atomic(FN_STATE, {})


def stop_fnconnect(cfg):
    """停止飞牛官方远程访问服务 FN Connect。"""
    # 同样实时探测，避免缓存里的旧状态让停止动作落空
    names = cfg["fnconnect_services"]
    running, state = _gather_state_items(names)
    invalidate_probe(names)
    if not running:
        return {"stopped": [], "note": "未检测到运行中的 FN Connect 服务"}

    for name in state["services"]:
        run(["systemctl", "stop", name], timeout=25)
    for name in state["manual"]:
        run(["pkill", "-x", name], timeout=10)
        run(["pkill", "-f", "(^|/)%s([[:space:]]|$)" % re.escape(name)], timeout=10)

    ensure_dirs()
    _write_json_atomic(FN_STATE, state)

    log("已停止 FN Connect：服务=%s 进程=%s" % (state["services"], state["manual"]))
    note = "FN Connect 已停止：外网（含飞牛 App）无法通过 FN ID 访问 NAS，" \
           "局域网访问不受影响，解除封锁后会自动恢复。"
    return {"stopped": state["services"] + state["manual"], "note": note}


def start_fnconnect():
    """按停止记录恢复 FN Connect。

    注意 FN Connect 这类中继服务必须 restart 而不是 start：
    路由断开期间它不会自己意识到中继会话已经死了，进程还在、会话却失效，
    表现就是「局域网正常、FN ID 远程连不上」。restart 才能重新握手。
    """
    state = read_fn_state()
    cfg = load_config()
    # 先把记录的单元整体重启一次，确保会话重建；随后再走通用恢复逻辑兜底
    for name in (state.get("services") or []):
        rc, _, _ = run(["systemctl", "restart", name], timeout=40)
        log("FN Connect 单元重启：%s rc=%s" % (name, rc))
        time.sleep(1.5)
    res = _restore_items(state, cfg["fnconnect_services"])
    restarted, failed = res["restarted"], res["failed"]
    if state.get("services") or state.get("manual"):
        reset_fn_state()
    notes = []
    if restarted:
        notes.append("FN Connect 已恢复，外网可重新通过 FN ID 访问：%s" % "、".join(restarted))
        log("已恢复 FN Connect：%s" % restarted)
    if failed:
        notes.append("未能自动恢复：%s" % "；".join(
            ["%s（%s）" % (f["name"], f["reason"]) for f in failed]))
    if not state.get("services") and not state.get("manual"):
        notes.append("没有找到停止记录，可能上次不是由本面板停止的")
    return {"restarted": restarted, "failed": failed, "note": "；".join(notes)}


def start_tunnels():
    """按停止记录恢复隧道：systemd 优先，起不来则按记录的命令行重建。"""
    state = read_tunnel_state()
    cfg = load_config()
    res = _restore_items(state, cfg["tunnel_services"])
    restarted, failed = res["restarted"], res["failed"]
    if state.get("services") or state.get("manual"):
        reset_tunnel_state()
    notes = []
    if restarted:
        notes.append("已恢复：%s" % "、".join(restarted))
        log("已恢复隧道：%s" % restarted)
    if failed:
        notes.append("未能自动恢复：%s" % "；".join(
            ["%s（%s）" % (f["name"], f["reason"]) for f in failed]))
        log("隧道恢复失败：%s" % failed)
    if not state.get("services") and not state.get("manual"):
        notes.append("没有找到停止记录：可能上次停止用的是别的方法，或未执行过停止")
    return {"restarted": restarted, "failed": failed, "note": "；".join(notes)}


# --------------------------------------------------------------------------
# 企业微信机器人通知
#
# 只在「高级选项」里填了 Webhook 才推送；发送全部走后台线程，绝不拖慢面板操作。
# 文案是企业微信的 text 消息（纯文本 + \n 换行），单条上限 2048 字节，
# 超了整个请求会被机器人拒绝，所以发出前统一按字节裁剪。
# --------------------------------------------------------------------------
WECOM_HOST = "qyapi.weixin.qq.com"
NOTIFY_MAX_BYTES = 1700          # 留出余量，2048 是接口硬上限
SESSION_FILE = os.path.join(VAR, "notify-session.json")
PENDING_FILE = os.path.join(VAR, "notify-pending.json")
_session_lock = threading.Lock()  # 保护会话快照文件
_notify_lock = threading.Lock()   # 串行化发送，避免并发重复推送同一条
_notify_guard = {"ts": 0}        # 守卫纠正提醒的限流时间戳


# --------------------------------------------------------------------------
# 待发队列（断网时通知发不出去，得等网络恢复后补推）
#
# 背景：soft（断外网）/ strict（断网口）模式会先切断外网，之后再发企业微信
# 通知 —— 此时 DNS 已经不可用，urlopen 必然报 Errno -3，告警直接丢失。
# 解决办法是断网前先发一次（DNS 还活着），仍失败的兜底存进本队列，
# 等下一次动作（通常是解除封锁，网络已恢复）时补推。
# --------------------------------------------------------------------------
def _pending_load():
    """读取待发队列；返回列表，损坏时按空队列处理。"""
    try:
        with open(PENDING_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return [str(x) for x in data if str(x).strip()]
    except Exception:
        pass
    return []


def _pending_save(items):
    """整体覆盖写待发队列。"""
    try:
        ensure_dirs()
        tmp = PENDING_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(list(items)[:20], fh, ensure_ascii=False)
        os.replace(tmp, PENDING_FILE)
    except Exception as exc:                                   # noqa: BLE001
        log("待发队列写入失败：%s" % exc)


def _pending_add(text):
    """把一条没能发出去的通知压入待发队列。"""
    text = str(text or "").strip()
    if not text:
        return
    with _notify_lock:
        items = _pending_load()
        if text not in items:
            items.append(text)
        _pending_save(items)
    log("通知已入待发队列（网络不可用，将在网络恢复后补推）：%s"
        % text.replace("\n", " / ")[:120])


def _pending_flush():
    """网络恢复后重发待发队列里的通知；成功一条移除一条。

    只在网络确实可用时调用。逐条发送：一条失败不影响后面的，
    失败的留在队列里等下次。
    补推时关闭自动入队（queue_on_fail=False）—— 否则失败的消息会被
    重新追加一遍，队列越滚越长。
    """
    with _notify_lock:
        items = _pending_load()
    if not items:
        return
    remain = []
    sent = 0
    for text in items:
        res = notify_push(text, queue_on_fail=False)
        if res.get("ok"):
            sent += 1
        else:
            remain.append(text)
    with _notify_lock:
        current = _pending_load()
        # 保留两类：本轮没发出去的，加上补推期间新压入的（不在本轮 items 里的）。
        # 只按 remain 过滤会把补推过程中刚入队的新消息误删掉。
        keep = [t for t in current if t in remain or t not in items]
        _pending_save(keep)
    if sent:
        log("待发队列补推完成：成功 %d 条，剩余 %d 条" % (sent, len(keep)))


def parse_webhook(url):
    """校验机器人地址；返回 (ok, 错误说明, {url,key})。

    只接受企业微信官方域名：这个地址会被服务端主动 POST，放开任意主机等于给了
    一个内网探测通道（SSRF）。要换其它通知渠道请改代码，不要放宽这里。
    """
    url = str(url or "").strip()
    if not url:
        return False, "地址为空", {}
    if any(c in url for c in "\r\n\t "):
        return False, "地址里不能有空格或换行", {}
    try:
        u = urlparse(url)
    except Exception:
        return False, "地址格式不正确", {}
    if (u.scheme or "").lower() != "https":
        return False, "地址必须以 https:// 开头", {}
    if (u.hostname or "").lower() != WECOM_HOST:
        return False, "只支持企业微信机器人的官方地址（%s）" % WECOM_HOST, {}
    key = ""
    for part in (u.query or "").split("&"):
        if part.startswith("key="):
            key = part[4:]
    if not re.match(r"^[A-Za-z0-9_-]{8,80}$", key):
        return False, "地址里缺少有效的 key 参数", {}
    netloc = (u.netloc or "").lower()
    if not re.match(r"^[a-z0-9.\-]+(:\d{1,5})?$", netloc):
        return False, "地址格式不正确", {}
    # 统一重建成规范形式：只保留官方路径与 key，丢掉多余参数/片段
    return True, "", {"url": "https://%s/cgi-bin/webhook/send?key=%s" % (netloc, key),
                      "key": key}


def mask_webhook(url):
    """面板展示用的掩码：只留 key 的首 4 位与末 4 位。

    key 就是机器人的凭证（拿到就能往群里发消息），所以配置保存后一律不再
    原样回显给前端，也顺手避开截图/日志泄露。
    """
    ok, _err, info = parse_webhook(url)
    if not ok:
        return ""
    key = info["key"]
    if len(key) > 12:
        shown = key[:4] + "****" + key[-4:]
    else:
        shown = "****"
    return info["url"].split("?key=")[0] + "?key=" + shown


def _cfg_public(cfg):
    """给前端的配置副本：机器人地址换成掩码，另给一个“是否已配置”的标志。"""
    out = dict(cfg)
    raw = str(out.get("notify_webhook") or "")
    out["notify_webhook"] = mask_webhook(raw)
    out["notify_webhook_set"] = bool(raw.strip())
    return out


def _ts_txt(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%m-%d %H:%M")
    except Exception:
        return "—"


def _span_txt(sec):
    """时长：8 小时 12 分 / 37 分钟 / 45 秒 —— 只保留两级，读起来不啰嗦。"""
    try:
        sec = max(0, int(sec))
    except Exception:
        return "—"
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    if h:
        return "%d 小时 %d 分" % (h, m)
    if m:
        return "%d 分 %d 秒" % (m, s) if s and m < 10 else "%d 分钟" % m
    return "%d 秒" % s


def _clip(text, limit=NOTIFY_MAX_BYTES):
    """按 UTF-8 字节裁剪，避免企业微信因为超长直接拒收整条消息。"""
    data = (text or "").encode("utf-8")
    if len(data) <= limit:
        return text
    cut = data[:limit].decode("utf-8", "ignore")
    return cut.rsplit("\n", 1)[0] + "\n…（内容过长已截断）"


def _hide_secret(text, secret):
    """日志 / 报错里把机器人 key 换成掩码（key 拿到就能往群里发消息）。"""
    if not text or not secret:
        return text
    return str(text).replace(secret,
                            (secret[:2] + "****") if len(secret) > 4 else "****")


def notify_push(text, queue_on_fail=True):
    """同步发送一条 text 消息；返回 {ok, error, skipped}。

    发送失败时（尤其是断网导致的 DNS 解析失败）自动把消息压入待发队列，
    等网络恢复后由 _pending_flush() 补推 —— 断外网模式下告警不会丢。
    queue_on_fail=False 用于「发测试」这类一次性消息：失败就失败，不入队。
    """
    cfg = load_config()
    raw = str(cfg.get("notify_webhook") or "").strip()
    if not raw:
        return {"ok": False, "skipped": True, "error": "未配置企业微信机器人地址"}
    ok, err, info = parse_webhook(raw)
    if not ok:
        log("企业微信通知未发送：配置的地址无效（%s）" % err)
        return {"ok": False, "error": "配置的机器人地址无效：%s" % err}
    body = json.dumps({"msgtype": "text", "text": {"content": _clip(text)}},
                      ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(info["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw_resp = resp.read().decode("utf-8", "replace")
    except Exception as exc:                                  # noqa: BLE001
        msg = _hide_secret(str(exc), info.get("key"))
        log("企业微信通知发送失败：%s" % msg)
        # 网络不可达（含断网后的 DNS 失败）时入队，网络恢复后补推
        if queue_on_fail:
            _pending_add(text)
        return {"ok": False, "error": "发送失败：%s" % msg}
    try:
        data = json.loads(raw_resp)
    except Exception:
        data = {}
    try:
        code = int(data.get("errcode") or 0)
    except Exception:
        code = -1
    if code != 0:
        msg = str(data.get("errmsg") or raw_resp[:120])
        log("企业微信通知被拒（errcode=%s）：%s" % (code, msg))
        return {"ok": False, "error": "机器人返回错误（%s）：%s" % (code, msg)}
    log("企业微信通知已发送")
    return {"ok": True}


def _notify_with_retry(text, attempts=3, wait=3):
    """发送通知，失败时带退避重试。

    解除封锁后脚本刚恢复默认路由 / 网卡，DNS 未必立刻可用 —— 立刻发一次
    往往还是解析失败。重试几次再放弃，都失败则由 notify_push 入队，
    等下一次动作（通常就是下一次解锁）或后端重启时补推。
    """
    for i in range(attempts):
        res = notify_push(text, queue_on_fail=(i == attempts - 1))
        if res.get("ok"):
            return True
        if i < attempts - 1:
            log("通知发送失败，%d 秒后重试（%d/%d）" % (wait, i + 1, attempts))
            time.sleep(wait)
    return False


def notify_async(text, queue_on_fail=True):
    """后台发送：面板操作不等网络，机器人挂了也不影响封锁/恢复本身。

    queue_on_fail=False 用于「发测试」这类一次性消息：失败不入队。
    """
    if not str(load_config().get("notify_webhook") or "").strip():
        return

    def _run():
        try:
            notify_push(text, queue_on_fail=queue_on_fail)
        except Exception as exc:                              # noqa: BLE001
            log("企业微信通知线程异常：%s" % exc)

    threading.Thread(target=_run, daemon=True).start()


# ---------- 封锁期间的会话快照（用于结束时的概览） ----------
def _read_session():
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json_file(path, data):
    try:
        ensure_dirs()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


def _write_session(data):
    _write_json_file(SESSION_FILE, data)


def session_begin(cfg, trigger):
    """封锁开始时记一笔基线：起始时间、拦截计数、模式。"""
    counts = blocked_counts()
    with _session_lock:
        _write_session({
            "start": now_ts(),
            "mode": cfg.get("mode"),
            "trigger": trigger,
            "v4": int(counts.get("v4") or 0),
            "v6": int(counts.get("v6") or 0),
            "guard": 0,
            "tunnels": [],
            "fn": [],
        })


def session_mark(key, names):
    """把本次停掉/恢复的服务名记进会话（只记名字，去重）。"""
    names = [n for n in (names or []) if n]
    if not names:
        return
    with _session_lock:
        data = _read_session()
        if not data:
            return
        cur = data.get(key)
        if not isinstance(cur, list):
            cur = []
        for n in names:
            if n not in cur:
                cur.append(n)
        data[key] = cur
        _write_session(data)


def session_guard_bump():
    """守卫自纠次数 +1（并发安全，文件不存在时静默跳过）。"""
    with _session_lock:
        data = _read_session()
        if not data:
            return
        data["guard"] = int(data.get("guard") or 0) + 1
        _write_session(data)


def session_take():
    """取走会话（读后即删，避免同一次封锁重复发概览）。"""
    with _session_lock:
        data = _read_session()
        try:
            os.unlink(SESSION_FILE)
        except Exception:
            pass
        return data


def read_last_session():
    """上一次封锁的最终统计（面板在已放行状态下显示“上次拦了多少”）。"""
    try:
        with open(LAST_SESSION_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    try:
        data["v4"] = max(0, int(data.get("v4") or 0))
        data["v6"] = max(0, int(data.get("v6") or 0))
        data["total"] = data["v4"] + data["v6"]
    except Exception:
        return None
    return data


def record_last_session(sess, counts):
    """把本次封锁的最终数字落盘。

    解除之后链和计数器一起消失，面板只有在这里还能知道“上次拦了多少”。
    counts 必须是解除动作开始前采到的（见 counts_before_unblock）。
    """
    if not sess:
        return None
    v4 = max(0, int(counts.get("v4") or 0) - int(sess.get("v4") or 0))
    v6 = max(0, int(counts.get("v6") or 0) - int(sess.get("v6") or 0))
    data = {
        "start": int(sess.get("start") or 0),
        "end": now_ts(),
        "mode": sess.get("mode") or "",
        "v4": v4, "v6": v6, "total": v4 + v6,
        "ok": bool(counts.get("ok")),
        "src": counts.get("src") or "",
        "guard": int(sess.get("guard") or 0),
    }
    _write_json_file(LAST_SESSION_FILE, data)
    return data


# ---------- 文案 ----------
def _text_start(cfg, result, manual):
    mode = cfg.get("mode") or "guard"
    lines = ["【网络守卫】已开始封锁",
             "%s · %s" % (datetime.now().strftime("%m-%d %H:%M"),
                          "手动执行" if manual else "定时任务")]
    lines.append("模式：%s（%s）" % (MODE_TEXT.get(mode, mode), mode))
    if not cfg.get("schedule_enabled"):
        lines.append("计划：手动任务，不会自动解除")
    else:
        nxt = next_transition(cfg)
        if nxt.get("ts") and nxt.get("state") == "on":
            lines.append("计划：%s 自动解除（%s后）" % (
                _ts_txt(nxt["ts"]), _span_txt(nxt["ts"] - now_ts())))
        else:
            # 当前不在定时封锁时段里（比如白天手动封锁）：说清楚什么时候会被自动解除，
            # 免得用户以为“到点自动封锁”等于“整夜都在封锁”。
            hold = manual_hold_until(cfg) if manual else None
            lines.append("计划：当前不在定时封锁时段，%s" % (
                "最多保持到 %s" % _ts_txt(hold) if hold else "由后续定时切换接管"))
    parts = []
    tun = result.get("tunnel") or {}
    fn = result.get("fnconnect") or {}
    if tun.get("stopped"):
        parts.append("隧道 %s" % "、".join(tun["stopped"]))
    if fn.get("stopped"):
        parts.append("FN Connect %s" % "、".join(fn["stopped"]))
    lines.append("已停止：%s" % ("；".join(parts) if parts else "无需停止的服务"))
    lines.append("说明：局域网访问不受影响，面板照常可用")
    return "\n".join(lines)


def _text_start_pending(cfg, manual, will_stop=None):
    """断网前预发的「即将封锁」通知。

    ============================ 为什么必须有这条 ============================
    soft（断外网）/ strict（断网口）模式会在动作执行时切断外网，之后 DNS 就
    不可用了 —— 通知必须赶在断网之前发出去，否则必然报：

        <urlopen error [Errno -3] Temporary failure in name resolution>

    这不是偶发网络抖动，而是 100% 必现的时序缺陷：断网在前、发通知在后。
    所以对断网模式改为「断网前预发」，此时网络还通，告警能真正送达群里。

    配套的兜底是待发队列（_pending_add / _pending_flush）：万一预发也失败，
    消息会存进 var/notify-pending.json，等网络恢复后自动补推，告警不丢。

    注意面板前台不展示这套时序细节（避免用户困惑），只保留简洁的操作指引；
    技术说明留在本注释与 README 里。
    =========================================================================

    will_stop 是断网前预采集到的待停服务名单（断网后就探测不到了）。
    """
    mode = cfg.get("mode") or "guard"
    lines = ["【网络守卫】即将开始封锁",
             "%s · %s" % (datetime.now().strftime("%m-%d %H:%M"),
                          "手动执行" if manual else "定时任务")]
    lines.append("模式：%s（%s）" % (MODE_TEXT.get(mode, mode), mode))
    if not cfg.get("schedule_enabled"):
        lines.append("计划：手动任务，不会自动解除")
    else:
        nxt = next_transition(cfg)
        if nxt.get("ts") and nxt.get("state") == "on":
            lines.append("计划：%s 自动解除（%s后）" % (
                _ts_txt(nxt["ts"]), _span_txt(nxt["ts"] - now_ts())))
        else:
            hold = manual_hold_until(cfg) if manual else None
            lines.append("计划：当前不在定时封锁时段，%s" % (
                "最多保持到 %s" % _ts_txt(hold) if hold else "由后续定时切换接管"))
    if will_stop:
        lines.append("将停止：%s" % "；".join(will_stop))
    lines.append("说明：局域网访问不受影响，面板照常可用")
    return "\n".join(lines)


def _predict_stop(cfg):
    """断网前预采集将被停止的服务名（隧道 + FN Connect）。

    断网之后脚本就探测不到运行中的进程了，所以这份名单必须在断网前拿。
    探测失败不影响封锁本身，返回空列表即可。
    """
    names = []
    try:
        if cfg.get("schedule_enabled"):
            if cfg.get("tunnel_guard"):
                _running, state = _gather_state_items(cfg["tunnel_services"])
                tun = state.get("services", []) + state.get("manual", [])
                if tun:
                    names.append("隧道 %s" % "、".join(tun))
            if cfg.get("fnconnect_guard"):
                _running, fstate = _gather_state_items(cfg["fnconnect_services"])
                fn = fstate.get("services", []) + fstate.get("manual", [])
                if fn:
                    names.append("FN Connect %s" % "、".join(fn))
    except Exception as exc:                                  # noqa: BLE001
        log("预采集待停服务失败：%s" % exc)
    return names


def _text_fail(action_text, result, state):
    reason = (result.get("note") or result.get("stderr") or "").strip()
    reason = re.sub(r"\s+", " ", reason)[:160] or "脚本返回 rc=%s" % result.get("rc")
    cur = "未知"
    if state == "off":
        cur = "仍在封锁中"
    elif state == "on":
        cur = "已放行（未封锁）"
    return "\n".join([
        "【网络守卫】操作失败：%s" % action_text,
        "%s" % datetime.now().strftime("%m-%d %H:%M"),
        "原因：%s" % reason,
        "影响：防火墙规则未被改动，当前状态「%s」" % cur,
    ])


def _text_purge(result):
    ok = bool(result.get("ok"))
    head = "【网络守卫】已完成彻底复原" if ok else "【网络守卫】彻底复原未完成"
    lines = [head, datetime.now().strftime("%m-%d %H:%M"),
             "操作：清空本程序留下的全部防火墙规则，并尝试补回默认路由"]
    if not ok:
        lines.append("异常：%s" % ((result.get("stderr") or result.get("note") or "未知")[:160]))
    lines.append("提示：FN Connect 若仍不通，到「设置 → 远程访问」把开关关掉再打开一次")
    return "\n".join(lines)


def _text_guard():
    return "\n".join([
        "【网络守卫】封锁被外部改动，已自动纠正",
        datetime.now().strftime("%m-%d %H:%M"),
        "检测到路由 / 防火墙规则被改动，已按计划恢复封锁",
        "同类提醒 10 分钟内最多一条",
    ])


def _text_test():
    return "\n".join([
        "【网络守卫】测试消息",
        datetime.now().strftime("%m-%d %H:%M"),
        "机器人配置成功。之后「开始封锁 / 解除封锁 / 操作失败」都会推送到这里，",
        "解除时还会附上这段时间的简要概览。",
    ])


def notify_end_summary(cfg, result, sess, counts=None):
    """封锁结束：发一条带本次概览的通知（时长、拦截增量、服务、自纠次数）。

    counts 必须在解除动作之前采好传进来（counts_before_unblock）——脚本一跑，
    NET_GUARD_IN 连同计数器就被清掉了，这里再读只能拿到“读不到”。
    """
    if counts is None:
        counts = blocked_counts()
    v4 = int(counts.get("v4") or 0)
    v6 = int(counts.get("v6") or 0)
    lines = ["【网络守卫】已解除封锁，网络已恢复"]
    if sess:
        start = int(sess.get("start") or 0)
        lines.append("封锁：%s → %s（%s）" % (_ts_txt(start),
                                           datetime.now().strftime("%m-%d %H:%M"),
                                           _span_txt(now_ts() - start)))
        mode = sess.get("mode") or cfg.get("mode") or "guard"
        lines.append("模式：%s（%s）" % (MODE_TEXT.get(mode, mode), mode))
        d4 = max(0, v4 - int(sess.get("v4") or 0))
        d6 = max(0, v6 - int(sess.get("v6") or 0))
        if counts.get("ok"):
            lines.append("本次拦截：%d 个（IPv4 %d / IPv6 %d）" % (d4 + d6, d4, d6))
        else:
            lines.append("本次拦截：未统计（锁定时未能读到防火墙计数器）")
        if sess.get("tunnels"):
            lines.append("隧道：%s 已停止并已恢复" % "、".join(sess["tunnels"]))
        if sess.get("fn"):
            lines.append("FN Connect：%s 已停止并已恢复" % "、".join(sess["fn"]))
        g = int(sess.get("guard") or 0)
        lines.append("守卫自纠：%s" % ("%d 次（封锁被外部改动后自动补回）" % g
                                    if g else "未触发"))
    else:
        lines.append("本次时长：未知（升级 / 重启前的记录已丢失）")
        lines.append("模式：%s（%s）" % (MODE_TEXT.get(cfg.get("mode"), cfg.get("mode")),
                                     cfg.get("mode")))
    tun = result.get("tunnel") or {}
    fn = result.get("fnconnect") or {}
    for k, label in ((tun, "隧道"), (fn, "FN Connect")):
        if k.get("failed"):
            lines.append("%s恢复失败：%s" % (label, "；".join(
                ["%s（%s）" % (f.get("name"), f.get("reason")) for f in k["failed"]])))
    lines.append("当前：已按计划放行，局域网与外网均可用")
    if cfg.get("fnconnect_guard"):
        lines.append("提示：FN Connect 将在数秒后自动重启以重建中继，"
                     "远程连接会短暂中断一次")
    return "\n".join(lines)


def notify_guard_change():
    """守卫纠错提醒（限流 10 分钟，避免被反复改路由的人刷屏）。"""
    now = now_ts()
    if now - _notify_guard["ts"] < 600:
        return
    _notify_guard["ts"] = now
    notify_async(_text_guard())


# --------------------------------------------------------------------------
# 动作执行
# --------------------------------------------------------------------------
def run_script(action, timeout=120, force=False, quiet=False):
    """执行 net-guard.sh 子命令。quiet=True 用于高频守卫自检，不写动作日志。"""
    if not os.path.exists(SCRIPT):
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "脚本不存在: %s" % SCRIPT}
    bash = os.environ.get("NETGUARD_BASH") or "bash"
    cmd = [bash, SCRIPT, action]
    if force:
        cmd.append("force")
    if not quiet:
        log("动作 %s 开始执行: %s" % (action, " ".join(cmd)))
    rc, stdout, stderr = run(cmd, timeout=timeout)
    ok = (rc == 0)
    note = ""
    if rc == 2 or "SKIPPED_BUSY" in (stdout or ""):
        # 脚本发现自己会打断 apt/dpkg，主动放弃本次操作：这不是成功
        ok = False
        note = ("检测到系统正在执行 apt/dpkg 更新，脚本为避免把更新打断而跳过了本次操作，"
                "网络规则没有被改动。请等更新结束后重试；若确认没有更新在跑，"
                "可在高级选项里临时关闭「更新期间跳过」。")
    elif rc == 3:
        # 守卫自检做过纠正（rc 约定见 do_verify）：算成功，由调用方决定如何呈现
        ok = True
    if not quiet:
        log("动作 %s 完成 rc=%s%s" % (action, rc, "" if ok else " err=" + stderr[:200]))
    return {"ok": ok, "rc": rc, "stdout": stdout[-4000:],
            "stderr": stderr[-2000:], "note": note}


def do_action(action, force=False, manual=False):
    """执行动作。

    manual=True 表示用户在界面上手动操作：会写入“手动覆盖”标记，
    使调度器在下一个定时切换点之前不再把它纠正回去。
    """
    if not _action_lock.acquire(blocking=False):
        return {"ok": False, "error": "另一个操作正在进行，请稍后重试"}
    try:
        cfg = load_config()
        # 新的封锁/解除阶段开始：清除手动停止/恢复的意图，回到自动对齐
        clear_intent(TUNNEL_INTENT)
        clear_intent(FN_INTENT)
        # 解除封锁必须在脚本动手之前取数：脚本里 fw_purge 一拆链，计数器就跟着消失了，
        # 之前放在通知组装时再读，只能得到“读不到”——这条链就是为此提前到这里的。
        pre_counts = counts_before_unblock() if action == "on" else None

        # ---- 断网前预发通知（仅 soft / strict 断网模式）----
        # 断外网 / 断网口模式会先切断外网，之后 DNS 即不可用，企业微信通知必然
        # 失败（Errno -3）。所以在动手断网之前先把「即将封锁」发出去 ——
        # 此时网络还通，告警能真正送到群里。
        # 详见 _text_start_pending 的注释。
        pre_sent = False
        if action == "off" and cfg.get("mode") in ("soft", "strict"):
            if str(cfg.get("notify_webhook") or "").strip():
                try:
                    will_stop = _predict_stop(cfg)
                    pre_text = _text_start_pending(cfg, manual, will_stop)
                    # 同步发送：必须确认送达与否，才知道后面要不要靠队列补推
                    pre_res = notify_push(pre_text)
                    pre_sent = bool(pre_res.get("ok"))
                    if pre_sent:
                        log("已在断网前发出「即将封锁」通知（网络即将断开）")
                    else:
                        log("断网前预发通知失败，已入待发队列：%s"
                            % (pre_res.get("error") or "未知原因"))
                except Exception as exc:                      # noqa: BLE001
                    log("断网前预发通知异常：%s" % exc)

        result = run_script(action, force=force)

        if manual:
            if action == "off":
                # 只有真的封锁成功才写入覆盖；失败时保持原样，让调度器继续自愈
                if result.get("ok"):
                    set_manual("off", manual_hold_until(cfg))
            elif action == "on":
                # 解除成功：写入「已放行」覆盖，让调度器在覆盖期内不要把封锁又装回去。
                #   —— 这里绝不能调 set_manual(None)：那会把覆盖记录整个删掉，
                #      调度器下一次轮询（10 秒）读到 manual=None，就会落回
                #      schedule_enabled 分支，按窗口重新封锁 —— 表现为
                #      「用户刚点完立即解除，10 秒后网络又断了」。
                if result.get("ok"):
                    set_manual("on", manual_hold_until(cfg))
                else:
                    # 解除失败：清除覆盖，让调度器持续重试直到恢复网络
                    set_manual(None)

        # 封锁开始就记基线，后面的停止名单与守卫自纠次数都记进这份快照
        if action == "off" and result.get("ok"):
            session_begin(cfg, "manual" if manual else "schedule")

        # 同步隧道 / FN Connect —— 仅在「定时任务」模式下自动管控
        if cfg.get("schedule_enabled"):
            if action in ("off",) and cfg["tunnel_guard"]:
                result["tunnel"] = stop_tunnels(cfg)
            if action in ("on", "reconcile") and os.path.exists(TUNNEL_STATE):
                result["tunnel"] = start_tunnels()

            if action in ("off",) and cfg.get("fnconnect_guard"):
                result["fnconnect"] = stop_fnconnect(cfg)
            if action in ("on", "reconcile") and os.path.exists(FN_STATE):
                result["fnconnect"] = start_fnconnect()

        # 状态刚变过，立即失效探测缓存，下面的 status() 才拿得到最新结果
        invalidate_probe(cfg.get("tunnel_services"))
        invalidate_probe(cfg.get("fnconnect_services"))

        _last_action["ts"] = now_ts()
        _last_action["msg"] = "%s %s" % (action, "成功" if result.get("ok") else "失败")

        # 企业微信通知：开始 / 结束（附概览）/ 失败
        try:
            if action == "off":
                if result.get("ok"):
                    session_mark("tunnels", (result.get("tunnel") or {}).get("stopped"))
                    session_mark("fn", (result.get("fnconnect") or {}).get("stopped"))
                    if pre_sent:
                        # 断网模式已在断网前发过「即将封锁」，这里不再重复发
                        # 「已开始封锁」—— 断网后发也发不出去，且会造成重复告警。
                        pass
                    else:
                        notify_async(_text_start(cfg, result, manual))
                else:
                    notify_async(_text_fail("立即封锁", result, read_state()))
            elif action == "on":
                if result.get("ok"):
                    sess = session_take()
                    # 顺手留一份“上次封锁拦了多少”，面板解除后还能看到
                    record_last_session(sess, pre_counts or {"ok": False})
                    # 解锁通知同步发送并带重试：脚本恢复默认路由 / 网卡后，
                    # DNS 未必立刻可用，立刻发大概率还是解析失败。
                    # 这里等网络就绪再重试几次，都失败才入队等下次补推。
                    _notify_with_retry(notify_end_summary(cfg, result, sess, pre_counts))
                else:
                    notify_async(_text_fail("解除封锁", result, read_state()))
        except Exception as exc:                              # noqa: BLE001
            log("通知组装失败：%s" % exc)

        # 网络已恢复（解除封锁）时，把之前断网期间没能发出去的告警补推出去。
        # 这是「告警不丢」的最后一环：断网时发的消息会留在待发队列里。
        if action in ("on", "reconcile"):
            try:
                _pending_flush()
            except Exception as exc:                          # noqa: BLE001
                log("待发队列补推异常：%s" % exc)

        result["status"] = status()
        return result
    finally:
        _action_lock.release()


# --------------------------------------------------------------------------
# 状态汇总
# --------------------------------------------------------------------------
APP_START = now_ts()


def status():
    cfg = load_config()
    st = read_state()
    info = cached("net", 3, net_info)
    counts = cached("counts", 3, blocked_counts)
    guard_on = cached("inbound", 3, lambda: chain_active("NET_GUARD_IN", "INPUT"))
    out_on = cached("outbound", 3, lambda: chain_active("NET_GUARD", "OUTPUT"))

    tun_all = tunnel_items(cfg)
    fn_all = fn_items(cfg)
    nxt = next_transition(cfg) if cfg["schedule_enabled"] else {"ts": None, "state": None, "in": None}

    return {
        "version": VERSION,
        "author": AUTHOR,
        "now": now_ts(),
        "uptime": now_ts() - APP_START,
        "state": st,
        "mode": cfg["mode"],
        "schedule": {
            "enabled": cfg["schedule_enabled"],
            "off_time": cfg["off_time"],
            "on_time": cfg["on_time"],
            "in_window": in_window(cfg),
            "next": nxt,
            "guard_applies": bool(cfg["schedule_enabled"]),
        },
        "firewall": {
            "inbound_active": guard_on,
            "outbound_active": out_on,
            "blocked_v4": counts["v4"],
            "blocked_v6": counts["v6"],
            "blocked_total": counts["v4"] + counts["v6"],
            "counters_ok": counts["ok"],
            # 已放行时计数器必然读不到（链已拆），改由这里给出上一次封锁的最终数字
            "last_session": read_last_session(),
        },
        "net": info,
        "io": io_snapshot(),
        "tunnels": {
            "guard_enabled": cfg["tunnel_guard"],
            "all": tun_all,
            "running": [i for i in tun_all if i["running"]],
            "stopped_record": read_tunnel_state(),
        },
        "fnconnect": {
            "guard_enabled": cfg["fnconnect_guard"],
            "items": fn_all,
            "running": [i["name"] for i in fn_all if i["running"]],
            "stopped_record": read_fn_state(),
        },
        "logs": {
            "dir": LOG_DIR,
            "keep_days": cfg["log_keep_days"],
            "dates": cached("logdates", 30, list_log_dates) or [],
        },
        "config": _cfg_public(cfg),
        "manual": read_manual(),
        "last_action": _last_action,
        "security": security_snapshot(),
        "start_ts": APP_START,
    }


def tail_log(lines=80, day=None):
    lines = max(1, min(int(lines), 1000))
    try:
        with open(log_path(day), "r", encoding="utf-8", errors="replace") as fh:
            data = fh.readlines()
        return "".join(data[-lines:])
    except Exception:
        return ""


# --------------------------------------------------------------------------
# 调度线程
# --------------------------------------------------------------------------
def sync_tunnels(cfg):
    """把隧道状态对齐到当前封锁状态。

    定时切换、手工封锁、后端重启后重启等情况统一由这里兜底：
      封锁中 → 隧道必须处于停止；已放行 → 按停止记录拉回。
    """
    if not cfg["tunnel_guard"]:
        return
    # 隧道自动管控只属于「定时任务」模式：手动任务下一切由用户自己决定
    if not cfg.get("schedule_enabled"):
        return
    rec = read_tunnel_state()
    blocked = (read_state() == "off")
    intent = read_intent(TUNNEL_INTENT)
    if intent:
        # 用户刚手动停止/恢复过：在意图期内完全按意图执行，不反向纠偏
        if intent["mode"] == "stopped":
            if tunnel_probe(cfg):
                log("隧道兜底：用户要求保持停止，发现隧道又在运行，执行停止")
                stop_tunnels(cfg)
        elif rec.get("services") and not tunnel_probe(cfg):
            log("隧道兜底：用户要求保持运行，按停止记录恢复")
            start_tunnels()
        return
    if blocked:
        if not rec.get("services") and not rec.get("manual"):
            if tunnel_probe(cfg):
                log("隧道兜底：当前处于封锁状态但隧道仍在运行，执行停止")
                stop_tunnels(cfg)
    else:
        if rec.get("services") or rec.get("manual"):
            log("隧道兜底：已放行但存在停止记录，执行恢复")
            start_tunnels()


def sync_fnconnect(cfg):
    """把 FN Connect 状态对齐到当前封锁状态（与隧道同一套逻辑）。"""
    if not cfg.get("fnconnect_guard"):
        return
    # 同上：手动任务模式下不自动停止 / 拉起 FN Connect
    if not cfg.get("schedule_enabled"):
        return
    rec = read_fn_state()
    blocked = (read_state() == "off")
    have_rec = bool(rec.get("services") or rec.get("manual"))
    intent = read_intent(FN_INTENT)
    if intent:
        if intent["mode"] == "stopped":
            if [i for i in fn_items(cfg) if i["running"]]:
                log("FN 兜底：用户要求保持停止，发现服务又在运行，执行停止")
                stop_fnconnect(cfg)
        elif have_rec and not [i for i in fn_items(cfg) if i["running"]]:
            log("FN 兜底：用户要求保持运行，按停止记录恢复")
            start_fnconnect()
        return
    if blocked:
        if not have_rec and [i for i in fn_items(cfg) if i["running"]]:
            log("FN Connect 兜底：封锁中但服务仍在运行，执行停止")
            stop_fnconnect(cfg)
    else:
        if have_rec:
            log("FN Connect 兜底：已放行且存在停止记录，执行恢复")
            start_fnconnect()


def _ping_ok(target, count=2, wait=3):
    """目标能否 ping 通。"""
    rc, _, _ = run(["ping", "-c", str(count), "-W", str(wait), "-n", target],
                   timeout=count * (wait + 2) + 5)
    return rc == 0


def _rule_exists(tool, args):
    rc, _, _ = run([tool, "-w"] + args, timeout=8)
    return rc == 0


def _chain_line(tool, parent, child):
    """child 链挂在 parent 链的第几条（1 起），不存在返回 0。"""
    rc, out, _ = run([tool, "-w", "-L", parent, "-n", "--line-numbers"], timeout=8)
    if rc != 0:
        return 0
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and child in parts[1]:
            return int(parts[0])
    return 0


def verify_guard():
    """现场体检：用真实的路由 / 防火墙规则 / ping 结果证明当前防护是否真的生效。"""
    cfg = load_config()
    mode = cfg["mode"]
    st = read_state()
    armed = (st == "off")
    checks = []

    def add(name, ok, detail, kind=None):
        checks.append({"name": name, "ok": bool(ok), "detail": detail,
                       "kind": kind or ("pass" if ok else "fail")})

    targets = cfg.get("ping_targets") or ["223.5.5.5"]
    target = targets[0]

    if not armed:
        add("当前处于放行状态", False,
            "关键点：防护模式只决定「封锁时用什么方式封」，切换它不会自动进入封锁。"
            "要点一次「立即封锁」，该模式才会真正落到系统上。", "info")
        up = _ping_ok(target)
        add("本机出网正常", up, "ping %s：%s（放行状态下应当能通）" %
            (target, "通" if up else "不通"))
        return {"armed": False, "mode": mode, "state": st, "checks": checks,
                "passed": False, "target": target,
                "summary": "当前未封锁。「%s」模式已保存，点「立即封锁」后即按该模式生效。"
                           % MODE_TEXT.get(mode, mode)}

    if mode == "guard":
        add("IPv4 入站链已挂载",
            _rule_exists("iptables", ["-C", "INPUT", "-j", "NET_GUARD_IN"]),
            "iptables -C INPUT -j NET_GUARD_IN")
        line = _chain_line("iptables", "INPUT", "NET_GUARD_IN")
        add("挂在 INPUT 链最前面", line == 1,
            "当前是第 %d 条%s" % (line, "" if line == 1 else
                               "——若排在 Docker / fnOS 放行规则之后，那些端口仍会被先放行"))
        v6 = _rule_exists("ip6tables", ["-C", "INPUT", "-j", "NET_GUARD_IN"])
        add("IPv6 入站链已挂载", v6,
            "IPv6 没有 NAT，公网能直达 NAS，这条很重要" if v6 else
            "未检测到 IPv6 入站链（本机可能没有可用的 IPv6 默认路由）", "info")

        counts = blocked_counts()
        total = counts["v4"] + counts["v6"]
        add("防火墙实际在拦包", True,
            "NET_GUARD_IN 累计丢弃 IPv4 %d / IPv6 %d 个包；隔几秒再自检一次，"
            "数字变大就说明规则确实在工作" % (counts["v4"], counts["v6"]), "info")

        dockerhook = _chain_line("iptables", "DOCKER-USER", "NET_GUARD_IN") if \
            _rule_exists("iptables", ["-L", "DOCKER-USER"]) else 0
        if _rule_exists("iptables", ["-L", "DOCKER-USER"]):
            add("Docker 映射端口已一并封锁", dockerhook > 0,
                "DOCKER-USER 链第 %d 条" % dockerhook if dockerhook else
                "系统上有 Docker，但没挂上 DOCKER-USER，容器映射端口可能仍可达")

        up = _ping_ok(target)
        add("本机主动出网保留", up,
            "ping %s：%s（guard 模式设计上就保留本机上网）" % (target, "通" if up else "不通"))

        add("外部验证方法", True,
            "用手机开蜂窝网络（别连家里 Wi-Fi）访问 NAS 的公网 IP / 域名端口，应当连接超时；"
            "frp、FN Connect 这类反向隧道不受 iptables 控制，需要用上面的开关停掉。", "info")

    elif mode == "soft":
        add("出站封锁链已挂载",
            _rule_exists("iptables", ["-C", "OUTPUT", "-j", "NET_GUARD"]),
            "iptables -C OUTPUT -j NET_GUARD")
        rc, out, _ = run(["ip", "-4", "route", "show", "default"], timeout=8)
        gone4 = not (out or "").strip()
        add("IPv4 默认路由已删除", gone4,
            "当前默认路由：%s" % ((out or "").strip() or "无（正确）"))
        rc6, out6, _ = run(["ip", "-6", "route", "show", "default"], timeout=8)
        gone6 = not (out6 or "").strip()
        add("IPv6 默认路由已删除", gone6,
            "当前默认路由：%s" % ((out6 or "").strip() or "无（正确）"))
        up = _ping_ok(target)
        add("本机已无法访问外网", not up,
            "ping %s：%s" % (target, "通说明还没断干净" if up else "不通（正确，已被拦下）"))
        add("局域网验证方法", True,
            "局域网内用电脑 ping NAS 的 IP 应当仍然通；Docker 容器的出网走 FORWARD 链，"
            "soft 模式默认不拦容器流量。", "info")

    else:  # strict
        info = net_info()
        iface = info.get("iface") or ""
        if not iface:
            try:
                with open("/var/lib/net-guard/iface.saved", "r", encoding="utf-8") as fh:
                    iface = fh.read().strip()
            except Exception:
                pass
        down = False
        if iface:
            rc, out, _ = run(["ip", "-o", "link", "show", iface], timeout=8)
            txt = (out or "")
            down = ("state DOWN" in txt) or ("<NO-CARRIER" in txt and "UP" not in txt)
        add("主网卡已关闭", down, "网卡 %s：%s" % (iface or "未知",
                                        "已 DOWN（正确）" if down else "仍处于 UP 状态"))
        up = _ping_ok(target)
        add("本机已无法访问外网", not up,
            "ping %s：%s" % (target, "通说明还没断干净" if up else "不通（正确）"))
        add("注意", True,
            "strict 模式会连局域网一起断掉，NAS 面板也可能打不开，"
            "恢复要靠「立即解除封锁」或主机前的控制台。", "info")

    failed = [c for c in checks if c["kind"] == "fail"]
    passed = not failed
    summary = ("「%s」已生效，%d 项检查全部通过。" % (MODE_TEXT.get(mode, mode), len(checks))
               if passed else
               "「%s」已在运行，但有 %d 项检查未通过：%s。" %
               (MODE_TEXT.get(mode, mode), len(failed),
                "；".join([f["name"] for f in failed])))
    return {"armed": True, "mode": mode, "state": st, "checks": checks,
            "passed": passed, "target": target, "summary": summary}


def guard_verify():
    """封锁态守卫自检（每 10 秒）：若路由/规则/网卡被外部改动绕过封锁，立即纠正。

    脚本侧约定：rc=0 无需纠正；rc=3 做过纠正（详情写进了脚本日志）。
    """
    res = run_script("verify", timeout=30, quiet=True)
    if res.get("rc") == 3:
        log("守卫：检测到封锁被外部改动（路由/规则/网卡），已自动纠正，详情见脚本日志")
        session_guard_bump()
        notify_guard_change()
        return True
    if not res.get("ok"):
        log("守卫自检异常 rc=%s err=%s" % (res.get("rc"), (res.get("stderr") or "")[:160]))
    return False


def scheduler_loop():
    time.sleep(3)
    _last_purge_day = {"day": ""}
    log("调度器已启动（每 10 秒检查一次）")
    while True:
        try:
            cfg = load_config()
            manual = read_manual()

            if manual:
                # 用户手动封锁/恢复过：在覆盖期内不反向纠偏，否则手一点就被撤销。
                if manual["state"] != read_state():
                    log("调度：尊重手动状态 %s（%d 秒后到期）" %
                        (manual["state"], manual["until"] - now_ts()))
                elif manual["state"] == "off":
                    # 手动封锁生效期间同样开守卫：防止路由/规则被外部改动绕过
                    guard_verify()
            elif cfg["schedule_enabled"]:
                win = in_window(cfg)
                desired = "off" if win else "on"
                current = read_state()

                if desired != current:
                    log("调度：当前=%s 期望=%s，执行 %s" % (current, desired, desired))
                    # 走统一动作入口：内部会顺带处理隧道联动与状态汇总
                    do_action(desired)
                    time.sleep(2)
                elif current == "off":
                    # 已在封锁态且符合计划：周期性验证执行效果
                    guard_verify()

            # 隧道兜底对齐（定时开关与手工封锁都覆盖）
            sync_tunnels(cfg)
            sync_fnconnect(cfg)

            # 每天一次：按保留天数清理过期日志
            today = datetime.now().strftime("%Y-%m-%d")
            if _last_purge_day["day"] != today:
                _last_purge_day["day"] = today
                gone = auto_purge_logs(cfg.get("log_keep_days",
                                               LOG_KEEP_DAYS_DEFAULT))
                if gone:
                    log("日志保留 %s 天，已清理过期日志：%s"
                        % (cfg.get("log_keep_days"), "、".join(gone)))
        except Exception as exc:                                # noqa: BLE001
            log("调度异常：%s" % exc)
        time.sleep(10)


# --------------------------------------------------------------------------
# HTTP 服务
# --------------------------------------------------------------------------
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def is_local_client(ip):
    """只接受本机与内网来源，避免端口被映射到公网后 API 直接暴露。"""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    if addr.is_loopback:
        return True
    return addr.is_private or addr.is_link_local


def _src_host(src):
    """解析来源头里的主机。

    返回 None 表示“这个头不参与校验”：包括空值，以及 file://、app://、
    android-app:// 这类非 http scheme —— 手机 App 的内嵌浏览器经常给出这种来源。
    """
    if not src:
        return None
    try:
        u = urlparse(src)
    except Exception:
        return None
    scheme = (u.scheme or "").lower()
    if scheme and scheme not in ("http", "https", "ws", "wss"):
        return None
    return (u.hostname or "").lower() or None


_local_ips_cache = {"ts": 0, "set": set()}


def _local_ip_set():
    """本机拥有的 IPv4 / IPv6 地址集合（不含回环）。带 30 秒缓存。"""
    now = now_ts()
    if now - _local_ips_cache["ts"] < 30 and _local_ips_cache["set"]:
        return _local_ips_cache["set"]
    out = set()
    try:
        # 走 /proc 解析，避免依赖 ip 命令的输出格式
        with open("/proc/net/fib_trie", "r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
        for m in re.finditer(r"\|--\s+(\d+\.\d+\.\d+\.\d+)", data):
            out.add(m.group(1))
    except Exception:
        pass
    try:
        with open("/proc/net/if_inet6", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    hexaddr = parts[0]
                    # /proc/net/if_inet6 用 32 位十六进制、大端、每组 4 位
                    raw = bytes.fromhex(hexaddr)
                    out.add(str(ipaddress.IPv6Address(raw)))
    except Exception:
        pass
    _local_ips_cache["ts"] = now
    _local_ips_cache["set"] = out
    return out


def _host_is_local(host):
    """来源主机是否是**本机**（而不是整个内网）。

    只放行本机是刻意的收紧：原先把整个内网（10.x / 172.16-31.x / 192.168.x）
    都当可信来源，等于「局域网里任意一台设备上跑个 Web 服务，都能伪造
    Origin 调用本面板的写接口」—— 内网里的恶意网页同样能发起跨站请求。

    放行的三类：
    - 回环地址（127.0.0.1 / ::1）与 localhost；
    - 本机自身持有的地址（NAS 的内网 IP）—— 飞牛 App 经本机网关转发时
      Origin 的主机正是本机的另一个端口，端口不同不等于跨站；
    - 链路本地地址（fe80::/10）—— 同样是本机网卡上的地址。
    """
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except Exception:
        # 域名无法离线核实，按不可信处理（走放行名单）
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    try:
        return str(addr) in _local_ip_set()
    except Exception:
        return False


# --------------------------------------------------------------------------
# 来源校验（CSRF）
#
# 只比对 Origin / Host 在真实客户端上太脆：飞牛 App（安卓 / iOS / 桌面端）用
# 官方页面外壳 office.app.5ddd.com 打开面板，再经 App 网关转发到设备的
# FN Connect 域名，于是 Origin 与 Host 天生不同，被误判成跨站伪造 —— 直接
# 结果就是手机端登录不了。因此改为两层：
#   1) 主校验：面板页每次加载下发一个随机令牌（写进 <meta name="ng-csrf">），
#      前端每个请求回带 X-NG-CSRF。跨站页面读不到我们的页面正文，拿不到令
#      牌；这条与域名无关，任何真正加载了面板页的客户端都能通过。
#   2) 兜底校验：没有令牌时（网关吞掉自定义头、curl、旧缓存页面）再比对来源，
#      规则见 Handler._csrf_ok。
# --------------------------------------------------------------------------
CSRF_HEADER = "X-NG-CSRF"
CSRF_META = "__NG_CSRF_NONCE__"
CSRF_TTL = 3 * 3600
CSRF_MAX = 96
_csrf_nonces = {}
_csrf_lock = threading.Lock()

# 飞牛官方客户端页面外壳：域名由厂商控制，普通用户挂不了任意页面，
# 放行不会给第三方站点留下伪造入口。
CSRF_APP_HOSTS = ("office.app.5ddd.com", "app.5ddd.com")
CSRF_APP_SUFFIXES = (".app.5ddd.com",)


def csrf_issue():
    """签发一个页面令牌（面板页每次加载都换新的，旧的自然过期）。"""
    tok = secrets.token_hex(16)
    now = time.time()
    with _csrf_lock:
        for k, exp in list(_csrf_nonces.items()):
            if exp < now:
                _csrf_nonces.pop(k, None)
        while len(_csrf_nonces) >= CSRF_MAX:
            _csrf_nonces.pop(next(iter(_csrf_nonces)), None)
        _csrf_nonces[tok] = now + CSRF_TTL
    return tok


def csrf_valid(tok):
    tok = (tok or "").strip()
    if not re.match(r"^[0-9a-f]{32}$", tok):
        return False
    with _csrf_lock:
        exp = _csrf_nonces.get(tok)
        if exp is None:
            return False
        if exp < time.time():
            _csrf_nonces.pop(tok, None)
            return False
    return True


def _host_allowlisted(host, cfg):
    """来源域名是否在放行名单里（精确域名 / .suffix 通配，也接受 *.suffix 写法）。"""
    if not host:
        return False
    host = host.lower().strip(".")
    if host in CSRF_APP_HOSTS:
        return True
    for suf in CSRF_APP_SUFFIXES:
        if host.endswith(suf):
            return True
    items = (cfg or {}).get("csrf_allow_origins") or []
    if isinstance(items, str):
        items = re.split(r"[\s,]+", items)
    if not isinstance(items, (list, tuple)):
        return False
    for item in items:
        # 兼容 "a.com, b.com" 这类整串写法（配置文件手写常见）
        for s in re.split(r"[\s,]+", str(item or "").strip().lower()):
            if not s:
                continue
            if s.startswith("*."):
                s = s[1:]
            if s.startswith("."):
                if host.endswith(s):
                    return True
            elif host == s:
                return True
    return False


class Handler(BaseHTTPRequestHandler):
    server_version = "NetGuard/" + VERSION
    protocol_version = "HTTP/1.1"

    # ---------- 输出辅助 ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _err(self, msg, code=400):
        self._json({"ok": False, "error": msg}, code)

    def log_message(self, fmt, *args):        # 静音默认访问日志
        return

    def _client_ok(self):
        ip = self.client_address[0]
        if is_local_client(ip):
            return True
        # 公网来源被拒：记录下来，用于横幅预警（说明端口可能已被映射出去）
        _rejected["count"] += 1
        _rejected["last_ip"] = ip
        _rejected["last_ts"] = now_ts()
        log("已拒绝公网来源访问：%s" % ip)
        self._err("仅允许内网访问", 403)
        return False

    def _token_from_request(self):
        tok = self.headers.get("X-NG-Token") or ""
        if tok:
            return tok.strip()
        m = re.search(r"ng_token=([A-Za-z0-9]+)", self.headers.get("Cookie") or "")
        return m.group(1) if m else ""

    def _auth_ok(self):
        """没设密码时保持开放（内网限制 + CSRF 已生效），设了就必须带 token。"""
        if not auth_enabled():
            return True
        if token_valid(self._token_from_request()):
            return True
        self._json({"ok": False, "error": "需要登录", "need_login": True}, 401)
        return False

    # 来源校验失败时返回给前端的提示（_csrf_ok 会补上来源域名细节）
    _csrf_msg = "请求来源校验失败，请刷新页面后重试"

    def _csrf_ok(self):
        """来源校验：阻断互联网上的恶意页面发起的跨站伪造请求。

        主校验是页面令牌（X-NG-CSRF），其次才看来源头。任一满足即放行：
        - 带有效页面令牌 → 与来源域名无关，真正加载过面板页的客户端都通过；
        - 缺 Origin / Referer（curl、部分 WebView）→ 放行，与原先一致；
        - 来源主机与本服务 Host 相同 → 放行；
        - 来源主机是**本机**地址（127.0.0.1 / ::1 / 本机自身网段）→ 放行。
          飞牛 App 的内嵌浏览器常经 App 自身网关转发请求，此时 Origin 的主机
          是本机的另一个端口，与本服务的 Host 不完全一致 —— 端口不同不等于跨站；
        - 来源主机在放行名单里：飞牛官方页面外壳（*.app.5ddd.com）+ 配置项
          csrf_allow_origins（自建反向代理 / 自定义域名）；
        - 其余情况 → 拒绝，并把详情记进日志。

        两处刻意收紧（防绕过）：
        - `Origin: null` 视为**不可信**并直接拒绝。浏览器在跨站场景会主动发这个值
          （sandbox iframe、file:// 页面、某些隐私模式），把它当「不参与校验」
          等于给跨站攻击开门。它与「压根没有 Origin 头」是两种不同的东西：
          前者出现了且内容明确，后者才是真的没带。
        - 只有**本机**地址放行，整个内网不再一律放行。否则局域网里任何一台设备
          上跑个 Web 服务，都能伪造 Origin 调用本面板的写接口。
          代价是走反代 / FN Connect 中继进来的请求需要带页面令牌（本来就该带）。
        """
        # 主校验：页面令牌。与来源域名无关，飞牛 App 网关改写 Host 也不受影响。
        if csrf_valid(self.headers.get(CSRF_HEADER)):
            return True

        host = ((self.headers.get("Host") or "").split(":")[0] or "").lower()
        cfg = load_config()
        for header in ("Origin", "Referer"):
            raw_val = self.headers.get(header)
            # `Origin: null` 是浏览器主动发出的跨站标记，不能当「没带这个头」放行。
            if raw_val and raw_val.strip().lower() == "null":
                log("来源校验拒绝：%s=null Host=%s UA=%s" % (
                    header, host, (self.headers.get("User-Agent") or "")[:90]))
                self._csrf_msg = ("请求来源校验失败（来源 %s 为 null）。"
                                  "请刷新页面后重试。" % header)
                return False
            src_host = _src_host(raw_val)
            if not src_host:
                continue
            if (src_host == host or _host_is_local(src_host)
                    or _host_allowlisted(src_host, cfg)):
                continue
            log("来源校验拒绝：%s=%s Host=%s UA=%s" % (
                header, src_host, host, (self.headers.get("User-Agent") or "")[:90]))
            self._csrf_msg = ("请求来源校验失败（来源 %s，本服务 %s）。"
                              "若经自有域名访问，请把该域名加入配置项 "
                              "csrf_allow_origins；否则刷新页面后重试。"
                              % (src_host, host or "未知"))
            return False
        return True

    # ---------- GET ----------
    def do_GET(self):                                        # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/") and path != "/api/auth":
            if not self._client_ok():
                return
            if not self._auth_ok():
                return

        if path in ("/", "/index.html"):
            return self._serve_file(os.path.join(WWW, "index.html"))

        if path == "/api/status":
            if not self._client_ok():
                return
            return self._json(status())

        if path == "/api/io":
            if not self._client_ok():
                return
            cfg = load_config()
            counts = cached("counts", 2, blocked_counts)
            guard_on = cached("inbound", 3, lambda: chain_active("NET_GUARD_IN", "INPUT"))
            out_on = cached("outbound", 3, lambda: chain_active("NET_GUARD", "OUTPUT"))
            return self._json({"ok": True, "io": io_snapshot(),
                               "mode": cfg["mode"], "state": read_state(),
                               "firewall": {"inbound_active": guard_on,
                                            "outbound_active": out_on,
                                            "blocked_v4": counts["v4"],
                                            "blocked_v6": counts["v6"],
                                            "blocked_total": counts["v4"] + counts["v6"],
                                            "counters_ok": counts["ok"]}})

        if path == "/api/log":
            if not self._client_ok():
                return
            qs = parse_qs(parsed.query)
            try:
                n = int((qs.get("lines") or ["80"])[0])
            except Exception:
                n = 80
            day = (qs.get("date") or [""])[0].strip()
            if day and not re.match(r"^\d{4}-\d{2}-\d{2}$", day):
                return self._err("日期格式应为 YYYY-MM-DD")
            day = day or datetime.now().strftime("%Y-%m-%d")
            return self._json({"ok": True, "date": day,
                               "content": tail_log(n, day)})

        if path == "/api/tunnels":
            if not self._client_ok():
                return
            cfg = load_config()
            return self._json({"ok": True, "running": tunnel_probe(cfg),
                               "all": tunnel_items(cfg),
                               "record": read_tunnel_state()})

        if path == "/favicon.ico":
            icon = os.path.join(DEST, "ui", "images", "icon-64.png")
            if os.path.exists(icon):
                return self._serve_file(icon)
            return self._send(204, b"", "image/png")

        # 静态资源（限定在 www 目录内）
        www_root = os.path.normpath(WWW)
        safe = os.path.normpath(os.path.join(www_root, path.lstrip("/")))
        # 必须用 commonpath 而不是字符串前缀：后者会放行 /www-secret 这类
        # 与本目录同前缀的兄弟目录，形成目录穿越。
        if (os.path.commonpath([www_root, safe]) == www_root
                and os.path.isfile(safe)):
            return self._serve_file(safe)

        return self._err("未找到", 404)

    # ---------- 认证 ----------
    def _handle_auth(self, body):
        if not isinstance(body, dict):
            return self._err("请求格式错误")
        op = str(body.get("op") or "")
        if op == "status":
            return self._json({"ok": True, "auth_required": auth_enabled()})

        if not self._csrf_ok():
            return self._err(self._csrf_msg, 403)

        pw = str(body.get("password") or "")

        if op == "setup":
            if auth_enabled():
                return self._err("密码已设置，请直接登录")
            if not (PW_MIN <= len(pw) <= PW_MAX):
                return self._err("密码长度需为 %d - %d 位" % (PW_MIN, PW_MAX))
            set_password(pw)
            return self._json({"ok": True, "token": issue_token()})

        if op == "login":
            if not auth_enabled():
                return self._json({"ok": True, "token": ""})
            allow, msg = login_penalty()
            if not allow:
                return self._err(msg, 429)
            if not check_password(pw):
                note_login_fail()
                time.sleep(0.5)          # 略微抬高爆破成本
                log("面板登录失败（来源 %s）" % self.client_address[0])
                return self._err("密码错误", 401)
            _auth_fails["n"] = 0
            log("面板登录成功（来源 %s）" % self.client_address[0])
            return self._json({"ok": True, "token": issue_token()})

        if op == "changepw":
            if not auth_enabled():
                return self._err("尚未设置密码")
            if not token_valid(self._token_from_request()):
                return self._err("需要登录", 401)
            old = str(body.get("old_password") or "")
            if not check_password(old):
                note_login_fail()
                time.sleep(0.5)
                return self._err("原密码错误", 401)
            if not (PW_MIN <= len(pw) <= PW_MAX):
                return self._err("新密码长度需为 %d - %d 位" % (PW_MIN, PW_MAX))
            set_password(pw)
            drop_all_tokens()
            log("面板密码已修改，其它设备需重新登录")
            return self._json({"ok": True, "token": issue_token()})

        return self._err("不支持的操作")

    def _serve_file(self, filepath):
        if not os.path.isfile(filepath):
            return self._err("文件不存在", 404)
        ext = os.path.splitext(filepath)[1].lower()
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except Exception:
            return self._err("读取失败", 500)
        if ext in (".html", ".htm"):
            # 面板页注入一次性来源令牌（跨站页面读不到正文，因此拿不到它）
            try:
                text = data.decode("utf-8")
                if CSRF_META in text:
                    data = text.replace(CSRF_META, csrf_issue()).encode("utf-8")
            except Exception:
                pass
        return self._send(200, data, MIME.get(ext, "application/octet-stream"))

    # ---------- POST ----------
    def do_POST(self):                                       # noqa: N802
        if not self._client_ok():
            return
        parsed = urlparse(self.path)
        if parsed.path != "/api/auth" and not self._auth_ok():
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > 256 * 1024:
            return self._err("请求体过大", 413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return self._err("JSON 解析失败")

        if parsed.path == "/api/auth":
            return self._handle_auth(body)

        if parsed.path == "/api/action":
            action = str(body.get("action") or "")
            if action not in ("off", "on", "reconcile", "cycle", "reload"):
                return self._err("不支持的动作")
            # 所有动作都要过来源校验：解除封锁、cycle（先断后连）同样危险，
            # 只校验 off 等于留下一个“跨站页面替你解除封锁”的口子。
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            result = do_action(action, manual=True)
            return self._json(result)

        if parsed.path == "/api/config":
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            with _cfg_lock:
                base = load_config()
                cfg, errs = validate_config(body, base)
                errs = errs + lan_warnings(cfg, self.client_address[0])
                save_config(cfg)
            # 配置变更后让新规则立刻生效：
            # 正在封锁时用 reload 原地重建（不改变状态），否则按时间纠偏。
            act = "reload" if read_state() == "off" else "reconcile"
            res = run_script(act, timeout=150)
            return self._json({"ok": True, "config": _cfg_public(cfg), "warnings": errs,
                               "reconcile": res, "status": status()})

        if parsed.path == "/api/notify/test":
            # 发一条测试消息：配置阶段最需要确认的就是“地址对不对、群里收不收得到”
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            res = notify_push(_text_test(), queue_on_fail=False)
            if res.get("ok"):
                return self._json({"ok": True})
            return self._json({"ok": False, "error": res.get("error") or "发送失败"}, 400)

        if parsed.path == "/api/purge":
            # 一键彻底复原：清空本程序留下的全部 iptables 规则、补回默认路由。
            # 用途：卸程序之前必点；或发现「恢复网络后 FN Connect 中继还是不通」时排障。
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            cfg = load_config()
            res = run_script("purge", timeout=150)
            clear_intent(TUNNEL_INTENT)
            clear_intent(FN_INTENT)
            set_manual(None)
            invalidate_probe(cfg.get("tunnel_services"))
            invalidate_probe(cfg.get("fnconnect_services"))
            _last_action["ts"] = now_ts()
            _last_action["msg"] = "清理规则 %s" % ("成功" if res.get("ok") else "失败")
            session_take()          # 规则都清了，本次封锁的会话快照没有意义了
            notify_async(_text_purge(res))
            return self._json({"ok": bool(res.get("ok")), "purge": res,
                               "status": status()})

        if parsed.path == "/api/verify":
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            res = verify_guard()
            return self._json({"ok": True, "verify": res})

        if parsed.path == "/api/log":
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            op = str(body.get("op") or "")
            if op != "purge":
                return self._err("不支持的操作")
            before = str(body.get("before") or "").strip()
            if not before:
                return self._err("缺少清理截止日期")
            res = purge_logs(before)
            if not res.get("ok"):
                return self._err(res.get("error") or "清理失败")
            with _cache_lock:
                _cache.pop("logdates", None)
                _cache.pop("logdates_ts", None)
            return self._json({"ok": True, "removed": res["removed"],
                               "freed": res["freed"],
                               "dates": list_log_dates()})

        if parsed.path == "/api/fnconnect":
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            op = str(body.get("op") or "")
            cfg = load_config()
            if op == "stop":
                res = stop_fnconnect(cfg)
                set_intent(FN_INTENT, "stopped", cfg)
            elif op == "start":
                res = start_fnconnect()
                set_intent(FN_INTENT, "running", cfg)
            else:
                return self._err("不支持的操作")
            invalidate_probe(cfg.get("fnconnect_services"))
            return self._json({"ok": True, "result": res, "items": fn_items(cfg)})

        if parsed.path == "/api/tunnels":
            if not self._csrf_ok():
                return self._err(self._csrf_msg, 403)
            op = str(body.get("op") or "")
            cfg = load_config()
            if op == "stop":
                res = stop_tunnels(cfg)
                set_intent(TUNNEL_INTENT, "stopped", cfg)
            elif op == "start":
                res = start_tunnels()
                set_intent(TUNNEL_INTENT, "running", cfg)
            else:
                return self._err("不支持的操作")
            with _cache_lock:
                _cache.pop(("probe", tuple(cfg["tunnel_services"])), None)
            return self._json({"ok": True, "result": res,
                               "running": tunnel_probe(cfg),
                               "all": tunnel_items(cfg)})

        return self._err("未找到", 404)


def main():
    ensure_dirs()
    tighten_perms()
    _ensure_log_dir()
    cfg = load_config()
    write_conf_sh(cfg)          # 每次启动都按 JSON 重建 shell 配置，防止两者不一致
    migrate_legacy_log()        # 旧版单文件日志迁移到按日目录
    log("网络守卫 v%s 启动，端口 %s，配置目录 %s" % (VERSION, PORT, ETC))
    gone = auto_purge_logs(cfg.get("log_keep_days", LOG_KEEP_DAYS_DEFAULT))
    if gone:
        log("启动时清理过期日志：%s" % "、".join(gone))

    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()
    # 网卡流量采样（独立于 HTTP 请求，保证曲线连续）
    threading.Thread(target=io_loop, daemon=True).start()
    # 公网暴露检测要联网查出口 IP，后台预热，别卡住页面首个请求
    threading.Thread(target=lambda: cached("exposure", 600, exposure_check),
                     daemon=True).start()

    # 断网期间没能发出去的告警（如「已解除封锁」），等网络恢复后补推。
    # 延后几秒再发：刚启动时网络可能还没完全就绪。
    def _flush_pending_later():
        time.sleep(15)
        try:
            if _pending_load():
                log("启动后检查待发队列，开始补推")
                _pending_flush()
        except Exception as exc:                              # noqa: BLE001
            log("启动后补推待发队列异常：%s" % exc)
    threading.Thread(target=_flush_pending_later, daemon=True).start()

    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    except OSError as exc:
        log("端口 %s 绑定失败：%s" % (PORT, exc))
        sys.exit(1)
    log("HTTP 服务已监听 0.0.0.0:%s" % PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
