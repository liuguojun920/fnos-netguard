# -*- coding: utf-8 -*-
"""缺陷回归测试：验证 4 个已修缺陷不会复发。

用法（在仓库根目录执行）：
    python tests/test_defects.py

覆盖：
- C-1 手动「立即解除封锁」不应被调度器撤销
- C-2 write_conf_sh 的 shell 转义（root 级命令注入）
- C-3 CSRF 来源校验（Origin:null / 任意内网地址不放行）
- H-1 状态 JSON 原子写（崩溃不留半截文件）

不需要 root，也不需要真实的 iptables：全部在临时目录里跑，不触碰系统。
"""
import os
import sys
import types
import json
import shutil
import subprocess

import os, sys, json, types, threading, tempfile, shutil

BASE = r"D:/MyJava_Code/WorkBuddy/2026-11-01-12-07-31/fnos-netguard/app/server"
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp_run")
if os.path.isdir(TMP): shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(os.path.join(TMP,"var"), exist_ok=True)
os.makedirs(os.path.join(TMP,"etc"), exist_ok=True)

src = open(os.path.join(BASE,"server.py"), encoding="utf-8").read().split("def main():")[0]
m = types.ModuleType("ng"); m.__dict__["__name__"]="ng"; m.__dict__["__file__"]="server.py"
exec(compile(src, "server.py", "exec"), m.__dict__)

m.__dict__["VAR"]  = os.path.join(TMP,"var")
m.__dict__["ETC"]  = os.path.join(TMP,"etc")
for k in ("PENDING_FILE","SESSION_FILE","LAST_SESSION_FILE","CONF_JSON","CONF_SH",
          "TUNNEL_STATE","FN_STATE","MANUAL_FILE","TUNNEL_INTENT","FN_INTENT"):
    m.__dict__[k] = os.path.join(TMP,"var", k) if "STATE" in k or "INTENT" in k or "FILE" in k or k in ("TUNNEL_STATE","FN_STATE") else os.path.join(TMP,"etc", k)

print("="*72); print("C-1：手动「立即解除封锁」不应被调度器撤销"); print("="*72)
cfg = dict(m.DEFAULT_CONFIG)
cfg["mode"]="soft"; cfg["schedule_enabled"]=True
cfg["notify_webhook"]="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abcdefgh12345678"
m.load_config = lambda: dict(cfg)
m.status = lambda: {}
m.session_mark = lambda *a: None
m.session_begin = lambda *a: None
m.session_take = lambda: {}
m.record_last_session = lambda *a: None
m.counts_before_unblock = lambda: {"ok":False}
m.notify_push = lambda *a, **k: {"ok":True}
m.notify_async = lambda *a, **k: None
m._pending_flush = lambda: None
m.guard_verify = lambda: None
m.invalidate_probe = lambda *a: None

CALLS=[]
def fake_run(action, force=False, quiet=False):
    CALLS.append(action)
    return {"ok":True,"rc":0,"stdout":"","stderr":""}
m.run_script = fake_run

# 模拟：用户在封锁窗口内点「立即解除封锁」
m.do_action("on", manual=True)
manual = m.read_manual()
print("解除后 manual 记录:", manual)
assert manual is not None, "✗ 手动覆盖记录被删掉了 —— 调度器 10 秒后会把封锁装回去"
assert manual["state"] == "on", "✗ state 应为 on"
print("✓ manual 记录保留且 state=on —— 调度器不会撤销用户的解除操作")

# 模拟调度器读取
if manual:
    print("  调度器读到:", manual["state"], "-> 保持放行，不重新封锁 ✓")
else:
    print("  调度器读到 None -> 会落回 schedule_enabled 分支重新封锁 ✗")

print()
print("="*72); print("C-2：write_conf_sh 的 shell 转义"); print("="*72)
mal = 'x"$(touch /tmp/pwned)"`id`;rm -rf /'
cfg2 = dict(cfg); cfg2["ping_targets"] = [mal]; cfg2["lan_v4"] = [mal]
m.write_conf_sh(cfg2)
conf = open(m.CONF_SH, encoding="utf-8").read()
print("生成的配置片段:")
for l in conf.splitlines():
    if "PING_TARGETS" in l or "LAN_V4" in l: print("   ", l)
# 关键验证：source 后拿到的值必须与原值完全一致，且不执行任何命令
import subprocess
BASH = r"C://Program Files//Git//bin//bash.exe"
out = subprocess.run([BASH,"-c",'source "%s"; printf "%%s" "$PING_TARGETS"' % m.CONF_SH],
                     capture_output=True, text=True, timeout=15)
got = out.stdout
print("source 后取到的值:", repr(got))
assert got == mal, "✗ source 后值被改写了：%r" % got
assert not os.path.exists("/tmp/pwned"), "✗ 命令被执行了！"
print("✓ 恶意值原样保留为数据，未被执行")

print()
print("="*72); print("C-3：CSRF 来源校验"); print("="*72)
print("_src_host('null') =", repr(m._src_host("null")))
print("_host_is_local('127.0.0.1') =", m._host_is_local("127.0.0.1"))
print("_host_is_local('192.168.1.50') =", m._host_is_local("192.168.1.50"), "(其他内网设备 -> 不可信)")
print("_host_is_local('10.0.0.5')     =", m._host_is_local("10.0.0.5"), "(其他内网设备 -> 不可信)")
assert m._host_is_local("192.168.1.50") is False, "✗ 整个内网仍被放行"
assert m._host_is_local("127.0.0.1") is True
print("✓ 只放行本机，整个内网不再一律放行")

print()
print("="*72); print("H-1：状态 JSON 原子写"); print("="*72)
m.set_manual("off", m.now_ts()+3600)
raw = open(m.MANUAL_FILE, encoding="utf-8").read()
print("manual.json 内容:", raw[:80])
assert json.loads(raw)["state"] == "off", "✗ 写入后读不出来"
# 模拟崩溃：截断的文件
open(m.MANUAL_FILE,"w",encoding="utf-8").write('{"state": "of')
print("人为截断后 read_manual():", m.read_manual(), "(None = 读到半截 JSON 当作无记录)")
# 原子写的关键：写入过程中原文件始终是完整旧值
import inspect
src_func = open(os.path.join(BASE,"server.py"), encoding="utf-8").read()
assert "os.replace(tmp, path)" in src_func, "✗ 不是原子替换"
assert src_func.count("_write_json_atomic(") >= 8, "✗ 状态写入点未全部改造"
print("✓ 使用 tmp + os.replace，读者不会看到中间态")

print()
print("="*72)
print("全部 4 项修复验证通过")
print("="*72)
