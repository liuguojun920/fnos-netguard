# -*- coding: utf-8 -*-
"""打包终验：gzip 头、checksum、版本号、权限位、包内是否含本轮全部新逻辑。

用法（在仓库根目录执行，需先跑 build_fpk.py）：
    python tools/verify_pkg.py
"""
import hashlib
import io
import os
import re
import tarfile

# 本脚本在 tools/ 下，仓库根目录是它的上一级。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_pkg():
    """找出待校验的包：优先带版本号的那个，其次最新修改的 .fpk。"""
    named = sorted(
        (os.path.join(ROOT, f) for f in os.listdir(ROOT)
         if f.startswith("app.netguard-") and f.endswith(".fpk")),
        key=os.path.getmtime, reverse=True)
    if named:
        return named[0]
    plain = os.path.join(ROOT, "app.netguard.fpk")
    if os.path.exists(plain):
        return plain
    # 退而求其次：任何 .fpk 里最新的
    anyfpk = sorted((os.path.join(ROOT, f) for f in os.listdir(ROOT)
                     if f.endswith(".fpk")), key=os.path.getmtime, reverse=True)
    return anyfpk[0] if anyfpk else plain


OUT = _find_pkg()
P = F = 0
def chk(cond, name):
    global P, F
    if cond:
        print("PASS  " + name); P += 1
    else:
        print("FAIL  " + name); F += 1

raw = open(OUT, "rb").read()
chk(raw[:2] == b"\x1f\x8b", "fpk 外层是 gzip（%.1f KB）" % (len(raw) / 1024.0))

with tarfile.open(OUT) as t:
    app = t.extractfile("app.tgz").read()
    man = t.extractfile("manifest").read().decode("utf-8")

md5 = hashlib.md5(app).hexdigest()
chk(md5 == re.search(r"checksum\s*=\s*([0-9a-f]{32})", man).group(1), "checksum 与内层 tgz 一致")
ver = re.search(r"version=([0-9.]+)", man).group(1)
pyver = re.search(r'VERSION\s*=\s*"([0-9.]+)"', io.open(
    os.path.join(ROOT, "app", "server", "server.py"), encoding="utf-8").read()).group(1)
chk(ver == pyver, "manifest 与 server.py 版本一致（%s / %s）" % (ver, pyver))

with tarfile.open(fileobj=io.BytesIO(app)) as it:
    py = it.extractfile("server/server.py").read().decode("utf-8")
    sh = it.extractfile("server/net-guard.sh").read().decode("utf-8")
    html = it.extractfile("server/www/index.html").read().decode("utf-8")
    modes = {x.name: oct(x.mode) for x in it.getmembers()}

chk(py.count('VERSION = "%s"' % ver) == 1, "server.py VERSION=%s" % ver)
# v1.0.17：解锁计数——动作前采样 + 脚本落盘兜底
chk("def counts_before_unblock" in py and "def read_last_counts" in py,
    "解锁前取数的三层逻辑在包内")
chk('pre_counts = counts_before_unblock() if action == "on" else None' in py,
    "do_action 在脚本拆链之前就把计数取走")
chk("def record_last_session" in py and "def read_last_session" in py,
    "上次封锁的最终统计会落盘（面板解锁后仍能展示）")
chk('"last_session": read_last_session()' in py, "status 回给前端 last_session")
chk("计数不可用（iptables 未能读取）" not in py, "旧的误导文案已移除")
chk("未统计（锁定时未能读到防火墙计数器）" in py, "确实拿不到时如实说明原因")
chk("guard_count() {" in sh and "s += $1" in sh, "脚本统计改为所有 DROP 规则之和")
chk('> "$STATE_DIR/last-counts"' in sh, "解锁拆链之前把计数落盘")
chk("LAST_COUNTS = os.path.join(STATE_DIR" in py, "后端知道去哪里读这份落盘")
chk("mmddhhmm" in html and "上次封锁" in html, "前端展示上次封锁拦了多少")
# v1.0.16：restore_services 异步化 + 前端非 JSON 错误可读
chk("RESTORE_DELAY" in sh and "sleep \"$RESTORE_DELAY\"" in sh
    and ") >/dev/null 2>&1 &" in sh,
    "脚本侧 restore_services 已异步延迟重启（不掐断用户当前连接）")
chk("服务返回了异常内容" in html and "r.text()" in html,
    "前端对网关 HTML 错误页给出可读提示")
chk("自动重启以重建中继" in html, "解除成功时提示 FN Connect 将短暂重启")
# v1.0.15：企业微信机器人通知
chk("def parse_webhook" in py and "def mask_webhook" in py and "def notify_push" in py,
    "机器人地址校验 / 掩码 / 发送逻辑在包内")
chk("\"notify_webhook\"" in py, "配置项 notify_webhook 已加入默认配置")
chk("def notify_async" in py and "threading.Thread(target=_run, daemon=True)" in py,
    "通知在后台线程发送，不阻塞面板操作")
chk("def session_begin" in py and "def notify_end_summary" in py and "def session_take" in py,
    "封锁会话快照与结束概览在包内")
chk("WECOM_HOST = \"qyapi.weixin.qq.com\"" in py, "只允许企业微信官方域名（防 SSRF）")
chk('"config": _cfg_public(cfg)' in py, "status 回给前端的是掩码配置")
chk("notify_async(_text_start(" in py and "notify_end_summary(cfg, result, sess, pre_counts)" in py,
    "开始 / 结束都会推送（结束时带上动作前采到的计数）")
chk("notify_async(_text_fail(" in py and "notify_async(_text_purge(res))" in py,
    "失败与彻底复原也会推送")
chk("session_guard_bump()" in py and "notify_guard_change()" in py, "守卫自纠会计数并提醒")
chk("/api/notify/test" in py, "有发测试接口")
chk('id="cfgNotify"' in html and 'id="btnNotifyTest"' in html, "前端有输入框与发测试按钮")
chk("X-NG-CSRF" in html and "cfgNotify" in html, "令牌与通知输入框都在同一页面")
chk("notify_webhook: wh" in html, "保存高级选项会提交机器人地址")
# v1.0.14：页面令牌（主校验）+ 来源兜底
chk("CSRF_HEADER = \"X-NG-CSRF\"" in py and "def csrf_issue" in py and "def csrf_valid" in py,
    "页面令牌的签发与校验在包内")
chk("csrf_valid(self.headers.get(CSRF_HEADER))" in py, "_csrf_ok 以令牌为主校验")
chk("def _host_allowlisted" in py and "\".app.5ddd.com\"" in py,
    "飞牛 App 页面外壳在放行名单里")
chk("\"csrf_allow_origins\"" in py, "配置项 csrf_allow_origins 已加入默认配置")
chk("text.replace(CSRF_META, csrf_issue())" in py, "面板页真的下发了令牌")
chk(py.count("self._err(self._csrf_msg, 403)") >= 8, "所有受保护接口都改用带来源细节的提示")
chk('"请求来源校验失败，请刷新页面后重试", 403' not in py, "旧的固定提示已全部替换")
chk('name="ng-csrf"' in html and "__NG_CSRF_NONCE__" in html, "前端 meta 占位符在包内")
chk('opt.headers["X-NG-CSRF"] = csrf' in html, "前端每个请求回带令牌")
# 来源校验：App 内嵌浏览器走的是「官方外壳域名放行」与「自定义 scheme 不参与校验」，
# 不是靠「整个内网都放行」。后者是 v1.0.22 修掉的绕过点。
chk("def _src_host" in py and "def _host_is_local" in py and "来源校验拒绝" in py,
    "来源校验支持 App 内嵌浏览器（官方外壳域名 / 自定义 scheme 放行）")
chk("_host_is_local(src_host)" in py and "_host_is_lan" not in py,
    "来源校验只放行本机，不再放行整个内网")
chk('== "null"' in py or 'strip().lower() == "null"' in py,
    "Origin: null 被显式拒绝（跨站 sandbox / file:// 页面）")
# v1.0.22 的三项可靠性修复
chk('set_manual("on", manual_hold_until(cfg))' in py,
    "手动解除封锁会写入「已放行」覆盖，不会被调度器撤销")
chk("def _sh_quote" in py and "_sh_quote(cfg[" in py,
    "写入 shell 配置前统一转义（防 root 级命令注入）")
chk("def _write_json_atomic" in py and py.count("_write_json_atomic(") >= 8,
    "状态文件全部走原子写（崩溃不留半截 JSON）")
chk("@media(max-width:640px)" in html and "@media(hover:none)" in html,
    "移动端样式（窄屏 + 触屏）在包内")
chk("initStaticNotes" in html and "toggleNote" in html and "canHover" in html,
    "说明条点按展开机制在包内")
chk("font-size:16px" in html and "min-height:46px" in html,
    "触摸目标与 iOS 输入框字号适配在包内")
chk("return min(int(nxt[" + chr(34) + "ts" + chr(34) + "]), limit)" in py, "手动意图 6 小时上限已生效")
chk("def _day_account" in py and "def _boot_ts" in py, "当日流量累计逻辑在包内")
chk("def guard_verify" in py and "do_verify()" in sh, "守卫自纠逻辑仍在")
chk("fmtDurSec" in html and "renderManualHint" in html, "倒计时与重写后的提示在包内")
chk("ioTodayTx" in html and "renderIoToday" in html, "今日累计展示在包内")
chk("function setNote(" in html and "authTip" not in html, "说明悬停化 + 密码介绍已删除")
# v1.0.12：禁用态按钮不再被 hover 刷成面板底色（白底白字）
chk(".btn.stop:not(:disabled):hover" in html and ".btn.start:not(:disabled):hover" in html,
    "语义按钮 hover 只对可点击态生效")
chk((chr(34) + "light" + chr(34)).join(["html[data-theme=", "] .btn.stop:disabled"]) in html
    or "html[data-theme=\"light\"] .btn.stop:disabled" in html, "亮色主题下禁用态有专属配色")
bad = "html[data-theme=\"light\"] .btn:disabled:hover{background:var(--panel-2)"
chk(bad not in html, "不再有把 disabled:hover 刷成 panel-2 的通用规则（白底白字根因）")
chk(".btn.stop:hover{" not in html and ".btn.start:hover{" not in html, "旧的裸 hover 规则已清除")
# v1.0.18：卸载不再报「未知错误」——锁等待可配置 + 钩子兜底清进程/等端口
chk('FLOCK_WAIT="${FLOCK_WAIT:-20}"' in sh, "锁等待时长可配置（默认 20s）")
chk('flock -w "$FLOCK_WAIT" 9' in sh, "with_lock 真正使用 FLOCK_WAIT")
main_hook = io.open(os.path.join(ROOT, "cmd", "main"), encoding="utf-8").read()
un_hook = io.open(os.path.join(ROOT, "cmd", "uninstall_init"), encoding="utf-8").read()
chk("FLOCK_WAIT=5" in main_hook, "main stop 的 purge 最多等锁 5 秒")
chk("FLOCK_WAIT=5" in un_hook, "uninstall_init 的 purge 最多等锁 5 秒")
chk('pkill -f "$SERVER"' in main_hook and "pgrep -f \"$SERVER\"" in main_hook,
    "main stop 按命令行兜底清理残留后端并等其退出")
chk("pkill -f \"${TRIM_APPDEST}/server/server.py\"" in un_hook,
    "uninstall_init 也兜底清理孤儿后端进程")
# v1.0.19：安全加固 + 作者署名
chk('AUTHOR = "带刀的文人"' in py, "作者常量在包内")
chk('"author": AUTHOR,' in py, "status 下发作者（面板版本处要用）")
chk("s.author" in html, "面板版本处拼接作者")
chk("带刀的文人" in man, "安装包介绍（desc）含作者")
chk('import io\nimport ipaddress' in py, "io 已导入（否则 /proc 读取静默失败）")
chk('if action == "off" and not self._csrf_ok()' not in py,
    "动作接口不再只对 off 校验来源")
chk("def _write_private" in py and "os.chmod(tmp, 0o600)" in py,
    "凭证文件（机器人 key / 密码哈希）按 0600 落盘")
chk("def tighten_perms" in py, "启动时收紧旧凭证文件权限")
chk("os.path.commonpath([www_root, safe])" in py, "静态资源做真实目录包含判断")
chk('if "csrf_allow_origins" in raw' in py, "来源域名白名单可配置")
chk("def _hide_secret" in py, "机器人 key 不进日志/报错")
chk('id="cfgOrigins"' in html, "高级选项有「允许的来源域名」输入框")
# v1.0.20：覆盖更新提速 + 手机端一行排版 + 定时任务隐藏隧道名单
up_hook = io.open(os.path.join(ROOT, "cmd", "upgrade_callback"), encoding="utf-8").read()
chk('( "$MAIN" start >/dev/null 2>&1 ) &' in up_hook,
    "升级收尾改为后台异步拉起（不再同步等 start）")
chk('"$MAIN" status >/dev/null 2>&1; then break' in up_hook,
    "异步拉起后钩子最多再确认 3 秒")
chk(".link-dot{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--muted);white-space:nowrap}" in html,
    "「已连接」不折行")
chk(".ver{font-family:var(--mono);font-size:13px;color:var(--dim);white-space:nowrap}" in html,
    "版本号不折行")
chk(html.count("white-space:nowrap") >= 5, "按钮/头部/提示均不折行（nowrap 覆盖足够）")
chk(".card-h .hint{margin-left:0;width:100%}" not in html,
    "卡片标题提示不再强制掉到单独一行")
chk("text-overflow:ellipsis" in html, "过长提示以省略号收纳")
chk(".ver .alab{display:none}" in html and "_vname.textContent = s.author" in html,
    "窄屏隐藏「作者」标签字样但保留名字（span 结构）")
chk('id="tunSvcWrap"' in html and 'if (tw) tw.style.display = on ? "none" : "";' in html,
    "定时任务模式下隐藏隧道进程名名单")
chk("定时任务的自动启停同样按这份名单执行" in html, "隧道名单说明同步更新")
chk(modes.get("server/net-guard.sh") == "0o755", "net-guard.sh 权限 755")
chk(modes.get("server/server.py") == "0o755", "server.py 权限 755")

print("=========== %d PASS / %d FAIL ===========" % (P, F))
raise SystemExit(1 if F else 0)
