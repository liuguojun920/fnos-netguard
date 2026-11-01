#!/usr/bin/env bash
# stub smoke test for net-guard.sh (fpk build)
# iptables/ip6tables 用带状态的模型：能真实反映规则是否被挂上、是否被拆干净，
# 从而覆盖住「切换防护模式后旧规则残留」这类致命缺陷。
#
# 用法：在仓库根目录执行  bash tests/smoke_netguard.sh
# 用的是 stub 模型，不触碰本机真实的 iptables / 路由。
#
# 环境要求：Linux（fnOS / Debian）。本测试用 stub 模拟 iptables / ip / systemctl，
# 但脚本里仍会走到 ping、flock、timeout 等系统命令的差异行为 —— 在 Windows 的
# Git Bash 下这些命令语义不同（ping 不认 -W/-n、timeout 不杀子进程组），
# 会导致用例挂住。检测到非 Linux 时直接跳过，不浪费 CI 时间。
set -u

# NG_FAKE_OS 可覆盖系统识别，方便在 CI 里强制走 Linux 分支。
case "${NG_FAKE_OS:-$(uname -s)}" in
  Linux) : ;;
  *)
    echo "SKIP  需要 Linux 环境（当前：${NG_FAKE_OS:-$(uname -s)}）。本测试依赖 ping / timeout / flock 的 Linux 语义。"
    exit 0
    ;;
esac

# 仓库根目录 = 本脚本所在目录的上一级
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT=/tmp/ngsmoke
export ROOT
rm -f /gone 2>/dev/null || true
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/state" "$ROOT/logs"
BIN="$ROOT/bin"
export STUB_LOG="$ROOT/calls.txt"
RULES="$ROOT/rules"
export RULES
: > "$STUB_LOG"
: > "$RULES"

cat > "$BIN/id" <<'EOF'
#!/usr/bin/env bash
echo 0
EOF
cat > "$BIN/ip" <<'EOF'
#!/usr/bin/env bash
# 通用 ip stub：只要没被标记为“路由已删”，任何 route 查询都能拿到默认路由，
# link 查询都能拿到 eth0 —— 否则 primary_iface 判空会让 soft/strict 用例静默早退。
ROUTE_GONE="${ROOT:-/tmp/ngsmoke}/gone"
args="$*"
a1="${1:-}"; a2="${2:-}"; a3="${3:-}"
case "$args" in
  *"route del"*) : > "$ROUTE_GONE"; exit 0;;
esac
if [ "$a1" = "-4" ] || [ "$a1" = "-6" ] || [ "$a1" = "-o" ]; then
  if [ "$a2" = "route" ] && [ "$a3" = "del" ]; then : > "$ROUTE_GONE"; exit 0; fi
fi
gone=0
[ -f "$ROUTE_GONE" ] && gone=1
[ "${FAKE_ROUTE_GONE:-0}" = "1" ] && gone=1
case "$args" in
  *link*) if [ "$gone" = "1" ]; then echo "2: eth0: <BROADCAST,MULTICAST> state DOWN"; else echo "2: eth0: <BROADCAST,MULTICAST,UP> state UP"; fi; exit 0;;
  *addr*) echo "inet 192.168.1.11/24 brd 192.168.1.255 scope global eth0"; exit 0;;
  *route*) [ "$gone" = "1" ] || echo "default via 192.168.1.1 dev eth0"; exit 0;;
esac
exit 0
EOF

cat > "$BIN/iptables" <<'EOF'
#!/usr/bin/env bash
# 极简 netfilter 模型：规则文件每行 "<所属链>|<规则参数>"
R="${RULES:-/tmp/ngsmoke/rules}"
echo "iptables $*" >> "${STUB_LOG:-/dev/null}"
new=(); for a in "$@"; do [ "$a" = "-w" ] || new+=("$a"); done
set -- "${new[@]}"
CMD="${1:-}"; C2="${2:-}"
tgt=""; prev=""
for a in "$@"; do if [ "$prev" = "-j" ]; then tgt="$a"; fi; prev="$a"; done
case "$CMD" in
  -S)
     if [ -n "$C2" ]; then awk -F'|' -v c="$C2" '$1==c {print "-A", $1, $2}' "$R" 2>/dev/null
     else awk -F'|' '{print "-A", $1, $2}' "$R" 2>/dev/null; fi
     exit 0;;
  -C)
     [ -z "$tgt" ] && exit 1
     awk -F'|' -v c="$C2" -v t="-j $tgt" '$1==c && $2==t {found=1} END{exit(found?0:1)}' "$R" 2>/dev/null
     exit $?;;
  -I|-A)
     [ -z "$tgt" ] && exit 1
     printf '%s|-j %s\n' "$C2" "$tgt" >> "$R"; exit 0;;
  -D)
     n=0; tmp="$R.tmp"; : > "$tmp"
     while IFS='|' read -r c r; do
       if [ "$c" = "$C2" ] && [ "$r" = "-j $tgt" ] && [ "$n" -eq 0 ]; then n=1; continue; fi
       printf '%s|%s\n' "$c" "$r" >> "$tmp"
     done < "$R"
     mv "$tmp" "$R"
     [ "$n" -eq 1 ] && exit 0 || exit 1;;
  -F|-X)
     tmp="$R.tmp"; : > "$tmp"
     while IFS='|' read -r c r; do
       [ "$c" = "$C2" ] && continue
       printf '%s|%s\n' "$c" "$r" >> "$tmp"
     done < "$R"
     mv "$tmp" "$R"; exit 0;;
  -N) printf '%s|-j __NEW__\n' "$C2" >> "$R"; exit 0;;
  -L)
     # 供 guard_count / blocked_counts 解析：每条规则一行，pkts 由 STUB_PKTS 决定
     awk -F'|' -v c="$C2" -v p="${STUB_PKTS:-0}" '
       $1==c {
         t=$2; sub(/^-j[[:space:]]*/, "", t); sub(/[[:space:]].*/, "", t);
         printf "%10d %10d %-8s all  --  *      *       0.0.0.0/0            0.0.0.0/0\n", p, p*60, t
       }' "$R" 2>/dev/null
     exit 0;;
esac
exit 0
EOF
sed "s/^echo \"iptables /echo \"ip6tables /" "$BIN/iptables" > "$BIN/ip6tables"

cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "${STUB_LOG:-/dev/null}"
case "$1" in
  is-active) echo "${FAKE_ACTIVE:-inactive}"; exit 0;;
  list-unit-files) echo "fn-connect.service enabled"; exit 0;;
esac
exit 0
EOF
cat > "$BIN/pgrep" <<'EOF'
#!/usr/bin/env bash
if [ "${FAKE_APT:-0}" = "1" ] && [ "$2" = "apt" ]; then exit 0; fi
exit 1
EOF
cat > "$BIN/pkill" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/logger" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/ping" <<'EOF'
#!/usr/bin/env bash
# ping 的 stub：默认认为网络是通的（返回 0）。
# 不 stub 的话会调到 Windows 自带的 ping —— 它不认 `-W` / `-n` 这类参数，
# 在恢复网络后的连通性自检里会挂住，整个测试就卡死了。
# 想模拟断网时不通，设 FAKE_PING_FAIL=1。
if [ "${FAKE_PING_FAIL:-0}" = "1" ]; then exit 1; fi
exit 0
EOF
cat > "$BIN/timeout" <<'EOF'
#!/usr/bin/env bash
# timeout 的 stub：把选项与持续时间参数剥掉后，直接执行被包裹的命令。
# 需要正确跳过 `-k <秒>`、`-w <秒>` 以及紧跟其后的持续时间（纯数字）——
# 只 shift 一次会把 `5` / `60` 当成命令去执行，导致断言全部取到 127 退出码。
#
# 注意：stub 不实现真正的超时杀进程。net-guard.sh 内部有「后台延迟重启服务」
# 这类异步子进程，父 shell 会等它们结束；真 timeout 也不管这个（它只管被包裹
# 的那条命令），所以这里保持一致即可。
while [ $# -gt 0 ]; do
  case "$1" in
    -k|-w|--kill-after|--signal) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
# 跳过持续时间（纯数字）
if [ $# -gt 0 ]; then
  case "$1" in
    ''|*[!0-9]*) : ;;
    *) shift ;;
  esac
fi
exec "$@"
EOF
chmod 755 "$BIN"/*

export PATH="$BIN:/usr/bin:/bin"
export NET_GUARD_CONF="$ROOT/conf"
export STATE_DIR="$ROOT/state"
export LOG_DIR="$ROOT/logs"

P=0; F=0
chk() { if [ "$1" = "1" ]; then echo "PASS  $2"; P=$((P+1)); else echo "FAIL  $2"; F=$((F+1)); fi; }
st() { cat "$ROOT/state/current" 2>/dev/null || echo "(none)"; }
# 某条父链上是否还挂着某个目标
has_ref() { awk -F'|' -v c="$1" -v t="-j $2" '$1==c && $2==t {f=1} END{exit(f?0:1)}' "$RULES" 2>/dev/null; }
ref_count() { awk -F'|' -v c="$1" -v t="-j $2" '$1==c && $2==t {n++} END{print n+0}' "$RULES" 2>/dev/null; }

S="$REPO/app/server/net-guard.sh"
conf() { printf '%s\n' "$@" > "$ROOT/conf"; }

echo "--- guard 模式 ---"
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: off rc=0"
chk "$([ "$(st)" = "off" ] && echo 1 || echo 0)" "guard: state=off"
has_ref INPUT NET_GUARD_IN; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: INPUT 挂上了入站链"
has_ref DOCKER-USER NET_GUARD_IN; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: DOCKER-USER 也挂上了"
timeout -k 5 60 bash "$S" status >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: status rc=0"
timeout -k 5 60 bash "$S" reload >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: reload rc=0"
chk "$([ "$(st)" = "off" ] && echo 1 || echo 0)" "guard: reload 保持封锁状态"
chk "$([ "$(ref_count INPUT NET_GUARD_IN)" = "1" ] && echo 1 || echo 0)" "guard: reload 不产生重复挂载"
# 再补一条 DROP：验证统计口径是“所有 DROP 之和”，而不是只看第一条（旧实现只会得到 7）
printf 'NET_GUARD_IN|-j DROP\n' >> "$RULES"
NDROP="$(awk -F'|' -v c=NET_GUARD_IN '$1==c && $2=="-j DROP" {n++} END{print n+0}' "$RULES")"
EXPECT=$((NDROP * 7))
rm -f "$STATE_DIR/last-counts"
export STUB_PKTS=7          # 每条规则的 pkts：期望 = DROP 行数 × 7
timeout -k 5 60 bash "$S" on >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: on rc=0"
unset STUB_PKTS
chk "$([ "$(st)" = "on" ] && echo 1 || echo 0)" "guard: state=on"
# 链和计数器随解锁一起消失，所以脚本必须在拆规则之前落盘
LC1="$(awk '{print $1}' "$STATE_DIR/last-counts" 2>/dev/null)"
LC2="$(awk '{print $2}' "$STATE_DIR/last-counts" 2>/dev/null)"
chk "$([ "${NDROP:-0}" -ge 2 ] && echo 1 || echo 0)" \
    "guard: 拆链前链里有 ${NDROP} 条 DROP（保证下面的求和断言有区分度）"
chk "$([ "$LC1" = "$EXPECT" ] && echo 1 || echo 0)" \
    "guard: 解锁前把计数落盘且是所有 DROP 之和（${NDROP} × 7 = ${EXPECT}，实得 ${LC1:-无}）"
chk "$([ -n "$LC2" ] && echo 1 || echo 0)" \
    "guard: last-counts 第二列是 IPv6 计数（实得 ${LC2:-无}）"
chk "$( [ -n "$(awk '{print $3}' "$STATE_DIR/last-counts" 2>/dev/null)" ] && echo 1 || echo 0)" \
    "guard: last-counts 带时间戳（供后端判断陈旧）"
if has_ref INPUT NET_GUARD_IN; then chk 0 "guard: 解除后 INPUT 无残留"; else chk 1 "guard: 解除后 INPUT 无残留"; fi
timeout -k 5 60 bash "$S" reconcile >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "guard: reconcile rc=0"

echo "--- 模式切换残留（致命缺陷回归）---"
: > "$RULES"
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
conf 'MODE=soft' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
timeout -k 5 60 bash "$S" on >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "切换 guard->soft: on rc=0"
if has_ref INPUT NET_GUARD_IN; then chk 0 "切换 guard->soft: 入站链已清理（否则恢复后外网仍进不来）"; else chk 1 "切换 guard->soft: 入站链已清理"; fi
if has_ref FORWARD NET_GUARD_IN; then chk 0 "切换 guard->soft: FORWARD 无残留"; else chk 1 "切换 guard->soft: FORWARD 无残留"; fi
if has_ref DOCKER-USER NET_GUARD_IN; then chk 0 "切换 guard->soft: DOCKER-USER 无残留"; else chk 1 "切换 guard->soft: DOCKER-USER 无残留"; fi

: > "$RULES"
conf 'MODE=soft' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00'
timeout -k 5 60 bash "$S" on >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "切换 soft->guard: on rc=0"
if has_ref OUTPUT NET_GUARD; then chk 0 "切换 soft->guard: 出站链已清理"; else chk 1 "切换 soft->guard: 出站链已清理"; fi

echo "--- soft 模式 ---"
rm -f "$ROOT/gone"
: > "$RULES"
conf 'MODE=soft' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "soft: off rc=0"
has_ref OUTPUT NET_GUARD; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "soft: OUTPUT 挂上出站链"
chk "$([ "$(st)" = "off" ] && echo 1 || echo 0)" "soft: state=off"
timeout -k 5 60 bash "$S" on >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "soft: on rc=0"
chk "$([ "$(st)" = "on" ] && echo 1 || echo 0)" "soft: state=on"
if has_ref OUTPUT NET_GUARD; then chk 0 "soft: 解除后无出站链残留"; else chk 1 "soft: 解除后无出站链残留"; fi

echo "--- verify 守卫自检 ---"
rm -f "$ROOT/gone"
: > "$RULES"
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify guard: 规则完好时 rc=0"
# 模拟外部清掉 INPUT 上的入站链挂载
awk -F'|' '$1!="INPUT"' "$RULES" > "$RULES.tmp" && mv "$RULES.tmp" "$RULES"
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 3 ] && echo 1 || echo 0)" "verify guard: 规则缺失时 rc=3（做过纠正）"
has_ref INPUT NET_GUARD_IN; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify guard: 入站链已重新挂载"
chk "$([ "$(st)" = "off" ] && echo 1 || echo 0)" "verify guard: 不改变封锁状态"
timeout -k 5 60 bash "$S" on >/dev/null 2>&1
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify guard: 放行态直接跳过 rc=0"

conf 'MODE=soft' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
rm -f "$ROOT/gone"
: > "$RULES"
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify soft: 无异常时 rc=0"
# 模拟有人手动把默认路由加了回来（路由 stub 靠 gone 标记判断路由是否存在）
rm -f "$ROOT/gone"
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 3 ] && echo 1 || echo 0)" "verify soft: 默认路由被加回时 rc=3"
chk "$([ -f "$ROOT/gone" ] && echo 1 || echo 0)" "verify soft: 被加回的默认路由已重新删除"
# 模拟出站封锁规则被外部清掉
awk -F'|' '$1!="OUTPUT"' "$RULES" > "$RULES.tmp" && mv "$RULES.tmp" "$RULES"
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 3 ] && echo 1 || echo 0)" "verify soft: 出站规则缺失时 rc=3"
has_ref OUTPUT NET_GUARD; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify soft: 出站链已重新挂载"

conf 'MODE=strict' 'OFF_TIME=00:05' 'ON_TIME=06:00'
: > "$RULES"; rm -f "$ROOT/gone"
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
# strict 下网卡应处于 DOWN：让 link 查询返回 DOWN（stub 用 gone 标记模拟）
FAKE_ROUTE_GONE=1 timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "verify strict: 网卡仍关闭时 rc=0"
rm -f "$ROOT/gone"
timeout -k 5 60 bash "$S" verify >/dev/null 2>&1
chk "$([ $? -eq 3 ] && echo 1 || echo 0)" "verify strict: 网卡被拉起时 rc=3"

echo "--- purge 彻底复原 ---"
rm -f "$ROOT/gone"
# 人为制造脏状态：INPUT 上重复挂载两条 + FORWARD + OUTPUT 各一条
cat > "$RULES" <<'EOF'
INPUT|-j NET_GUARD_IN
INPUT|-j NET_GUARD_IN
FORWARD|-j NET_GUARD_IN
DOCKER-USER|-j NET_GUARD_IN
OUTPUT|-j NET_GUARD
EOF
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00'
timeout -k 5 60 bash "$S" purge >/dev/null 2>&1; chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "purge: rc=0"
left="$(grep -c NET_GUARD "$RULES" 2>/dev/null || true)"
chk "$([ "${left:-0}" = "0" ] && echo 1 || echo 0)" "purge: 全部规则清零 (剩 ${left:-0})"
chk "$([ "$(st)" = "on" ] && echo 1 || echo 0)" "purge: 状态复位为 on"

echo "--- 其它 ---"
rm -f "$ROOT/gone"
: > "$RULES"; rm -f "$ROOT/gone"
conf 'MODE=soft' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'PING_TARGETS=223.5.5.5'
FAKE_APT=1 timeout -k 5 60 bash "$S" off > "$ROOT/busy.out" 2>&1
rc=$?
chk "$([ $rc -eq 2 ] && echo 1 || echo 0)" "busy: rc=2"
grep -q SKIPPED_BUSY "$ROOT/busy.out"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "busy: SKIPPED_BUSY printed"
chk "$([ "$(st)" = "on" ] && echo 1 || echo 0)" "busy: state untouched (no fake block)"

: > "$RULES"; : > "$STUB_LOG"
conf 'MODE=guard' 'OFF_TIME=00:05' 'ON_TIME=06:00' 'RESTORE_SERVICES=fn-connect' 'RESTORE_DELAY=1'
timeout -k 5 60 bash "$S" off >/dev/null 2>&1
timeout -k 5 60 bash "$S" on  >/dev/null 2>&1
# v1.0.16：restore_services 异步化——远程访问的用户正踩着 FN Connect 中继，
# 同步重启会把当前 HTTP 响应一起掐断。解除后必须先走完响应，延迟后再重启。
grep -q 'systemctl restart fn-connect' "$STUB_LOG"
chk "$([ $? -ne 0 ] && echo 1 || echo 0)" "restore 异步：解除后未立即重启（先让响应走完）"
sleep 2
grep -q 'systemctl restart fn-connect' "$STUB_LOG"
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "restore 异步：延迟后仍完成重启（后台不丢）"

TODAY=$(date '+%Y-%m-%d')
LOG_DIR="$ROOT/logs" timeout -k 5 60 bash "$S" status >/dev/null 2>&1
chk "$([ -f "$ROOT/logs/net-guard-$TODAY.log" ] && echo 1 || echo 0)" "log split by day"

echo "=========== $P PASS / $F FAIL ==========="
