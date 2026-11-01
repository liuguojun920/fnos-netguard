#!/usr/bin/env bash
# stub smoke test for netguard-rescue.sh
# 故障现场：INPUT 被重复挂了 2 条 NET_GUARD_IN、DOCKER-USER 1 条、OUTPUT 1 条 NET_GUARD，
#          且默认路由完全丢失 —— 这正是「局域网通、FN 中继不通」的典型状态。
#
# 用法：在仓库根目录执行  bash tests/smoke_rescue.sh
# 用的是 stub 模型，不触碰本机真实的 iptables / 路由。
set -u

# 环境要求：Linux（fnOS / Debian）。stub 之外的 ping / timeout / flock 在
# Windows 的 Git Bash 下语义不同，会导致用例挂住。检测到非 Linux 直接跳过。
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
ROOT=/tmp/ngrescue
export ROOT
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/state"
BIN="$ROOT/bin"
export STUB_LOG="$ROOT/calls.txt"
: > "$STUB_LOG"

IPT_RULES="$ROOT/rules"
cat > "$IPT_RULES" <<'EOF'
INPUT|-j NET_GUARD_IN
INPUT|-j NET_GUARD_IN
DOCKER-USER|-j NET_GUARD_IN
OUTPUT|-j NET_GUARD
FORWARD|-j NET_GUARD_IN
EOF

cat > "$BIN/id" <<'EOF'
#!/usr/bin/env bash
echo 0
EOF

cat > "$BIN/ip" <<'EOF'
#!/usr/bin/env bash
args="$*"
RF="${ROOT:-/tmp/ngrescue}/route"
case "$args" in
  *"route replace default"*) echo "default via 192.168.1.1 dev eth0" > "$RF"; echo "ip $*" >> "$STUB_LOG"; exit 0;;
  *"link set"*) echo "ip $*" >> "$STUB_LOG"; exit 0;;
  *route*) [ -f "$RF" ] && cat "$RF"; exit 0;;
  *addr*|*address*) echo "2: eth0    inet 192.168.1.11/24 brd 192.168.1.255 scope global eth0"; exit 0;;
  *link*) echo "2: eth0    <BROADCAST,MULTICAST,UP> state UP"; exit 0;;
esac
exit 0
EOF

cat > "$BIN/iptables" <<'EOF'
#!/usr/bin/env bash
# 极简 iptables 模型：每条规则 "<父链>|-j <目标>"
RULES="${ROOT:-/tmp/ngrescue}/rules"
echo "iptables $*" >> "$STUB_LOG"
shift 0
prev=""; args=""
for a in "$@"; do :; done
# 去掉 -w
new=(); for a in "$@"; do [ "$a" = "-w" ] || new+=("$a"); done
set -- "${new[@]}"
CMD="${1:-}"; C2="${2:-}"
case "$CMD" in
  -S)
     if [ -n "$C2" ]; then grep "^${C2}|" "$RULES" 2>/dev/null | while IFS='|' read -r c r; do echo "-A $c $r"; done
     else while IFS='|' read -r c r; do echo "-A $c $r"; done < "$RULES"; fi
     exit 0;;
  -D)
     # -D INPUT -j NET_GUARD_IN  -> 删第一条匹配
     tgt="${4:-}"
     n=0; tmp="$RULES.tmp"; : > "$tmp"
     while IFS='|' read -r c r; do
       if [ "$c" = "$C2" ] && [ "$r" = "-j $tgt" ] && [ "$n" -eq 0 ]; then n=1; continue; fi
       echo "$c|$r" >> "$tmp"
     done < "$RULES"
     mv "$tmp" "$RULES"
     [ "$n" -eq 1 ] && exit 0 || exit 1;;
  -F|-X)
     tmp="$RULES.tmp"; : > "$tmp"
     while IFS='|' read -r c r; do
       [ "$c" = "$C2" ] && continue
       echo "$c|$r" >> "$tmp"
     done < "$RULES"
     mv "$tmp" "$RULES"; exit 0;;
  -N) exit 0;;
esac
exit 0
EOF
sed "s/iptables /ip6tables /" "$BIN/iptables" > "$BIN/ip6tables"

cat > "$BIN/dhclient" <<'EOF'
#!/usr/bin/env bash
echo "dhclient $*" >> "$STUB_LOG"
echo "default via 192.168.1.1 dev eth0" > "${ROOT:-/tmp/ngrescue}/route"
exit 0
EOF
cat > "$BIN/timeout" <<'EOF'
#!/usr/bin/env bash
t="$1"; shift
"$@"
EOF
cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
case "$1" in
  list-unit-files) echo "fn-connect.service enabled"; echo "frpc.service enabled"; exit 0;;
  is-active) echo active; exit 0;;
esac
exit 0
EOF
cat > "$BIN/ping" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/nmcli" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod 755 "$BIN"/*

export PATH="$BIN:/usr/bin:/bin"

P=0; F=0
chk() { if [ "$1" = "1" ]; then echo "PASS  $2"; P=$((P+1)); else echo "FAIL  $2"; F=$((F+1)); fi; }

R="$REPO/netguard-rescue.sh"

# ---- 1) diag 只读，不许产生任何变更类调用
: > "$STUB_LOG"
OUT="$(bash "$R" diag 2>&1)"
rc=$?
chk "$([ $rc -eq 0 ] && echo 1 || echo 0)" "diag: rc=0"
expr "$(printf '%s' "$OUT")" : '.*没有默认路由' >/dev/null; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "diag: 报告默认路由缺失"
grep -q 'NET_GUARD' <<<"$OUT"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "diag: 列出 iptables 残留"
mutations="$(grep -c -E '^(-D|-F|-X)|route replace' "$STUB_LOG" 2>/dev/null || true)"
chk "$([ "${mutations:-0}" = "0" ] && echo 1 || echo 0)" "diag: 只读不改动 (mutations=${mutations:-0})"

# ---- 2) clean 应清掉全部 NET_GUARD 规则（含重复挂载）
: > "$STUB_LOG"
bash "$R" clean >"$ROOT/clean.out" 2>&1
rc=$?
chk "$([ $rc -eq 0 ] && echo 1 || echo 0)" "clean: rc=0"
left="$(bash "$BIN/iptables" -S 2>/dev/null | grep -c 'NET_GUARD' || true)"
chk "$([ "$left" = "0" ] && echo 1 || echo 0)" "clean: iptables 残留清零 (剩 $left)"
left6="$(bash "$BIN/ip6tables" -S 2>/dev/null | grep -c 'NET_GUARD' || true)"
chk "$([ "$left6" = "0" ] && echo 1 || echo 0)" "clean: ip6tables 残留清零 (剩 $left6)"
grep -q -- '-D INPUT -j NET_GUARD_IN' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 删除了 INPUT 挂载"
chk "$([ "$(grep -c -- '-D INPUT -j NET_GUARD_IN' "$STUB_LOG")" -ge 2 ] && echo 1 || echo 0)" "clean: 重复挂载也被删干净"
grep -q -- '-D DOCKER-USER -j NET_GUARD_IN' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 删除了 DOCKER-USER 挂载"
grep -q -- '-D FORWARD -j NET_GUARD_IN' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 删除了 FORWARD 挂载"
grep -q -- '-D OUTPUT -j NET_GUARD' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 删除了 OUTPUT 挂载"
grep -q 'link set eth0 up' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 网卡被拉起"
chk "$([ -f "$ROOT/route" ] && echo 1 || echo 0)" "clean: 默认路由已补回"
grep -q 'dhclient' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 走了 DHCP 续租兜底"

# ---- 3) fn 应完整 stop -> start 一次 FN Connect
: > "$STUB_LOG"
bash "$R" fn >"$ROOT/fn.out" 2>&1
rc=$?
chk "$([ $rc -eq 0 ] && echo 1 || echo 0)" "fn: rc=0"
grep -q 'systemctl stop fn-connect' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "fn: 先 stop"
grep -q 'systemctl start fn-connect' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "fn: 再 start"
order_ok="$(awk '/stop fn-connect/{a=1} /start fn-connect/{if(a==1){print 1; exit}}' "$STUB_LOG" || true)"
chk "$([ "$order_ok" = "1" ] && echo 1 || echo 0)" "fn: 顺序 stop->start"

# ---- 4) 幂等：再跑一次不应报错
rm -f "$ROOT/route"
bash "$R" clean >/dev/null 2>&1; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "idempotent: 重复 clean rc=0"
bash "$R" verify >/dev/null 2>&1; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "verify: rc=0"

# ---- 5) 无残留时 clean 也要安全通过（已是干净状态）
: > "$IPT_RULES"
bash "$R" clean >/dev/null 2>&1; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "clean: 干净状态下幂等"

# ---- 6) 非 root 应拒绝
PATH_NOID="$BIN"
mv "$BIN/id" "$BIN/id.bak"
cat > "$BIN/id" <<'EOF'
#!/usr/bin/env bash
echo 1000
EOF
chmod 755 "$BIN/id"
bash "$R" clean >/dev/null 2>&1
rc=$?
chk "$([ $rc -ne 0 ] && echo 1 || echo 0)" "perm: 非 root 被拒绝"
mv "$BIN/id.bak" "$BIN/id"

echo "=========== $P PASS / $F FAIL ==========="
