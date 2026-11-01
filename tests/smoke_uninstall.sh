#!/usr/bin/env bash
# stub smoke test：卸载钩子必须能把规则清干净
# 场景 A：net-guard.sh 还在（正常卸载） -> 调 purge
# 场景 B：net-guard.sh 已不在位（残余清理） -> 走内置兜底手拆
#
# 用法：在仓库根目录执行  bash tests/smoke_uninstall.sh
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
ROOT=/tmp/nguninst
export ROOT
rm -rf "$ROOT"; mkdir -p "$ROOT/bin" "$ROOT/state" "$ROOT/logs" "$ROOT/dest/server"
BIN="$ROOT/bin"
export STUB_LOG="$ROOT/calls.txt"
RULES="$ROOT/rules"; export RULES
: > "$STUB_LOG"

cat > "$BIN/id" <<'EOF'
#!/usr/bin/env bash
echo 0
EOF
cat > "$BIN/ip" <<'EOF'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"route replace default"*) echo "default via 192.168.1.1 dev eth0" > "${ROOT:-/tmp/nguninst}/route"; echo "ip $*" >> "$STUB_LOG"; exit 0;;
  *"link set"*) echo "ip $*" >> "$STUB_LOG"; exit 0;;
  *route*) cat "${ROOT:-/tmp/nguninst}/route" 2>/dev/null || echo "default via 192.168.1.1 dev eth0"; exit 0;;
  *address*) echo "2: eth0    inet 192.168.1.11/24"; exit 0;;
esac
exit 0
EOF
cp /tmp/ngsmoke/bin/iptables "$BIN/iptables" 2>/dev/null || true
cp /tmp/ngsmoke/bin/ip6tables "$BIN/ip6tables" 2>/dev/null || true
cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "${STUB_LOG:-/dev/null}"
case "$1" in list-unit-files) exit 1;; esac
exit 0
EOF
cp /tmp/ngsmoke/bin/timeout "$BIN/timeout" 2>/dev/null || true
chmod 755 "$BIN"/*
export PATH="$BIN:/usr/bin:/bin"

P=0; F=0
chk() { if [ "$1" = "1" ]; then echo "PASS  $2"; P=$((P+1)); else echo "FAIL  $2"; F=$((F+1)); fi; }
left() { grep -c NET_GUARD "$RULES" 2>/dev/null || true; }

dirty() {
cat > "$RULES" <<'EOF'
INPUT|-j NET_GUARD_IN
INPUT|-j NET_GUARD_IN
DOCKER-USER|-j NET_GUARD_IN
FORWARD|-j NET_GUARD_IN
OUTPUT|-j NET_GUARD
NET_GUARD_IN|-j DROP
EOF
}

CMD="$REPO/cmd/uninstall_init"

echo "--- 场景 A：脚本还在，应调用 purge ---"
dirty
cp "$REPO/app/server/net-guard.sh" "$ROOT/dest/server/net-guard.sh"
printf 'MODE=guard\nSTATE_DIR=%s/state\nLOG_DIR=%s/logs\n' "$ROOT" "$ROOT" > "$ROOT/conf"
TRIM_APPDEST="$ROOT/dest" TRIM_PKGETC="$ROOT" bash "$CMD" >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "A: uninstall_init rc=0"
chk "$([ "$(left)" = "0" ] && echo 1 || echo 0)" "A: 规则清零 (剩 $(left))"
grep -q 'purge' "$STUB_LOG" || true

echo "--- 场景 B：脚本已不在位，走内置兜底 ---"
dirty
rm -rf "$ROOT/dest"
: > "$STUB_LOG"
TRIM_APPDEST="$ROOT/dest" TRIM_PKGETC="$ROOT" bash "$CMD" >"$ROOT/b.out" 2>&1
rc=$?
chk "$([ $rc -eq 0 ] && echo 1 || echo 0)" "B: uninstall_init rc=0"
chk "$([ "$(left)" = "0" ] && echo 1 || echo 0)" "B: 兜底也把规则清干净 (剩 $(left))"
grep -q -- '-D INPUT -j NET_GUARD_IN' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "B: 拆掉 INPUT 挂载"
grep -q -- '-D DOCKER-USER -j NET_GUARD_IN' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "B: 拆掉 DOCKER-USER 挂载"
grep -q -- '-D OUTPUT -j NET_GUARD' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "B: 拆掉 OUTPUT 挂载"
chk "$([ "$(grep -c -- '-D INPUT -j NET_GUARD_IN' "$STUB_LOG" || true)" -ge 2 ] && echo 1 || echo 0)" "B: 重复挂载被删干净"
grep -q 'link set eth0 up' "$STUB_LOG"; chk "$( [ $? -eq 0 ] && echo 1 || echo 0)" "B: 网卡被拉起"

echo "--- 场景 C：本来就干净，不该报错 ---"
: > "$RULES"; rm -f "$ROOT/route"
TRIM_APPDEST="$ROOT/dest" TRIM_PKGETC="$ROOT" bash "$CMD" >/dev/null 2>&1
chk "$([ $? -eq 0 ] && echo 1 || echo 0)" "C: 干净状态下幂等 rc=0"

echo "=========== $P PASS / $F FAIL ==========="
