#!/usr/bin/env bash
# =============================================================================
#  fnOS / Debian 定时断网守护脚本  net-guard（fpk 内嵌版）
#  功能：每天深夜切断 NAS 的外网出口，清晨自动恢复，局域网访问全程不受影响。
#
#  子命令：
#    net-guard.sh off                 断开外网（soft 模式：删默认路由 + 防火墙拒绝出网）
#    net-guard.sh on                  恢复外网
#    net-guard.sh purge               彻底复原：清空全部规则 + 恢复路由（卸载前必做）
#    net-guard.sh reconcile           按当前时间判断应有的状态，并纠正（开机自愈用）
#    net-guard.sh verify              封锁态守卫自检：路由/规则/网卡被外部改动时立即纠正
#    net-guard.sh reload              按最新配置原地重建规则（不改变当前封锁/放行状态）
#    net-guard.sh status              查看当前状态
#    net-guard.sh detect              探测本机网络管理方式与网卡信息
#
#  配置文件：/var/apps/app.netguard/etc/net-guard.conf
#  日志：    /var/log/net-guard.log   同时写入 syslog（tag: net-guard）
# =============================================================================

set -Eeuo pipefail

CONF_FILE="${NET_GUARD_CONF:-/var/apps/app.netguard/etc/net-guard.conf}"
# shellcheck source=/dev/null
[ -r "$CONF_FILE" ] && . "$CONF_FILE"

# ------------------------------ 默认配置（可被 conf 覆盖） -------------------
MODE="${MODE:-guard}"           # guard = 封入站保出站；soft = 断外网；strict = down 网口
OFF_TIME="${OFF_TIME:-00:05}"        # 断网时刻 HH:MM
ON_TIME="${ON_TIME:-06:00}"          # 恢复时刻 HH:MM
IFACE="${IFACE:-auto}"               # 网卡名，auto = 自动取承载默认路由的那张
STATE_DIR="${STATE_DIR:-/var/lib/net-guard}"
LOG_DIR="${LOG_DIR:-}"           # 由上层（面板服务端）注入，未注入时退回单文件日志
LOG_FILE="${LOG_FILE:-/var/log/net-guard.log}"
if [ -n "$LOG_DIR" ]; then LOG_FILE="$LOG_DIR/net-guard-$(date '+%Y-%m-%d').log"; fi
LOCK_FILE="${LOCK_FILE:-/run/net-guard.lock}"
FLOCK_WAIT="${FLOCK_WAIT:-20}"       # 抢并发锁最多等几秒；stop/卸载钩子会调小以免拖垮应用中心
CHAIN="${CHAIN:-NET_GUARD}"          # soft 模式用的出站链名
CHAIN_IN="${CHAIN_IN:-NET_GUARD_IN}" # guard 模式用的入站链名
PING_TARGETS="${PING_TARGETS:-223.5.5.5 119.29.29.29}"   # 连通性自检目标
GUARD_DOCKER="${GUARD_DOCKER:-yes}"  # guard 模式是否同时封 Docker 映射端口（挂 DOCKER-USER 链）
GUARD_FORWARD="${GUARD_FORWARD:-no}" # 是否连桥接虚拟机等 FORWARD 流量一起封（一般不需要）
DROP_LOG="${DROP_LOG:-no}"           # 是否记录被拦截的包（限流每分钟 3 条，写入系统日志）
PROTECT_APT="${PROTECT_APT:-yes}"    # soft/strict 模式下，检测到 apt/dpkg 正在工作时跳过本次操作
# 网络恢复后自动重启的服务（空格分隔，由面板注入 FN Connect 等服务名）。
# 目的：拉回路由后让长连接类的中继服务重新握手，避免"路由回来了但中继还连不上"。
RESTORE_SERVICES="${RESTORE_SERVICES:-}"
LAN_V4="${LAN_V4:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 255.255.255.255/32}"
LAN_V6="${LAN_V6:-fe80::/10 fd00::/8 ff00::/8}"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$(dirname "$LOCK_FILE")" 2>/dev/null || true

# --------------------------------- 基础工具 ---------------------------------
log() {
    local line
    line="$(date '+%Y-%m-%d %H:%M:%S') [$1] $2"
    echo "$line" >>"$LOG_FILE" 2>/dev/null || true
    command -v logger >/dev/null 2>&1 && logger -t net-guard "$1: $2" 2>/dev/null || true
    if [ -t 1 ]; then echo "$line"; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log ERROR "必须以 root 执行（试试 sudo $0 $*）"
        exit 1
    fi
}

# 并发互斥，避免定时器和手工执行打架
with_lock() {
    if have flock; then
        exec 9>"$LOCK_FILE"
        flock -w "$FLOCK_WAIT" 9 || { log ERROR "另一个 net-guard 实例正在运行，本次跳过"; exit 0; }
    fi
}

# --------------------------------- 环境探测 ---------------------------------
NM_AVAILABLE=0
IFUPDOWN_AVAILABLE=0
DHCP_CLIENT=""

detect_env() {
    if have nmcli; then
        if nmcli -t -f RUNNING general 2>/dev/null | grep -q '^running$'; then NM_AVAILABLE=1; fi
    fi
    if [ -x /sbin/ifdown ] || [ -x /usr/sbin/ifdown ] || have ifdown; then
        IFUPDOWN_AVAILABLE=1
    fi
    for c in dhclient udhcpc dhcpcd; do
        if have "$c"; then DHCP_CLIENT="$c"; break; fi
    done
    return 0
}

primary_iface() {
    if [ "$IFACE" != "auto" ]; then
        echo "$IFACE"
        return 0
    fi
    ip -o route show default 2>/dev/null | awk '{print $5; exit}'
}

default_gateway() {
    ip -o route show default 2>/dev/null | awk '{print $3; exit}'
}

# activities that must not be interrupted: 系统更新 / 包管理
busy_with_updates() {
    if [ "$PROTECT_APT" != "yes" ]; then return 1; fi
    for p in apt apt-get dpkg unattended-upgrade apt.systemd.daily; do
        if pgrep -x "$p" >/dev/null 2>&1; then return 0; fi
    done
    # 持有 dpkg 锁也算在忙
    if have fuser; then
        for l in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
            if [ -e "$l" ] && fuser "$l" >/dev/null 2>&1; then return 0; fi
        done
    fi
    return 1
}

# --------------------------------- 状态文件 ---------------------------------
state_file() { echo "$STATE_DIR/current"; }

read_state() {
    local f; f="$(state_file)"
    [ -r "$f" ] && cat "$f" || echo "unknown"
}

write_state() {
    echo "$1" >"$(state_file)"
    date '+%s' >"$STATE_DIR/last-$1" 2>/dev/null || true
}

# 保存默认路由，恢复时按原样加回去
save_routes() {
    ip -4 route show default >"$STATE_DIR/routes-v4.saved" 2>/dev/null || true
    ip -6 route show default >"$STATE_DIR/routes-v6.saved" 2>/dev/null || true
    primary_iface >"$STATE_DIR/iface.saved" 2>/dev/null || true
    default_gateway >"$STATE_DIR/gateway.saved" 2>/dev/null || true
}

restore_routes() {
    local ok=0 line gw ifc
    ifc="$(cat "$STATE_DIR/iface.saved" 2>/dev/null || true)"
    if [ -z "$ifc" ]; then ifc="$(primary_iface)"; fi

    # 1) 优先按保存的路由表原样恢复
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if ip -4 route replace $line >/dev/null 2>&1; then ok=1; fi
    done <"$STATE_DIR/routes-v4.saved" 2>/dev/null || true

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        ip -6 route replace $line >/dev/null 2>&1 || true
    done <"$STATE_DIR/routes-v6.saved" 2>/dev/null || true

    # 2) 仍无默认路由 -> 重新向 DHCP 要地址
    if [ "$ok" -ne 1 ]; then
        gw="$(cat "$STATE_DIR/gateway.saved" 2>/dev/null || true)"
        if [ -n "$gw" ] && [ -n "$ifc" ]; then
            if ip -4 route replace default via "$gw" dev "$ifc" >/dev/null 2>&1; then ok=1; fi
        fi
    fi
    if [ "$ok" -ne 1 ]; then renew_dhcp "$ifc"; fi
    return 0
}

renew_dhcp() {
    local ifc="$1"
    log INFO "尝试重新获取 DHCP 租约 ($ifc)"
    case "$DHCP_CLIENT" in
        dhclient)
            timeout 25 dhclient -r "$ifc" >/dev/null 2>&1 || true
            timeout 40 dhclient -1 -timeout 20 "$ifc" >/dev/null 2>&1 || true
            ;;
        udhcpc)
            timeout 30 udhcpc -i "$ifc" -q -n >/dev/null 2>&1 || true
            ;;
        dhcpcd)
            timeout 30 dhcpcd -n "$ifc" >/dev/null 2>&1 || true
            ;;
    esac
    if [ "$NM_AVAILABLE" = "1" ]; then
        timeout 30 nmcli device reapply "$ifc" >/dev/null 2>&1 || \
        timeout 30 nmcli con up "$(nmcli -t -f DEVICE,NAME d 2>/dev/null | awk -F: -v d="$ifc" '$1==d{print $2; exit}')" >/dev/null 2>&1 || true
    fi
    if [ "$IFUPDOWN_AVAILABLE" = "1" ] && [ -n "$ifc" ]; then
        ip -4 route show default | grep -q ' default ' || {
            timeout 30 ifdown --force "$ifc" >/dev/null 2>&1 || true
            timeout 40 ifup "$ifc" >/dev/null 2>&1 || true
        }
    fi
}

# --------------------------------- 防火墙规则 ---------------------------------
fw_block_outside() {
    # 拒绝一切非局域网的出站流量；局域网地址段直接 RETURN 放行
    if have iptables; then
        iptables -w -N "$CHAIN" 2>/dev/null || iptables -w -F "$CHAIN"
        iptables -w -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -w -I OUTPUT -j "$CHAIN"
        iptables -w -A "$CHAIN" -o lo -j RETURN
        local n
        for n in $LAN_V4; do iptables -w -A "$CHAIN" -d "$n" -j RETURN; done
        iptables -w -A "$CHAIN" -j REJECT --reject-with icmp-host-prohibited
    fi
    if have ip6tables && ip -6 route show default 2>/dev/null | grep -q default; then
        ip6tables -w -N "$CHAIN" 2>/dev/null || ip6tables -w -F "$CHAIN"
        ip6tables -w -C OUTPUT -j "$CHAIN" 2>/dev/null || ip6tables -w -I OUTPUT -j "$CHAIN"
        ip6tables -w -A "$CHAIN" -o lo -j RETURN
        local m
        for m in $LAN_V6; do ip6tables -w -A "$CHAIN" -d "$m" -j RETURN; done
        ip6tables -w -A "$CHAIN" -j REJECT --reject-with icmp6-adm-prohibited
    fi
}

fw_unblock_outside() {
    if have iptables; then
        iptables  -w -D OUTPUT -j "$CHAIN" 2>/dev/null || true
        iptables  -w -F "$CHAIN" 2>/dev/null || true
        iptables  -w -X "$CHAIN" 2>/dev/null || true
    fi
    if have ip6tables; then
        ip6tables -w -D OUTPUT -j "$CHAIN" 2>/dev/null || true
        ip6tables -w -F "$CHAIN" 2>/dev/null || true
        ip6tables -w -X "$CHAIN" 2>/dev/null || true
    fi
    return 0
}

# --------------------- 入站封锁（guard 模式：只挡外部进来） ------------------
# 规则必须挂在 INPUT 链最前面，否则 fnOS/Docker 自带的 ACCEPT 规则会先放行。
fw_block_inbound() {
    local g="$CHAIN_IN"

    if have iptables; then
        iptables -w -N "$g" 2>/dev/null || iptables -w -F "$g"

        # 1) 本机内部通信
        iptables -w -A "$g" -i lo -j RETURN
        # 2) 自己主动发起的连接及其回包 —— 这是"只封入站保出站"的关键
        iptables -w -A "$g" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        # 3) 局域网设备
        local n
        for n in $LAN_V4; do iptables -w -A "$g" -s "$n" -j RETURN; done
        # 4) DHCP 续租（广播包不受 conntrack 保护，必须显式放行）
        iptables -w -A "$g" -p udp --sport 67 --dport 68 -j RETURN

        if [ "$DROP_LOG" = "yes" ]; then
            iptables -w -A "$g" -m limit --limit 3/min -j LOG --log-prefix "net-guard-drop: " --log-level 4
        fi
        # 5) 其余一切来自互联网的新连接：丢弃，且不回任何响应
        iptables -w -A "$g" -j DROP

        iptables -w -C INPUT -j "$g" 2>/dev/null || iptables -w -I INPUT 1 -j "$g"

        # Docker 端口映射走 FORWARD 链，必须单独封
        if [ "$GUARD_DOCKER" = "yes" ] && iptables -w -L DOCKER-USER -n >/dev/null 2>&1; then
            iptables -w -C DOCKER-USER -j "$g" 2>/dev/null || iptables -w -I DOCKER-USER 1 -j "$g"
        fi
        if [ "$GUARD_FORWARD" = "yes" ]; then
            iptables -w -C FORWARD -j "$g" 2>/dev/null || iptables -w -I FORWARD 1 -j "$g"
        fi
    fi

    if have ip6tables; then
        ip6tables -w -N "$g" 2>/dev/null || ip6tables -w -F "$g"
        ip6tables -w -A "$g" -i lo -j RETURN
        ip6tables -w -A "$g" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
        # IPv6 邻居发现（NDP）用的是 fe80::/10 链路本地地址，已被上面的 LAN_V6 放行，
        # 因此这里不额外无条件放行 ICMPv6 —— 来自公网的 IPv6 探活包一并被丢弃
        local m
        for m in $LAN_V6; do ip6tables -w -A "$g" -s "$m" -j RETURN; done
        ip6tables -w -A "$g" -p udp --sport 547 --dport 546 -j RETURN
        ip6tables -w -A "$g" -j DROP

        ip6tables -w -C INPUT -j "$g" 2>/dev/null || ip6tables -w -I INPUT 1 -j "$g"
        if [ "$GUARD_DOCKER" = "yes" ] && ip6tables -w -L DOCKER-USER -n >/dev/null 2>&1; then
            ip6tables -w -C DOCKER-USER -j "$g" 2>/dev/null || ip6tables -w -I DOCKER-USER 1 -j "$g"
        fi
        if [ "$GUARD_FORWARD" = "yes" ]; then
            ip6tables -w -C FORWARD -j "$g" 2>/dev/null || ip6tables -w -I FORWARD 1 -j "$g"
        fi
    fi

    log INFO "入站封锁已生效：拒绝互联网侧的新连接，局域网与自己发起的连接不受影响"
}

fw_unblock_inbound() {
    local g="$CHAIN_IN"
    if have iptables; then
        iptables  -w -D INPUT -j "$g" 2>/dev/null || true
        iptables  -w -D DOCKER-USER -j "$g" 2>/dev/null || true
        iptables  -w -D FORWARD -j "$g" 2>/dev/null || true
        iptables  -w -F "$g" 2>/dev/null || true
        iptables  -w -X "$g" 2>/dev/null || true
    fi
    if have ip6tables; then
        ip6tables -w -D INPUT -j "$g" 2>/dev/null || true
        ip6tables -w -D DOCKER-USER -j "$g" 2>/dev/null || true
        ip6tables -w -D FORWARD -j "$g" 2>/dev/null || true
        ip6tables -w -F "$g" 2>/dev/null || true
        ip6tables -w -X "$g" 2>/dev/null || true
    fi
    log INFO "入站封锁已解除"
}

# --------------------------------- 全量残留清理 --------------------------------
# 为什么必须要有这一步（血泪教训）：
#   场景：用户在防护模式之间来回切换（guard <-> soft/strict），或多次重复执行封锁。
#   后果：旧模式留下的 iptables 规则不会被新模式的那套清理函数删掉 ——
#         例如从 guard 切到 soft 后执行恢复，soft 分支只会拆 OUTPUT 上的出站链，
#         INPUT/FORWARD/DOCKER-USER 上的入站链 NET_GUARD_IN 会永久留在那里继续丢包。
#         表现就是「局域网正常、FN Connect 中继转发不通」，而且卸载本程序也不会清理，
#         因为 netfilter 规则活在内核里，删文件对它没有任何影响。
#   对策：任何状态切换前先做一次全量清理，并提供 purge 子命令给排障和卸载前使用。
fw_purge() {
    local tool all pairs pair p target n
    for tool in iptables ip6tables; do
        have "$tool" || continue
        # 一次全表扫描找出所有挂在这两条自定义链上的引用，避免逐链反复 fork iptables
        all="$($tool -w -S 2>/dev/null)" || continue
        pairs="$(printf '%s\n' "$all" | awk -v c1="$CHAIN" -v c2="$CHAIN_IN" '
            ($1 == "-A" || $1 == "-I") {
                for (i = 1; i <= NF; i++)
                    if ($i == "-j" && (i + 1) <= NF && ($(i+1) == c1 || $(i+1) == c2))
                        print $2, $(i+1)
            }' | sort -u)"
        [ -z "$pairs" ] && continue
        printf '%s\n' "$pairs" | while read -r p target; do
            if [ -z "$p" ] || [ -z "$target" ]; then continue; fi
            n=0
            # 同一条链上可能被重复挂载，一次 -D 只删一条，循环到干净为止
            while $tool -w -S "$p" 2>/dev/null | grep -qE -- "-j $target\$"; do
                $tool -w -D "$p" -j "$target" 2>/dev/null || break
                n=$((n + 1))
                if [ "$n" -ge 10 ]; then break; fi
            done
        done
        for target in "$CHAIN" "$CHAIN_IN"; do
            $tool -w -F "$target" 2>/dev/null || true
            $tool -w -X "$target" 2>/dev/null || true
        done
    done
    return 0
}

# 网络恢复后重启依赖长连接的服务（FN Connect 等）。
# 必须异步 + 延迟：解除封锁 / 彻底复原往往就是用户正踩着 FN Connect 的
# 中继在远程访问面板的时候，同步重启会把当前 HTTP 响应（以及用户手里
# 的连接）一起掐断——表现是「点了解除封锁反而报错、连接被重置、
# 页面拿到网关错误页」。先让响应走完，几秒后再重启。
RESTORE_DELAY="${RESTORE_DELAY:-5}"
restore_services() {
    [ -z "$RESTORE_SERVICES" ] && return 0
    (
        sleep "$RESTORE_DELAY"
        for n in $RESTORE_SERVICES; do
            systemctl restart "$n" >/dev/null 2>&1 || true
            log INFO "已异步重启长连接服务：$n"
        done
    ) >/dev/null 2>&1 &
    return 0
}

# guard 模式下统计被拦截的包数（iptables -L -n -v 的 pkts 列）。
# 累加所有 DROP 行的计数，而不是只看第一条 —— 与面板 / 通知的口径保持一致；
# 将来若在链里加"拒绝某几个端口"这类规则，也不会只算到其中一条。
guard_count() {
    local v4 v6
    v4="$(iptables  -w -L "$CHAIN_IN" -n -v 2>/dev/null | awk '$0 ~ /DROP/ {s += $1} END {print s + 0}')"
    v6="$(ip6tables -w -L "$CHAIN_IN" -n -v 2>/dev/null | awk '$0 ~ /DROP/ {s += $1} END {print s + 0}')"
    echo "${v4:-0} ${v6:-0}"
}

guard_stats() {
    local c4 c6
    set -- $(guard_count)
    c4="${1:-0}"; c6="${2:-0}"
    echo "IPv4 $c4 个 / IPv6 $c6 个"
}

# --------------------------------- 核心动作 ---------------------------------
do_off() {
    local arg="${1:-}"
    if [ "$(read_state)" = "off" ] && [ "$arg" != "force" ]; then
        log INFO "已经是封锁状态，无需重复执行"
        return 0
    fi

    # guard 模式不删路由、不动网卡，只加防火墙规则，可随时安全撤销。
    # 先清掉另一种模式可能留下的出站链，避免两套规则叠加后恢复不干净。
    if [ "$MODE" = "guard" ]; then
        log INFO "启动入站封锁：mode=guard（保留局域网与本机主动出网）"
        fw_purge
        fw_block_inbound
        write_state off
        log INFO "外网已无法主动连入；NAS 自身上网能力保持不变"
        return 0
    fi

    if busy_with_updates; then
        log WARN "检测到 apt/dpkg 正在工作，本次跳过断网（避免更新卡死）"
        # 退出码 2 = 主动放弃，调用方据此判为“未生效”，不要误报成功
        echo "SKIPPED_BUSY"
        return 2
    fi

    local ifc; ifc="$(primary_iface)"
    if [ -z "$ifc" ]; then
        log WARN "未发现承载默认路由的网卡，可能已断网，跳过"
        return 0
    fi

    save_routes
    log INFO "开始断网：mode=$MODE iface=$ifc"
    fw_purge   # 清掉 guard 模式可能残留的入站链

    if [ "$MODE" = "strict" ]; then
        ip link set "$ifc" down
        log INFO "网卡 $ifc 已 down（strict 模式：局域网也不可达）"
    else
        # 先加墙再删路由，避免出现短暂可出网的窗口
        fw_block_outside
        while ip -4 route show default | grep -q 'default'; do
            ip -4 route del default 2>/dev/null || break
        done
        while ip -6 route show default | grep -q 'default'; do
            ip -6 route del default 2>/dev/null || break
        done
        log INFO "外网已断开（soft 模式：局域网仍可访问）"
    fi

    write_state off
}

do_on() {
    local arg="${1:-}"
    if [ "$(read_state)" = "on" ] && [ "$arg" != "force" ]; then
        log INFO "已经处于联网状态，无需重复执行"
        return 0
    fi

    if [ "$MODE" = "guard" ]; then
        local blocked c4 c6
        blocked="$(guard_stats)"     # 统计必须在拆规则之前读，否则计数器随链一起消失
        set -- $(guard_count)
        c4="${1:-0}"; c6="${2:-0}"
        # 落盘一份：拆完规则链和计数器一起消失，之后面板 / 通知再也读不到“这次拦了多少”。
        # 格式：<IPv4 包数> <IPv6 包数> <unix 时间戳>，由 server.py 在实时值缺失时回退读取。
        if mkdir -p "$STATE_DIR" 2>/dev/null; then
            printf '%s %s %s\n' "$c4" "$c6" "$(date +%s)" \
                > "$STATE_DIR/last-counts" 2>/dev/null || true
        fi
        log INFO "解除入站封锁；本轮累计拦截来自互联网的入站包：$blocked"
        fw_purge
        write_state on
        restore_services
        return 0
    fi

    fw_purge   # 无论当前是什么模式，先把所有可能的历史残留清干净

    local ifc; ifc="$(primary_iface)"
    if [ -z "$ifc" ]; then ifc="$(cat "$STATE_DIR/iface.saved" 2>/dev/null || true)"; fi

    log INFO "开始恢复网络：mode=$MODE iface=${ifc:-unknown}"

    if [ "$MODE" = "strict" ]; then
        if [ -n "$ifc" ]; then ip link set "$ifc" up; fi
        sleep 2
        restore_routes
    else
        fw_unblock_outside
        if ! ip -4 route show default | grep -q 'default'; then restore_routes; fi
    fi

    write_state on
    restore_services
    self_check "$ifc"
}

# 彻底复原：清规则 + 恢复路由/网卡 + 重启依赖服务。
# 排障用，也应当在卸载本程序之前执行一次——卸载只删文件，内核里的 netfilter 规则不会跟着消失。
do_purge() {
    log INFO "开始彻底复原：清理全部 net-guard 规则"
    fw_purge

    local ifc; ifc="$(primary_iface)"
    if [ -z "$ifc" ]; then ifc="$(cat "$STATE_DIR/iface.saved" 2>/dev/null || true)"; fi
    if [ -n "$ifc" ]; then ip link set "$ifc" up 2>/dev/null || true; fi
    if ! ip -4 route show default 2>/dev/null | grep -q 'default'; then
        log WARN "未发现默认路由，尝试按保存的信息 / DHCP 恢复"
        restore_routes
    fi
    rm -f "$STATE_DIR/"*.saved 2>/dev/null || true

    write_state on
    restore_services

    if iptables  -w -S 2>/dev/null | grep -q 'NET_GUARD' || \
       ip6tables -w -S 2>/dev/null | grep -q 'NET_GUARD'; then
        log ERROR "仍有 NET_GUARD 规则未能清除，请手工核对：iptables -S | grep NET_GUARD"
        return 1
    fi
    log INFO "复原完成：规则已清空，网络应恢复正常"
    return 0
}

self_check() {
    local ifc="$1" gw ok=0 attempt
    gw="$(default_gateway)"
    for attempt in 1 2; do
        ok=1
        if [ -n "$gw" ]; then
            ping -c 2 -W 3 -n "$gw" >/dev/null 2>&1 || ok=0
        fi
        if [ "$ok" -eq 1 ]; then
            for t in $PING_TARGETS; do
                if ! ping -c 2 -W 3 -n "$t" >/dev/null 2>&1; then
                    ok=0
                    break
                fi
                break   # 有一个公网目标通即视为恢复成功
            done
        fi
        if [ "$ok" -eq 1 ]; then break; fi
        log WARN "第 $attempt 次连通性自检未通过，重新申请地址后重试"
        if [ -n "$ifc" ]; then renew_dhcp "$ifc"; fi
        sleep 3
    done

    if [ "$ok" -eq 1 ]; then
        log INFO "连通性自检通过，网络已恢复"
    else
        log ERROR "联网自检仍未通过，请检查网线/网关/DHCP 服务（当前网关=${gw:-无}）"
    fi
}

# 守卫纠偏（幂等，不改状态文件）：封锁期间若默认路由被人手动加回（soft）、
# 网卡被拉起（strict）、或封锁规则被外部清掉（guard/soft），立即纠正回封锁态。
# 由面板调度器每 10 秒调用一次；返回 0=无需纠正，3=做过纠正（供面板记录）。
# 注意不要用返回值 2 —— 那是「apt/dpkg 忙碌跳过」的约定信号。
do_verify() {
    [ "$(read_state)" = "off" ] || return 0
    local fixed=0
    case "$MODE" in
        guard)
            local miss=0
            if have iptables && ! iptables -w -C INPUT -j "$CHAIN_IN" >/dev/null 2>&1; then
                miss=1
            fi
            if have ip6tables && ! ip6tables -w -C INPUT -j "$CHAIN_IN" >/dev/null 2>&1; then
                miss=1
            fi
            if [ "$miss" -eq 1 ]; then
                log WARN "守卫：入站封锁规则缺失（可能被外部清掉），重新挂载"
                fw_block_inbound
                fixed=1
            fi
            ;;
        soft)
            if ip -4 route show default 2>/dev/null | grep -q 'default'; then
                while ip -4 route show default 2>/dev/null | grep -q 'default'; do
                    ip -4 route del default 2>/dev/null || break
                done
                log WARN "守卫：检测到 IPv4 默认路由被外部恢复，已重新删除"
                fixed=1
            fi
            if ip -6 route show default 2>/dev/null | grep -q 'default'; then
                while ip -6 route show default 2>/dev/null | grep -q 'default'; do
                    ip -6 route del default 2>/dev/null || break
                done
                log WARN "守卫：检测到 IPv6 默认路由被外部恢复，已重新删除"
                fixed=1
            fi
            local miss_out=0
            if have iptables && ! iptables -w -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
                miss_out=1
            fi
            if [ "$miss_out" -eq 1 ]; then
                log WARN "守卫：出站封锁规则缺失，重新挂载"
                fw_block_outside
                fixed=1
            fi
            ;;
        strict)
            local ifc
            ifc="$(primary_iface)"
            if [ -n "$ifc" ] && ip link show "$ifc" 2>/dev/null | grep -q 'state UP'; then
                ip link set "$ifc" down
                log WARN "守卫：网卡 $ifc 被外部拉起，已重新关闭"
                fixed=1
            fi
            ;;
    esac
    if [ "$fixed" -eq 1 ]; then return 3; fi
    return 0
}

do_reload() {
    # 按最新配置重建规则，且不改变当前的封锁/放行状态。
    # 用途：改了放行网段、拦截日志等设置后立刻让新配置生效。
    local st; st="$(read_state)"
    if [ "$st" = "off" ]; then
        log INFO "按最新配置重建规则（保持封锁状态）"
        do_off force
    else
        log INFO "当前为放行状态，按最新配置刷新"
        do_on force
    fi
    return 0
}

# 开机自愈 / 状态纠偏
do_reconcile() {
    local now state_now
    now="$(date '+%s')"
    # 判断当前是否处于断网窗口 [OFF_TIME, ON_TIME)
    if [ "$(read_state)" = "off" ]; then state_now=off; else state_now=on; fi

    local should=on in_window=0
    local today_on today_off
    today_off="$(date -d "$OFF_TIME" '+%s' 2>/dev/null || echo 0)"
    today_on="$(date -d "$ON_TIME" '+%s' 2>/dev/null || echo 0)"

    # 窗口判断，兼容跨零点（如 23:30 -> 06:00）
    if [ "$today_off" -le "$today_on" ]; then
        if [ "$now" -ge "$today_off" ] && [ "$now" -lt "$today_on" ]; then in_window=1; fi
    else
        if [ "$now" -ge "$today_off" ] || [ "$now" -lt "$today_on" ]; then in_window=1; fi
    fi
    if [ "$in_window" -eq 1 ]; then should=off; fi

    log INFO "状态纠偏：当前=$state_now 应为=$should"
    if [ "$should" = "off" ] && [ "$state_now" != "off" ]; then do_off "$@"
    elif [ "$should" = "on" ] && [ "$state_now" != "on" ]; then do_on "$@"
    fi
}

show_status() {
    local st ifc gw rt mdesc
    st="$(read_state)"
    ifc="$(primary_iface)"; gw="$(default_gateway)"
    rt="$(ip -4 route show default 2>/dev/null | head -n1)"
    case "$MODE" in
        guard)  mdesc="入站封锁（外部连不进来，本机照常上网）" ;;
        soft)   mdesc="断外网（局域网保留）" ;;
        strict) mdesc="彻底断开网口" ;;
        *)      mdesc="$MODE" ;;
    esac
    echo "================ net-guard 状态 ================"
    echo "运行模式      : $MODE  —  $mdesc"
    echo "封锁/恢复时间 : $OFF_TIME  ->  $ON_TIME"
    echo "当前状态      : $st"
    echo "主网卡        : ${ifc:-无}"
    echo "默认网关      : ${gw:-无}"
    echo "默认路由(v4)  : ${rt:-无}"
    if [ "$MODE" = "guard" ]; then
        # 用 -C 精确探测规则是否挂在链上，比扫整个 iptables -S 更快也更准
        if have iptables && iptables -w -C INPUT -j "$CHAIN_IN" >/dev/null 2>&1; then
            echo "入站封锁规则  : 已生效"
            echo "已拦截入侵包  : $(guard_stats)"
        else
            echo "入站封锁规则  : 未生效"
        fi
    else
        if have iptables && iptables -w -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
            echo "出站封锁规则  : 已生效"
        else
            echo "出站封锁规则  : 未生效"
        fi
    fi
    if [ -r "$STATE_DIR/routes-v4.saved" ]; then
        echo "已备份路由    : $(head -n1 "$STATE_DIR/routes-v4.saved")"
    fi
    echo "最近日志      :"
    tail -n 8 "$LOG_FILE" 2>/dev/null || echo "  (无)"
    echo "================================================"
}

do_detect() {
    detect_env
    local _ifc _gw _sd _dk
    _ifc="$(primary_iface)"; _gw="$(default_gateway)"
    if have systemctl && pidof systemd >/dev/null 2>&1; then _sd="可用"; else _sd="不可用，请改用 cron"; fi
    if iptables -w -L DOCKER-USER -n >/dev/null 2>&1; then _dk="存在"; else _dk="无（未装 Docker 或未启用）"; fi
    echo "NetworkManager : $([ "$NM_AVAILABLE" = 1 ] && echo 可用 || echo 未使用/无)"
    echo "ifupdown       : $([ "$IFUPDOWN_AVAILABLE" = 1 ] && echo 可用 || echo 无)"
    echo "DHCP 客户端    : ${DHCP_CLIENT:-无}"
    echo "iptables       : $(have iptables && echo 可用 || echo 无)"
    echo "ip6tables      : $(have ip6tables && echo 可用 || echo 无)"
    echo "systemd        : ${_sd}"
    echo "DOCKER-USER 链 : ${_dk}"
    echo "主网卡         : ${_ifc:-未识别}"
    echo "默认网关       : ${_gw:-无}"
    echo "--- 全部网卡 ---"
    ip -brief link show 2>/dev/null || ip link show
}

# --------------------------------- 入口 -------------------------------------
main() {
    local cmd="${1:-status}"
    shift || true
    need_root "$cmd" "$@"
    detect_env

    case "$cmd" in
        off)        with_lock; do_off "$@" ;;
        reload)     with_lock; do_reload "$@" ;;
        on)         with_lock; do_on "$@" ;;
        purge|clean|reset) with_lock; do_purge ;;
        reconnect|cycle) with_lock; do_off force >/dev/null 2>&1 || true; sleep 2; do_on force ;;
        reconcile)  with_lock; do_reconcile "$@" ;;
        verify)     with_lock; do_verify "$@" ;;
        status)     show_status ;;
        detect)     do_detect ;;
        *)
            cat <<'USAGE'
用法: net-guard.sh <命令>
  off        断开外网
  on         恢复外网
  purge      彻底复原：清空本程序所有 iptables 规则 + 恢复路由，卸载前务必先执行
  reconcile  按当前时间自动纠正状态（开机自愈）
  reload     按最新配置重建规则（保持当前封锁/放行状态）
  verify     封锁态守卫自检：路由被加回/规则被清/网卡被拉起时立即纠正
  status     查看状态与最近日志
  detect     探测本机网络管理方式
  cycle      强制重连一次（排障用）
USAGE
            exit 1
            ;;
    esac
}

main "$@"
