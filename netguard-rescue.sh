#!/usr/bin/env bash
# =============================================================================
#  netguard-rescue —— 网络守卫残留清理 & FN Connect 通信急救脚本
#
#  用途：当「恢复网络后 FN Connect 中继转发不可用 / 外网访问不来 / 卸载程序也无效」
#        时执行。它不依赖网络守卫是否已安装，root 直接跑即可。
#
#  用法：
#    sudo bash netguard-rescue.sh            # 诊断 + 清理 + 恢复（默认）
#    sudo bash netguard-rescue.sh diag       # 只诊断，不改任何东西
#    sudo bash netguard-rescue.sh clean      # 只清理防火墙/路由残留
#    sudo bash netguard-rescue.sh fn         # 只重启 FN Connect 相关服务
#
#  它做四件事：
#    1. 删除所有残留的 NET_GUARD / NET_GUARD_IN 链与其挂载（iptables + ip6tables）
#    2. 恢复默认路由 / 拉起网卡（默认路由丢失是「局域网通、外网不通」的首要原因）
#    3. 重启 FN Connect 相关服务与容器
#    4. 自检并打印结论
# =============================================================================

set -Eeuo pipefail

CHAINS_V4="NET_GUARD NET_GUARD_IN"
PARENT_CHAINS="INPUT OUTPUT FORWARD DOCKER-USER"
FN_NAMES="fn-connect trim_connect trim-connect fnconnect fn_connect fnconnectd fnos-connect"
SAVED_DIRS="/var/lib/net-guard /var/apps/app.netguard/var"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
good() { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m[!!]\033[0m %s\n' "$*"; }
info() { printf '     %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 1. 诊断
do_diag() {
    say "== 网卡与地址 =="
    ip -brief address show 2>/dev/null || ip address show

    say "== IPv4 路由表 =="
    if ip -4 route show | grep -q '^default\| default '; then
        good "存在默认路由：$(ip -4 route show default | head -3 | tr '\n' ' ')"
    else
        bad "没有默认路由！这就是外网/FN 中继不通的典型症状"
    fi
    echo "---- 完整路由 ----"
    ip route show

    say "== IPv6 路由 =="
    ip -6 route show default 2>/dev/null || info "(无 IPv6 默认路由)"

    say "== DNS 配置 =="
    cat /etc/resolv.conf 2>/dev/null | grep -v '^#' || true

    say "== 防火墙残留（NET_GUARD*）=="
    local found=0
    if have iptables; then
        if iptables -w -S 2>/dev/null | grep -q 'NET_GUARD'; then
            found=1
            bad "发现 iptables 残留规则："
            iptables -w -S 2>/dev/null | grep 'NET_GUARD' || true
        fi
    fi
    if have ip6tables; then
        if ip6tables -w -S 2>/dev/null | grep -q 'NET_GUARD'; then
            found=1
            bad "发现 ip6tables 残留规则："
            ip6tables -w -S 2>/dev/null | grep 'NET_GUARD' || true
        fi
    fi
    if [ "$found" -eq 0 ]; then
        good "防火墙里没有 NET_GUARD 相关的残留规则"
    fi

    say "== FORWARD / INPUT 默认策略 =="
    have iptables  && iptables  -w -S INPUT 2>/dev/null | head -3 || true
    have iptables  && iptables  -w -S FORWARD 2>/dev/null | head -3 || true

    say "== FN Connect 服务状态 =="
    local n st
    for n in $FN_NAMES; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${n}.service"; then
            st="$(systemctl is-active "$n" 2>/dev/null || echo inactive)"
            if [ "$st" = "active" ]; then good "$n: $st"; else bad "$n: $st"; fi
        fi
    done
    info "(以上只列出本机真实存在的 FN Connect 服务单元)"

    if have docker && docker info >/dev/null 2>&1; then
        say "== 可能与 FN 相关的容器 =="
        docker ps -a --format '{{.Names}}\t{{.Status}}' 2>/dev/null | \
            grep -iE 'fn|trim|connect' || info "(未发现名字含 fn/trim/connect 的容器)"
    fi

    say "== 外网连通性 =="
    local gw; gw="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
    if [ -n "$gw" ]; then
        ping -c 2 -W 3 -n "$gw" >/dev/null 2>&1 && good "网关 $gw 可达" || bad "网关 $gw 不可达"
    fi
    ping -c 2 -W 4 -n 223.5.5.5 >/dev/null 2>&1 && good "公网 223.5.5.5 可达" || bad "公网 223.5.5.5 不可达"
    ping -c 2 -W 4 -n www.baidu.com >/dev/null 2>&1 && good "域名解析 + 出网正常" || bad "域名或出网异常"
}

# ------------------------------------------------- 2. 清理 net-guard 残留规则
do_clean() {
    say "== 清理 NET_GUARD 防火墙残留 =="
    local c p tool parent
    for tool in iptables ip6tables; do
        have "$tool" || continue
        # 2.1 先从各父链上摘掉跳转（可能重复挂载，循环删干净）
        for p in $PARENT_CHAINS; do
            $tool -w -S "$p" >/dev/null 2>&1 || continue
            local guard=0 target
            while $tool -w -S "$p" 2>/dev/null | grep -q -- "-j NET_GUARD\|-j NET_GUARD_IN"; do
                target=""
                target="$($tool -w -S "$p" 2>/dev/null | grep -oE -- '-j (NET_GUARD|NET_GUARD_IN)$' | head -1 | awk '{print $2}')" || true
                if [ -z "$target" ]; then break; fi
                $tool -w -D "$p" -j "$target" 2>/dev/null || break
                guard=$((guard + 1))
                if [ "$guard" -ge 20 ]; then break; fi
            done
        done
        # 2.2 清空并删除链本体
        for c in $CHAINS_V4; do
            $tool -w -F "$c" 2>/dev/null || true
            $tool -w -X "$c" 2>/dev/null || true
        done
    done
    if iptables  -w -S 2>/dev/null | grep -q 'NET_GUARD' || \
       ip6tables -w -S 2>/dev/null | grep -q 'NET_GUARD'; then
        bad "仍有 NET_GUARD 规则未能自动清除，请手工检查上面 diag 的输出"
    else
        good "NET_GUARD 规则已全部清除"
    fi

    say "== 恢复默认路由 / 网卡 =="
    local ifc
    ifc="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
    if [ -z "$ifc" ]; then
        # 没有默认路由时，拿第一张有 IPv4 地址、非 lo/docker/虚拟网卡的口
        ifc="$(ip -o -4 address show 2>/dev/null | awk '$2!="lo" && $2!~/^(docker|br-|veth|tailscale|zt|tun)/ {print $2; exit}')"
    fi
    info "目标网卡：${ifc:-未识别}"

    if [ -n "$ifc" ]; then
        ip link set "$ifc" up 2>/dev/null || true
        info "网卡已置为 up"
    fi

    if ip -4 route show default 2>/dev/null | grep -q 'default'; then
        good "默认路由已存在，无需恢复"
    else
        bad "默认路由缺失，尝试恢复……"
        # (a) 用本脚本先前保存的原始路由
        local d line restored=0
        for d in $SAVED_DIRS; do
            if [ -s "$d/routes-v4.saved" ]; then
                info "使用保存的路由：$d/routes-v4.saved"
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    ip -4 route replace $line 2>/dev/null && restored=1
                done <"$d/routes-v4.saved"
                if [ "$restored" -eq 1 ]; then break; fi
            fi
        done
        # (b) 用保存的网关地址
        if [ "$restored" -ne 1 ]; then
            for d in $SAVED_DIRS; do
                if [ -s "$d/gateway.saved" ] && [ -n "$ifc" ]; then
                    local gw; gw="$(head -1 "$d/gateway.saved")"
                    info "使用保存的网关：$gw"
                    ip -4 route replace default via "$gw" dev "$ifc" 2>/dev/null && restored=1
                    if [ "$restored" -eq 1 ]; then break; fi
                fi
            done
        fi
        # (c) 重新向 DHCP 要地址——最通用的一招
        if [ "$restored" -ne 1 ]; then
            info "尝试重新申请 DHCP 租约"
            if have dhclient; then
                timeout 20 dhclient -r "$ifc" >/dev/null 2>&1 || true
                timeout 40 dhclient -1 -timeout 20 "$ifc" >/dev/null 2>&1 || true
            elif have udhcpc; then
                timeout 30 udhcpc -i "$ifc" -q -n >/dev/null 2>&1 || true
            elif have dhcpcd; then
                timeout 30 dhcpcd -n "$ifc" >/dev/null 2>&1 || true
            fi
            if have nmcli && nmcli -t -f RUNNING general 2>/dev/null | grep -q '^running$'; then
                timeout 30 nmcli device reapply "$ifc" >/dev/null 2>&1 || \
                timeout 30 nmcli con up "$(nmcli -t -f DEVICE,NAME d 2>/dev/null | awk -F: -v d="$ifc" '$1==d{print $2; exit}')" >/dev/null 2>&1 || true
            fi
            if (have ifdown || [ -x /sbin/ifdown ]) && [ -n "$ifc" ]; then
                timeout 30 ifdown --force "$ifc" >/dev/null 2>&1 || true
                timeout 40 ifup "$ifc" >/dev/null 2>&1 || true
            fi
        fi
        ip -4 route show default 2>/dev/null | grep -q 'default' \
            && good "默认路由已恢复：$(ip -4 route show default | head -2 | tr '\n' ' ')" \
            || bad "默认路由仍未恢复，请检查网线、光猫/路由器，或在飞牛网络设置里手动点一次「保存/连接」"
    fi
}

# ------------------------------------------------------ 3. 重启 FN Connect
do_fn() {
    say "== 重启 FN Connect 相关服务 =="
    local n restarted=0 st
    for n in $FN_NAMES; do
        systemctl list-unit-files 2>/dev/null | grep -q "^${n}.service" || continue
        # 先 stop 再 start：让中继会话完整重建一次，比 restart 更彻底
        systemctl stop "$n" >/dev/null 2>&1 || true
        sleep 1
        systemctl start "$n" >/dev/null 2>&1 || true
        sleep 2
        st="$(systemctl is-active "$n" 2>/dev/null || echo inactive)"
        if [ "$st" = "active" ]; then good "$n 已重新拉起 ($st)"; restarted=1
        else bad "$n 启动失败 ($st)，请查看：journalctl -u $n -n 50"; fi
    done
    if [ "$restarted" -eq 0 ]; then
        info "本机没有上述 FN Connect 服务单元；若为容器部署，请到飞牛「远程访问/FN Connect」页面关掉再打开一次"
    fi

    if have docker && docker info >/dev/null 2>&1; then
        local cname
        for cname in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -iE 'fn|trim|connect' || true); do
            info "重启容器：$cname"
            docker restart "$cname" >/dev/null 2>&1 && good "$cname 已重启" || bad "$cname 重启失败"
        done
    fi

    info "提示：FN Connect 需要在飞牛「设置 → 远程访问」里重新建立中继会话，"
    info "      若服务已起但仍不通，把该页面开关关掉、等 5 秒再打开一次即可。"
}

do_verify() {
    say "== 恢复后自检 =="
    local gw; gw="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
    [ -n "$gw" ] && (ping -c 2 -W 3 -n "$gw" >/dev/null 2>&1 && good "网关 $gw 可达" || bad "网关 $gw 不可达") \
                 || bad "仍然没有默认路由"
    ping -c 2 -W 4 -n 223.5.5.5 >/dev/null 2>&1 && good "公网 IP 可达" || bad "公网 IP 不可达"
    ping -c 2 -W 4 -n www.baidu.com >/dev/null 2>&1 && good "域名解析正常" || bad "域名解析失败（检查 /etc/resolv.conf）"
    iptables  -w -S 2>/dev/null | grep -q 'NET_GUARD' && bad "iptables 仍有 NET_GUARD 残留" || good "iptables 干净"
    ip6tables -w -S 2>/dev/null | grep -q 'NET_GUARD' && bad "ip6tables 仍有 NET_GUARD 残留" || good "ip6tables 干净"
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "请以 root 执行：sudo bash $0 $*" >&2
        exit 1
    fi
    case "${1:-all}" in
        diag)  do_diag ;;
        clean) do_clean ;;
        fn)    do_fn ;;
        verify) do_verify ;;
        all)
            do_diag
            echo
            do_clean
            echo
            do_fn
            echo
            do_verify
            echo
            say "完成。请现在用手机流量（不走家里的 WiFi）测试 FN Connect 远程访问。"
            say "若仍不通，请把上面全部输出发我，并顺便执行：journalctl -u fn-connect -n 80"
            ;;
        *)
            echo "用法: $0 {all|diag|clean|fn|verify}" >&2; exit 1 ;;
    esac
}

main "$@"
