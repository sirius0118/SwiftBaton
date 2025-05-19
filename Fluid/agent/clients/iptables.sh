#!/bin/bash -
#===============================================================================
#
# FILE: iptable_redirect_port.sh
#
# USAGE: ./iptable_redirect_port.sh PROTOCOL SERVER_PORT DHOST DPORT [-d]
#
# DESCRIPTION: Redirect traffic to another server.
#
# OPTIONS: ---
# REQUIREMENTS: ---
# BUGS: ---
# NOTES: ---
# AUTHOR: Zhang Guangtong <zhgt123@gmail.com>
# ORGANIZATION:
# CREATED: 2015年08月05日 10:07
# REVISION: ---
#===============================================================================

# example:
#iptables -t nat -A PREROUTING -p tcp --dport 1111 -j DNAT --to-destination 192.168.1.10:8022
#iptables -t nat -A POSTROUTING -d 192.168.1.10 -p tcp --dport 8022 -j MASQUERADE

redirect_port()
{
    PROTOCOL=$1
    SERVER_PORT=$2
    DHOST=$3
    DPORT=$4

    # 新增本地流量处理规则
    iptables -t nat -A OUTPUT -p $PROTOCOL --dport $SERVER_PORT -j DNAT --to-destination $DHOST:$DPORT
    
    # 原有规则保持不变
    iptables -t nat -A PREROUTING -p $PROTOCOL --dport $SERVER_PORT -j DNAT --to-destination $DHOST:$DPORT
    iptables -I FORWARD -d $DHOST -p $PROTOCOL --dport $DPORT -j ACCEPT
    iptables -I FORWARD -s $DHOST -p $PROTOCOL --sport $DPORT -j ACCEPT
    iptables -t nat -A POSTROUTING -d $DHOST -p $PROTOCOL --dport $DPORT -j MASQUERADE

    # 启用本地回环NAT支持
    sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
}

clean_redirect_port()
{
    PROTOCOL=$1
    SERVER_PORT=$2
    DHOST=$3
    DPORT=$4

    # 删除新增的本地流量规则
    iptables -t nat -D OUTPUT -p $PROTOCOL --dport $SERVER_PORT -j DNAT --to-destination $DHOST:$DPORT
    
    # 原有清理规则保持不变
    iptables -t nat -D PREROUTING -p $PROTOCOL --dport $SERVER_PORT -j DNAT --to-destination $DHOST:$DPORT
    iptables -D FORWARD -d $DHOST -p $PROTOCOL --dport $DPORT -j ACCEPT
    iptables -D FORWARD -s $DHOST -p $PROTOCOL --sport $DPORT -j ACCEPT
    iptables -t nat -D POSTROUTING -d $DHOST -p $PROTOCOL --dport $DPORT -j MASQUERADE
}

usage()
{
    echo "Usage: $0 PROTOCOL SERVER_PORT DHOST DPORT [-d]"
    echo ""
    echo "example1:"
    echo " $0 tcp 443 192.168.1.20 8043"
    echo " Visit this host on port 443 equal vist 192.168.1.20:443"
    echo "example2:"
    echo " $0 tcp 443 192.168.1.20 8043 -d"
    echo " Clean previous rules"
    echo "Notes: please make sure net.ipv4.ip_forward=1 in /etc/sysctl.conf and run \"sysctl -p\" to apply changes"
}

if [ $# -lt 4 ]; then
    usage
    exit
fi
if [ "$5" == "-d" ]; then
    clean_redirect_port "$@"
else
    redirect_port "$@"
fi