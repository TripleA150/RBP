#!/bin/bash

# Проверка необходимости перезагрузить
# if [[ -f /var/run/reboot-required ]] || pidof apt apt-get dpkg unattended-upgrades &>/dev/null; then
# 	echo 'Error: You need to reboot this server before installation!'
# 	exit 2
# fi

# Проверка прав root
if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!' >&2
	exit 3
fi

cd /root

# Проверка на OpenVZ и LXC
if [[ "$(systemd-detect-virt)" == 'openvz' || "$(systemd-detect-virt)" == 'lxc' ]]; then
	echo 'Error: OpenVZ and LXC are not supported!' >&2
	exit 4
fi

# Проверка версии системы
# lsb_release отсутствует на минимальной установке, читаем /etc/os-release
if [[ ! -r /etc/os-release ]]; then
	echo 'Error: /etc/os-release not found, cannot detect your Linux distribution!' >&2
	exit 7
fi
. /etc/os-release
OS="${ID,,}"
VERSION="${VERSION_ID%%.*}"
OS_PRETTY="${PRETTY_NAME:-$OS $VERSION_ID}"

# У Debian testing/sid и прочих rolling-релизов VERSION_ID в os-release отсутствует,
# без этой проверки версия оказалась бы пустой и в тексте ошибки зияла бы дыра
if [[ -z "$VERSION" ]]; then
	echo "Error: your distribution ($OS_PRETTY) has no version number in /etc/os-release!" >&2
	echo 'Rolling releases like Debian testing/sid are not supported, use a stable release' >&2
	exit 10
fi

if [[ "$OS" == 'debian' ]]; then
	if (( VERSION < 12 )); then
		echo "Error: Debian $VERSION is not supported! Minimal supported version is 12" >&2
		exit 5
	fi
elif [[ "$OS" == 'ubuntu' ]]; then
	if (( VERSION < 22 )); then
		echo "Error: Ubuntu $VERSION is not supported! Minimal supported version is 22" >&2
		exit 6
	fi
else
	echo "Error: Your Linux distribution ($OS) is not supported!" >&2
	exit 7
fi

DEFAULT_INTERFACE="$(ip route get 1.2.3.4 2>/dev/null | grep -oP 'dev \K\S+')"
if [[ -z "$DEFAULT_INTERFACE" ]]; then
	echo 'Default network interface not found!' >&2
	exit 8
fi

DEFAULT_IP="$(ip route get 1.2.3.4 2>/dev/null | grep -oP 'src \K\S+')"
if [[ -z "$DEFAULT_IP" ]]; then
	echo 'Default IPv4 address not found!' >&2
	exit 9
fi

RESOLVED_IP=''
resolve_ipv4() {
	local input="$1" ip octet
	if [[ -z "$input" ]]; then
		echo 'Error: address cannot be empty!' >&2
		return 1
	fi
	if [[ "$input" =~ ^[0-9.]+$ ]]; then
		ip="$input"
	else
		ip="$(getent ahostsv4 "$input" | awk '{print $1; exit}')"
		if [[ -z "$ip" ]]; then
			echo "Error: cannot resolve $input to an IPv4 address!" >&2
			return 1
		fi
		echo "  $input resolved to $ip"
	fi
	if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		echo "Error: $ip is not a valid IPv4 address!" >&2
		return 1
	fi
	for octet in ${ip//./ }; do
		if [[ ! "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( octet > 255 )); then
			echo "Error: $ip is not a valid IPv4 address!" >&2
			return 1
		fi
	done
	if [[ "$ip" == "$DEFAULT_IP" ]]; then
		echo "Error: $ip is the address of this server, it would create a DNAT loop!" >&2
		return 1
	fi
	RESOLVED_IP="$ip"
	return 0
}

echo
echo -e '\e[1;32mInstalling proxy for AntiZapret VPN server\e[0m'
echo 'Proxied ports:'
echo '    OpenVPN UDP:           504, 508, 50080, 50443'
echo '    OpenVPN TCP:           504, 508, 50080, 50443'
echo '    WireGuard/AmneziaWG:   540, 580, 51080, 51443, 52080, 52443'
echo '    OpenConnect:           443, 53080, 53443'
echo

MTU=$(< "/sys/class/net/$DEFAULT_INTERFACE/mtu")
if (( MTU < 1500 )); then
	echo "Warning! Low MTU on $DEFAULT_INTERFACE: $MTU"
	echo "Change MTU in OpenVPN and WireGuard configs from 1420 to $((MTU-80)) on AntiZapret VPN server"
	echo
fi

# Спрашиваем о настройках
until [[ "$OPENVPN_UDP" =~ ^(y|n)$ ]]; do
	read -rp 'Enable OpenVPN UDP proxying? [y/n]: ' -e -i y OPENVPN_UDP
	OPENVPN_UDP="${OPENVPN_UDP,,}"
done
echo
until [[ "$OPENVPN_TCP" =~ ^(y|n)$ ]]; do
	read -rp 'Enable OpenVPN TCP proxying? [y/n]: ' -e -i y OPENVPN_TCP
	OPENVPN_TCP="${OPENVPN_TCP,,}"
done
echo
until [[ "$WIREGUARD" =~ ^(y|n)$ ]]; do
	read -rp 'Enable WireGuard/AmneziaWG proxying? [y/n]: ' -e -i y WIREGUARD
	WIREGUARD="${WIREGUARD,,}"
done
until [[ "$OPENCONNECT" =~ ^(y|n)$ ]]; do
	read -rp 'Enable OpenConnect proxying? [y/n]: ' -e -i n OPENCONNECT
	OPENCONNECT="${OPENCONNECT,,}"
done
echo
if [[ "$OPENVPN_UDP" == 'y' || "$OPENVPN_TCP" == 'y' ]]; then
	while read -rp 'Enter OpenVPN server IPv4 address or hostname: ' -e OPENVPN_IP
	do
		resolve_ipv4 "$OPENVPN_IP" || continue
		OPENVPN_IP="$RESOLVED_IP"
		break
	done
	echo
fi
if [[ "$WIREGUARD" == 'y' ]]; then
	while read -rp 'Enter WireGuard/AmneziaWG server IPv4 address or hostname: ' -e WIREGUARD_IP
	do
		resolve_ipv4 "$WIREGUARD_IP" || continue
		WIREGUARD_IP="$RESOLVED_IP"
		break
	done
	echo
fi
if [[ "$OPENCONNECT" == 'y' ]]; then
	while read -rp 'Enter OpenConnect server IPv4 address or hostname: ' -e OPENCONNECT_IP
	do
		resolve_ipv4 "$OPENCONNECT_IP" || continue
		OPENCONNECT_IP="$RESOLVED_IP"
		break
	done
	echo
fi
echo 'Warning! SSH protection may block your IP after 5 logins/minute!'
until [[ "$SSH_PROTECTION" =~ ^(y|n)$ ]]; do
	read -rp 'Enable SSH brute-force protection? [y/n]: ' -e -i y SSH_PROTECTION
	SSH_PROTECTION="${SSH_PROTECTION,,}"
done
echo
echo 'Warning! Scan protection blocks ping and closed-port replies!'
until [[ "$SCAN_PROTECTION" =~ ^(y|n)$ ]]; do
	read -rp 'Enable network scan protection? [y/n]: ' -e -i y SCAN_PROTECTION
	SCAN_PROTECTION="${SCAN_PROTECTION,,}"
done
echo
echo 'Installation, please wait...'

# Удалим ненужные службы
apt-get purge -y ufw
apt-get purge -y firewalld
apt-get purge -y apparmor
apt-get purge -y apport
apt-get purge -y modemmanager
apt-get purge -y snapd
apt-get purge -y upower
apt-get purge -y multipath-tools
apt-get purge -y rsyslog
apt-get purge -y udisks2
apt-get purge -y tuned
apt-get purge -y sysstat
apt-get purge -y fwupd
apt-get purge -y pcscd
apt-get purge -y packagekit

# SSH protection включён
if [[ "$SSH_PROTECTION" == 'y' ]]; then
	apt-get purge -y fail2ban
	apt-get purge -y sshguard
fi

# Отключим IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# Удаляем переопределённые параметры ядра
# sed -i '/^$/!{/^#/!d}' /etc/sysctl.conf

# Принудительная загрузка модуля nf_conntrack
echo 'nf_conntrack' > /etc/modules-load.d/nf_conntrack.conf

# Завершим выполнение скрипта при ошибке
set -e

# Обработка ошибок
handle_error() {
	echo "$OS_PRETTY $(uname -r) $(date --iso-8601=seconds)" >&2
	echo -e "\e[1;31mError at line $1: $2\e[0m" >&2
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

# Автоматически сохраним правила iptables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# Обновляем систему и ставим необходимые пакеты
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get update
dpkg --configure -a
apt-get install --fix-broken -y
apt-get dist-upgrade -y
apt-get install -y iptables iptables-persistent irqbalance unattended-upgrades
apt-get autoremove --purge -y
apt-get clean
dpkg-reconfigure -f noninteractive unattended-upgrades

# Отключим IPv6
echo "# Disable IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1" > /etc/sysctl.d/99-disable-ipv6.conf

# Параметры conntrack
echo 'options nf_conntrack hashsize=131072' > /etc/modprobe.d/nf_conntrack.conf
modprobe nf_conntrack
if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
	echo 131072 > /sys/module/nf_conntrack/parameters/hashsize
fi
echo "net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=524288
net.netfilter.nf_conntrack_tcp_timeout_established=3600
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=180" > /etc/sysctl.d/99-conntrack.conf
while IFS= read -r param; do
	param="${param// /}"
	if [[ -z "$param" || "$param" == \#* ]]; then
		continue
	fi
	if ! sysctl -w "$param" > /dev/null; then
		echo "Warning! Kernel parameter is not supported: ${param%%=*}" >&2
	fi
done < /etc/sysctl.d/99-most.conf

# Очистка правил iptables
iptables -w -F
iptables -w -t nat -F
iptables -w -t mangle -F
iptables -w -t raw -F
ip6tables -w -F
ip6tables -w -t nat -F
ip6tables -w -t mangle -F
ip6tables -w -t raw -F

# Новые правила iptables
# filter
# Default policy
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
ip6tables -w -P INPUT ACCEPT
ip6tables -w -P FORWARD ACCEPT
ip6tables -w -P OUTPUT ACCEPT
# INPUT connection tracking
iptables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I INPUT 1 -m conntrack --ctstate INVALID -j DROP
# FORWARD connection tracking
iptables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
# OUTPUT connection tracking
iptables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
ip6tables -w -I OUTPUT 1 -m conntrack --ctstate INVALID -j DROP
# SSH protection
if [[ "$SSH_PROTECTION" == 'y' ]]; then
	iptables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/minute --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name proxy-ssh --hashlimit-htable-expire 60000 -j DROP
	ip6tables -w -I INPUT 2 -p tcp --dport ssh -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/minute --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name proxy-ssh6 --hashlimit-htable-expire 60000 -j DROP
fi
# Scan protection
if [[ "$SCAN_PROTECTION" == 'y' ]]; then
	iptables -w -I INPUT 2 -i "$DEFAULT_INTERFACE" -p icmp --icmp-type echo-request -j DROP
	iptables -w -I OUTPUT 2 -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
	iptables -w -I OUTPUT 3 -o "$DEFAULT_INTERFACE" -p icmp --icmp-type port-unreachable -j DROP
	ip6tables -w -I INPUT 2 -i "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type echo-request -j DROP
	ip6tables -w -I OUTPUT 2 -o "$DEFAULT_INTERFACE" -p tcp --tcp-flags RST RST -j DROP
	ip6tables -w -I OUTPUT 3 -o "$DEFAULT_INTERFACE" -p icmpv6 --icmpv6-type port-unreachable -j DROP
fi

# mangle
# Clamp TCP MSS
iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# nat
# OpenVPN TCP
if [[ "$OPENVPN_TCP" == 'y' ]]; then
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 504 -j DNAT --to-destination "$OPENVPN_IP:50443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 508 -j DNAT --to-destination "$OPENVPN_IP:50080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 50080 -j DNAT --to-destination "$OPENVPN_IP:50080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 50443 -j DNAT --to-destination "$OPENVPN_IP:50443"
fi
# OpenVPN UDP
if [[ "$OPENVPN_UDP" == 'y' ]]; then
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 504 -j DNAT --to-destination "$OPENVPN_IP:50443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 508 -j DNAT --to-destination "$OPENVPN_IP:50080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 50080 -j DNAT --to-destination "$OPENVPN_IP:50080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 50443 -j DNAT --to-destination "$OPENVPN_IP:50443"
fi
# WireGuard/AmneziaWG
if [[ "$WIREGUARD" == 'y' ]]; then
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 540 -j DNAT --to-destination "$WIREGUARD_IP:51443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 580 -j DNAT --to-destination "$WIREGUARD_IP:51080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 51080 -j DNAT --to-destination "$WIREGUARD_IP:51080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 51443 -j DNAT --to-destination "$WIREGUARD_IP:51443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 52080 -j DNAT --to-destination "$WIREGUARD_IP:51080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 52443 -j DNAT --to-destination "$WIREGUARD_IP:51443"
fi
# OpenConnect
if [[ "$OPENCONNECT" == 'y' ]]; then
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 443 -j DNAT --to-destination "$OPENCONNECT_IP:53443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 443 -j DNAT --to-destination "$OPENCONNECT_IP:53443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 53443 -j DNAT --to-destination "$OPENCONNECT_IP:53443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 53443 -j DNAT --to-destination "$OPENCONNECT_IP:53443"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p tcp --dport 53080 -j DNAT --to-destination "$OPENCONNECT_IP:53080"
	iptables -w -t nat -A PREROUTING "${DNAT_MATCH[@]}" -p udp --dport 53080 -j DNAT --to-destination "$OPENCONNECT_IP:53080"
fi
# SNAT
if [[ -n "$OPENVPN_IP" ]]; then
	iptables -w -A INPUT -s "$OPENVPN_IP" -j ACCEPT
	iptables -w -t nat -A POSTROUTING -d "$OPENVPN_IP" -j SNAT --to-source "$DEFAULT_IP" --random-fully
fi
if [[ -n "$WIREGUARD_IP" && "$WIREGUARD_IP" != "$OPENVPN_IP" ]]; then
	iptables -w -A INPUT -s "$WIREGUARD_IP" -j ACCEPT
	iptables -w -t nat -A POSTROUTING -d "$WIREGUARD_IP" -j SNAT --to-source "$DEFAULT_IP" --random-fully
fi
if [[ -n "$OPENCONNECT_IP" && "$OPENCONNECT_IP" != "$OPENVPN_IP" && "$OPENCONNECT_IP" != "$WIREGUARD_IP" ]]; then
	iptables -w -A INPUT -s "$OPENCONNECT_IP" -j ACCEPT
	iptables -w -t nat -A POSTROUTING -d "$OPENCONNECT_IP" -j SNAT --to-source "$DEFAULT_IP" --random-fully
fi

# Сохранение новых правил iptables
netfilter-persistent save
systemctl enable netfilter-persistent

# Перезагружаем
echo
echo -e '\e[1;32mProxy for AntiZapret VPN server installed successfully!\e[0m'
reboot
