#!/bin/bash
#
# Добавление/удаление клиента
#
# chmod +x client.sh && ./client.sh [1-12] [имя_клиента] [срок_действия_сертификата]
#
# Срок действия сертификата в днях - только для OpenVPN
#
set -e
export LC_ALL=C
shopt -s nullglob

handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

if (( $# > 3 )); then
	echo 'Too many parameters! Usage: ./client.sh [1-12] [client_name] [cert_expire_days]'
	exit 2
fi

SERVER_IP="$(ip route get 1.2.3.4 2>/dev/null | grep -oP 'src \K\S+')"
if [[ -z "$SERVER_IP" ]]; then
	echo 'Default IPv4 address not found!'
	exit 3
fi

export EASYRSA_PKI=/etc/openvpn/easyrsa3/pki
cd /root/antizapret
source setup
umask 022
OPTION="$1"
CLIENT_NAME="$2"
CLIENT_CERT_EXPIRE="$3"

askClientName(){
	if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
		echo
		echo 'Enter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)'
		until [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; do
			read -rp 'Client name: ' -e CLIENT_NAME
		done
	fi
}

askClientCertExpire(){
	if ! [[ "$CLIENT_CERT_EXPIRE" =~ ^[0-9]+$ ]] || (( CLIENT_CERT_EXPIRE <= 0 )) || (( CLIENT_CERT_EXPIRE > 3650 )); then
		echo
		echo 'Enter client certificate expiration days (1-3650):'
		until [[ "$CLIENT_CERT_EXPIRE" =~ ^[0-9]+$ ]] && (( CLIENT_CERT_EXPIRE > 0 )) && (( CLIENT_CERT_EXPIRE <= 3650 )); do
			read -rp 'Certificate expiration days: ' -e -i 3650 CLIENT_CERT_EXPIRE
		done
	fi
}

setServerHost_FileName(){
	if [[ -z "$1" ]]; then
		SERVER_HOST="$SERVER_IP"
	else
		SERVER_HOST="$1"
	fi

	FILE_NAME="${CLIENT_NAME}"
	FILE_NAME="${FILE_NAME#vpn-}"
	FILE_NAME="${FILE_NAME}"
}

render() {
	local IFS=
	while read -r line; do
		while [[ "$line" =~ (\$\{[a-zA-Z_][a-zA-Z_0-9]*\}) ]]; do
			local LHS="${BASH_REMATCH[1]}"
			local RHS="$(eval echo "\"$LHS\"")"
			line="${line//$LHS/$RHS}"
		done
		echo "$line"
	done < "$1"
}

initOpenVPN(){
	mkdir -p /etc/openvpn/easyrsa3
	mkdir -p /etc/openvpn/server/ccd
	mkdir -p /etc/openvpn/server/ccd2
	mkdir -p /etc/openvpn/server/logs

	if [[ ! -f /etc/openvpn/easyrsa3/pki/ca.crt ]] || \
	   [[ ! -f /etc/openvpn/easyrsa3/pki/issued/antizapret-server.crt ]] || \
	   [[ ! -f /etc/openvpn/easyrsa3/pki/private/antizapret-server.key ]]; then
		rm -rf /etc/openvpn/easyrsa3/pki
		/usr/share/easy-rsa/easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 /usr/share/easy-rsa/easyrsa --batch --req-cn='AntiZapret CA' build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 /usr/share/easy-rsa/easyrsa --batch build-server-full 'antizapret-server' nopass
	fi

	EASYRSA_CRL_DAYS=3650 /usr/share/easy-rsa/easyrsa gen-crl
	chmod 755 /etc/openvpn/easyrsa3/pki
	chmod 644 /etc/openvpn/easyrsa3/pki/crl.pem
}

addOpenVPN(){
	setServerHost_FileName "$OPENVPN_HOST"

	if [[ ! -f /etc/openvpn/easyrsa3/pki/issued/"$CLIENT_NAME".crt ]] || \
	   [[ ! -f /etc/openvpn/easyrsa3/pki/private/"$CLIENT_NAME".key ]]; then
		askClientCertExpire
		echo
		EASYRSA_CERT_EXPIRE="$CLIENT_CERT_EXPIRE" /usr/share/easy-rsa/easyrsa --batch build-client-full "$CLIENT_NAME" nopass
	else
		echo
		echo 'Client with that name already exists! Please enter different name for new client'
		echo
		if [[ "$CLIENT_CERT_EXPIRE" != "0" ]]; then
			echo 'Current client certificate expiration period:'
			openssl x509 -in /etc/openvpn/easyrsa3/pki/issued/"$CLIENT_NAME".crt -noout -dates
			echo
			echo "Attention! Certificate renewal is NOT possible after 'notAfter' date"
			askClientCertExpire
			echo
			rm -f /etc/openvpn/easyrsa3/pki/issued/"$CLIENT_NAME".crt
			/usr/share/easy-rsa/easyrsa --batch --days="$CLIENT_CERT_EXPIRE" sign client "$CLIENT_NAME"
		fi
	fi

	CA_CERT="$(grep -A 999 'BEGIN CERTIFICATE' -- "/etc/openvpn/easyrsa3/pki/ca.crt")"
	CLIENT_CERT="$(grep -A 999 'BEGIN CERTIFICATE' -- "/etc/openvpn/easyrsa3/pki/issued/$CLIENT_NAME.crt")"
	CLIENT_KEY="$(cat -- "/etc/openvpn/easyrsa3/pki/private/$CLIENT_NAME.key")"
	if [[ ! "$CA_CERT" ]] || [[ ! "$CLIENT_CERT" ]] || [[ ! "$CLIENT_KEY" ]]; then
		echo 'Cannot load client keys!'
		exit 4
	fi

	render "/etc/openvpn/client/templates/antizapret-udp.conf" > "/root/antizapret/client/openvpn/antizapret-udp/$FILE_NAME-udp.ovpn"
	render "/etc/openvpn/client/templates/antizapret-tcp.conf" > "/root/antizapret/client/openvpn/antizapret-tcp/$FILE_NAME-tcp.ovpn"
	render "/etc/openvpn/client/templates/antizapret.conf" > "/root/antizapret/client/openvpn/antizapret/$FILE_NAME.ovpn"
	render "/etc/openvpn/client/templates/vpn-udp.conf" > "/root/antizapret/client/openvpn/vpn-udp/vpn-$FILE_NAME-udp.ovpn"
	render "/etc/openvpn/client/templates/vpn-tcp.conf" > "/root/antizapret/client/openvpn/vpn-tcp/vpn-$FILE_NAME-tcp.ovpn"
	render "/etc/openvpn/client/templates/vpn.conf" > "/root/antizapret/client/openvpn/vpn/vpn-$FILE_NAME.ovpn"

	echo "OpenVPN profile files (re)created for client '$CLIENT_NAME' at /root/antizapret/client/openvpn"
}

deleteOpenVPN(){
	setServerHost_FileName "$OPENVPN_HOST"
	echo

	/usr/share/easy-rsa/easyrsa --batch revoke "$CLIENT_NAME"
	EASYRSA_CRL_DAYS=3650 /usr/share/easy-rsa/easyrsa gen-crl
	chmod 755 /etc/openvpn/easyrsa3/pki
	chmod 644 /etc/openvpn/easyrsa3/pki/crl.pem

	rm -f /root/antizapret/client/openvpn/antizapret/"$FILE_NAME".ovpn
	rm -f /root/antizapret/client/openvpn/antizapret-udp/"$FILE_NAME"-udp.ovpn
	rm -f /root/antizapret/client/openvpn/antizapret-tcp/"$FILE_NAME"-tcp.ovpn
	rm -f /root/antizapret/client/openvpn/vpn/vpn-"$FILE_NAME".ovpn
	rm -f /root/antizapret/client/openvpn/vpn-udp/vpn-"$FILE_NAME"-udp.ovpn
	rm -f /root/antizapret/client/openvpn/vpn-tcp/vpn-"$FILE_NAME"-tcp.ovpn

	echo "kill $CLIENT_NAME" | socat - UNIX-CONNECT:/run/openvpn-server/antizapret-udp.sock &>/dev/null || true
	echo "kill $CLIENT_NAME" | socat - UNIX-CONNECT:/run/openvpn-server/antizapret-tcp.sock &>/dev/null || true
	echo "kill $CLIENT_NAME" | socat - UNIX-CONNECT:/run/openvpn-server/vpn-udp.sock &>/dev/null || true
	echo "kill $CLIENT_NAME" | socat - UNIX-CONNECT:/run/openvpn-server/vpn-tcp.sock &>/dev/null || true

	echo "OpenVPN client '$CLIENT_NAME' successfully deleted"
}

listOpenVPN(){
	[[ -n "$CLIENT_NAME" ]] && return
	echo
	echo 'OpenVPN client names:'
	ls /etc/openvpn/easyrsa3/pki/issued | sed 's/\.crt$//' | grep -v "^antizapret-server$" | sort
}

initWireGuard(){
	if [[ ! -f /etc/wireguard/key ]]; then
		echo
		echo 'Generating WireGuard/AmneziaWG server keys'
		PRIVATE_KEY="$(wg genkey)"
		PUBLIC_KEY="$(echo "${PRIVATE_KEY}" | wg pubkey)"
		echo "PRIVATE_KEY=${PRIVATE_KEY}
PUBLIC_KEY=${PUBLIC_KEY}" > /etc/wireguard/key
		render "/etc/wireguard/templates/antizapret.conf" > "/etc/wireguard/antizapret.conf"
		render "/etc/wireguard/templates/vpn.conf" > "/etc/wireguard/vpn.conf"
	fi
}

addWireGuard(){
	setServerHost_FileName "$WIREGUARD_HOST"
	echo

	source /etc/wireguard/key
	IPS="$(cat /etc/wireguard/ips)"

	# AntiZapret

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/antizapret.conf)"

	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
		echo 'Client (AntiZapret) with that name already exists! Please enter different name for new client'
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
		BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/antizapret.conf | sed 's/.*= *//' | cut -d'.' -f1-3 | head -n 1)"
		for i in {2..255}; do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
			if ! grep -q "$CLIENT_IP" /etc/wireguard/antizapret.conf; then
				break
			fi
			if [[ "$i" == 255 ]]; then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 5
			fi
		done
		echo "# Client = ${CLIENT_NAME}
# PrivateKey = ${CLIENT_PRIVATE_KEY}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${CLIENT_PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
" >> "/etc/wireguard/antizapret.conf"
		wg syncconf antizapret <(wg-quick strip antizapret 2>/dev/null) &>/dev/null || true
	fi

	render "/etc/wireguard/templates/antizapret-client-wg.conf" > "/root/antizapret/client/wireguard/antizapret/$FILE_NAME-wg.conf"
	render "/etc/wireguard/templates/antizapret-client-am.conf" > "/root/antizapret/client/amneziawg/antizapret/$FILE_NAME.conf"

	# VPN

	CLIENT_BLOCK="$(sed -n "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/ {p; /^AllowedIPs/q}" /etc/wireguard/vpn.conf)"
	if [[ -n "$CLIENT_BLOCK" ]]; then
		CLIENT_PRIVATE_KEY="$(echo "$CLIENT_BLOCK" | grep '# PrivateKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PUBLIC_KEY="$(echo "$CLIENT_BLOCK" | grep 'PublicKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_PRESHARED_KEY="$(echo "$CLIENT_BLOCK" | grep 'PresharedKey =' | cut -d '=' -f 2- | sed 's/ //g')"
		CLIENT_IP="$(echo "$CLIENT_BLOCK" | grep 'AllowedIPs =' | cut -d '=' -f 2- | sed 's/ //g' | cut -d '/' -f 1)"
		echo 'Client (VPN) with that name already exists! Please enter different name for new client'
	else
		CLIENT_PRIVATE_KEY="$(wg genkey)"
		CLIENT_PUBLIC_KEY="$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
		CLIENT_PRESHARED_KEY="$(wg genpsk)"
		BASE_CLIENT_IP="$(grep "^Address" /etc/wireguard/vpn.conf | sed 's/.*= *//' | cut -d'.' -f1-3 | head -n 1)"
		for i in {2..255}; do
			CLIENT_IP="${BASE_CLIENT_IP}.$i"
			if ! grep -q "$CLIENT_IP" /etc/wireguard/vpn.conf; then
				break
			fi
			if [[ "$i" == 255 ]]; then
				echo 'The WireGuard/AmneziaWG subnet can support only 253 clients!'
				exit 6
			fi
		done
		echo "# Client = ${CLIENT_NAME}
# PrivateKey = ${CLIENT_PRIVATE_KEY}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${CLIENT_PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
" >> "/etc/wireguard/vpn.conf"
		wg syncconf vpn <(wg-quick strip vpn 2>/dev/null) &>/dev/null || true
	fi

	render "/etc/wireguard/templates/vpn-client-wg.conf" > "/root/antizapret/client/wireguard/vpn/vpn-$FILE_NAME-wg.conf"
	render "/etc/wireguard/templates/vpn-client-am.conf" > "/root/antizapret/client/amneziawg/vpn/vpn-$FILE_NAME.conf"

	echo "WireGuard/AmneziaWG profile files (re)created for client '$CLIENT_NAME' at /root/antizapret/client/wireguard and /root/antizapret/client/amneziawg"
	echo
	echo 'Attention! If import fails, shorten profile filename to 32 chars (Windows) or 15 (Linux/Android/iOS), remove parentheses'
}

deleteWireGuard(){
	setServerHost_FileName "$WIREGUARD_HOST"
	echo

	if ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/antizapret.conf" && ! grep -q "# Client = ${CLIENT_NAME}" "/etc/wireguard/vpn.conf"; then
		echo "Failed to delete client '$CLIENT_NAME'! Please check if client exists"
		exit 7
	fi

	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/antizapret.conf
	sed -i "/^# Client = ${CLIENT_NAME}$/,/^AllowedIPs/d" /etc/wireguard/vpn.conf

	sed -i '/^$/N;/^\n$/D' /etc/wireguard/antizapret.conf
	sed -i '/^$/N;/^\n$/D' /etc/wireguard/vpn.conf

	rm -f /root/antizapret/client/{wireguard,amneziawg}/antizapret/"$FILE_NAME"-*.conf
	rm -f /root/antizapret/client/{wireguard,amneziawg}/vpn/vpn-"$FILE_NAME"-*.conf

	wg syncconf antizapret <(wg-quick strip antizapret 2>/dev/null) &>/dev/null || true
	wg syncconf vpn <(wg-quick strip vpn 2>/dev/null) &>/dev/null || true

	echo "WireGuard/AmneziaWG client '$CLIENT_NAME' successfully deleted"
}

listWireGuard(){
	[[ -n "$CLIENT_NAME" ]] && return
	echo
	echo 'WireGuard/AmneziaWG client names:'
	grep -hE "^# Client" /etc/wireguard/antizapret.conf /etc/wireguard/vpn.conf | cut -d '=' -f 2 | sed 's/ //g' | sort -u
}

initOpenConnect(){
	mkdir -p /etc/ocserv/certs
	if [[ ! -f /etc/ocserv/certs/server-cert.pem ]] || \
	   [[ ! -f /etc/ocserv/certs/server-key.pem ]]; then
		local CERT_CN CERT_ALT
		if [[ -n "$OPENCONNECT_HOST" ]]; then
			CERT_CN="$OPENCONNECT_HOST"
			CERT_ALT="DNS:$OPENCONNECT_HOST"
		else
			CERT_CN="$SERVER_IP"
			CERT_ALT="IP:$SERVER_IP"
		fi
		echo
		echo "Generating OpenConnect server certificate for '$CERT_CN'"
		rm -f /etc/ocserv/certs/server-cert.pem
		rm -f /etc/ocserv/certs/server-key.pem
		openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
			-keyout /etc/ocserv/certs/server-key.pem \
			-out /etc/ocserv/certs/server-cert.pem \
			-subj "/CN=$CERT_CN" \
			-addext "subjectAltName=$CERT_ALT" \
			-addext "keyUsage=digitalSignature,keyEncipherment" \
			-addext "extendedKeyUsage=serverAuth" &>/dev/null
	fi

	touch /etc/ocserv/antizapret.passwd
	touch /etc/ocserv/vpn.passwd
	touch /etc/ocserv/secrets

	chmod 700 /etc/ocserv/certs
	chmod 600 /etc/ocserv/certs/server-key.pem
	chmod 644 /etc/ocserv/certs/server-cert.pem
	chmod 600 /etc/ocserv/antizapret.passwd
	chmod 600 /etc/ocserv/vpn.passwd
	chmod 600 /etc/ocserv/secrets

	CERT_PIN="pin-sha256:$(openssl x509 -in /etc/ocserv/certs/server-cert.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)"
}

addOpenConnect(){
	setServerHost_FileName "$OPENCONNECT_HOST"
	echo

	CLIENT_PASSWORD="$(grep -m 1 "^${CLIENT_NAME}:" /etc/ocserv/secrets | cut -d ':' -f 2- || true)"

	if [[ -n "$CLIENT_PASSWORD" ]]; then
		echo 'Client (OpenConnect) with that name already exists! Please enter different name for new client'
	else
		CLIENT_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)"
	fi

	PASSWORD_HASH="$(openssl passwd -6 "$CLIENT_PASSWORD")"

	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/antizapret.passwd
	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/vpn.passwd
	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/secrets

	echo "${CLIENT_NAME}:*:${PASSWORD_HASH}" >> /etc/ocserv/antizapret.passwd
	echo "${CLIENT_NAME}:*:${PASSWORD_HASH}" >> /etc/ocserv/vpn.passwd
	echo "${CLIENT_NAME}:${CLIENT_PASSWORD}" >> /etc/ocserv/secrets

	render "/etc/ocserv/templates/antizapret-client.conf" > "/root/antizapret/client/openconnect/antizapret/$FILE_NAME.txt"
	render "/etc/ocserv/templates/vpn-client.conf" > "/root/antizapret/client/openconnect/vpn/vpn-$FILE_NAME.txt"

	echo "OpenConnect profile files (re)created for client '$CLIENT_NAME' at /root/antizapret/client/openconnect"
}

deleteOpenConnect(){
	setServerHost_FileName "$OPENCONNECT_HOST"
	echo

	if ! grep -q "^${CLIENT_NAME}:" /etc/ocserv/secrets; then
		echo "Failed to delete client '$CLIENT_NAME'! Please check if client exists"
		exit 10
	fi

	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/antizapret.passwd
	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/vpn.passwd
	sed -i "/^${CLIENT_NAME}:/d" /etc/ocserv/secrets

	rm -f /root/antizapret/client/openconnect/antizapret/"$FILE_NAME".txt
	rm -f /root/antizapret/client/openconnect/vpn/vpn-"$FILE_NAME".txt

	occtl -s /run/occtl-antizapret.socket disconnect user "$CLIENT_NAME" &>/dev/null || true
	occtl -s /run/occtl-vpn.socket disconnect user "$CLIENT_NAME" &>/dev/null || true

	echo "OpenConnect client '$CLIENT_NAME' successfully deleted"
}

listOpenConnect(){
	[[ -n "$CLIENT_NAME" ]] && return
	[[ -f /etc/ocserv/secrets ]] || return 0
	echo
	echo 'OpenConnect client names:'
	cut -d ':' -f 1 /etc/ocserv/secrets | sort -u
}

recreate(){
	echo

	rm -rf /root/antizapret/client
	mkdir -p /root/antizapret/client/{openvpn/{antizapret,antizapret-tcp,antizapret-udp,vpn,vpn-tcp,vpn-udp},wireguard/{antizapret,vpn},amneziawg/{antizapret,vpn},openconnect/{antizapret,vpn}}

	# OpenVPN
	if [[ -d /etc/openvpn/easyrsa3/pki/issued ]]; then
		initOpenVPN
		CLIENT_CERT_EXPIRE=0
		ls /etc/openvpn/easyrsa3/pki/issued | sed 's/\.crt$//' | grep -v "^antizapret-server$" | sort | while read -r CLIENT_NAME; do
			if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
				addOpenVPN >/dev/null
				echo "OpenVPN profile files recreated for client '$CLIENT_NAME'"
			else
				echo "OpenVPN client name '$CLIENT_NAME' is invalid! No profile files recreated"
			fi
		done
	else
		CLIENT_NAME=antizapret-client
		CLIENT_CERT_EXPIRE=3650
		echo "Creating OpenVPN server keys and first OpenVPN client: '$CLIENT_NAME'"
		initOpenVPN
		addOpenVPN >/dev/null
	fi

	# WireGuard/AmneziaWG
	if [[ -f /etc/wireguard/key && -f /etc/wireguard/antizapret.conf && -f /etc/wireguard/vpn.conf ]]; then
		grep -hE "^# Client" /etc/wireguard/antizapret.conf /etc/wireguard/vpn.conf | cut -d '=' -f 2 | sed 's/ //g' | sort -u | while read -r CLIENT_NAME; do
			if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
				addWireGuard >/dev/null
				echo "WireGuard/AmneziaWG profile files recreated for client '$CLIENT_NAME'"
			else
				echo "WireGuard/AmneziaWG client name '$CLIENT_NAME' is invalid! No profile files recreated"
			fi
		done
	else
		CLIENT_NAME=antizapret-client
		echo "Creating WireGuard/AmneziaWG server keys and first WireGuard/AmneziaWG client: '$CLIENT_NAME'"
		initWireGuard
		addWireGuard >/dev/null
	fi

	# OpenConnect
	if [[ -d /etc/ocserv/templates ]]; then
		if [[ -s /etc/ocserv/secrets ]]; then
			initOpenConnect
			cut -d ':' -f 1 /etc/ocserv/secrets | sort -u | while read -r CLIENT_NAME; do
				if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
					addOpenConnect >/dev/null
					echo "OpenConnect profile files recreated for client '$CLIENT_NAME'"
				else
					echo "OpenConnect client name '$CLIENT_NAME' is invalid! No profile files recreated"
				fi
			done
		else
			CLIENT_NAME=antizapret-client
			echo "Creating OpenConnect server certificate and first OpenConnect client: '$CLIENT_NAME'"
			initOpenConnect
			addOpenConnect >/dev/null
		fi
	fi
}

backup(){
	echo

	rm -rf /root/antizapret/backup
	mkdir -p /root/antizapret/backup/wireguard
	mkdir -p /root/antizapret/backup/config
	mkdir -p /root/antizapret/backup/knot-resolver
	mkdir -p /root/antizapret/backup/custom
	mkdir -p /root/antizapret/backup/ocserv

	cp -r /etc/openvpn/easyrsa3 /root/antizapret/backup
	cp -r /etc/wireguard/antizapret.conf /root/antizapret/backup/wireguard
	cp -r /etc/wireguard/vpn.conf /root/antizapret/backup/wireguard
	cp -r /etc/wireguard/key /root/antizapret/backup/wireguard
	cp -r /root/antizapret/config/*.txt /root/antizapret/backup/config || true
	cp -r /etc/knot-resolver/*.lua /root/antizapret/backup/knot-resolver || true
	cp -r /root/antizapret/custom*.sh /root/antizapret/backup/custom || true
	cp -r /etc/ocserv/certs /root/antizapret/backup/ocserv || true
	cp -r /etc/ocserv/antizapret.passwd /root/antizapret/backup/ocserv || true
	cp -r /etc/ocserv/vpn.passwd /root/antizapret/backup/ocserv || true
	cp -r /etc/ocserv/secrets /root/antizapret/backup/ocserv || true

	BACKUP_FILE="/root/antizapret/backup-$SERVER_IP.tar.gz"
	tar -czf $BACKUP_FILE -C /root/antizapret/backup easyrsa3 wireguard config knot-resolver custom ocserv
	tar -tzf $BACKUP_FILE >/dev/null

	rm -rf /root/antizapret/backup

	echo "Backup configuration and clients (re)created at $BACKUP_FILE"
}

restore(){
	echo

	if [[ -e /root/backup*.tar.gz ]]; then
		rm -rf /root/easyrsa3
		rm -rf /root/wireguard
		rm -rf /root/config
		rm -rf /root/knot-resolver
		rm -rf /root/custom
		rm -rf /root/ocserv
	fi

	tar -xzf /root/backup*.tar.gz -C /root || true
	rm -f /root/backup*.tar.gz || true

	if [[ ! -d /root/easyrsa3 && ! -d /root/wireguard && ! -d /root/config && ! -d /root/knot-resolver && ! -d /root/custom ]]; then
		echo 'Backup not found! Upload backup*.tar.gz to /root, or extract folders to /root: easyrsa3, wireguard, config, knot-resolver, custom'
		exit 8
	fi

	if [[ -d /root/easyrsa3/pki ]]; then
		rm -rf /etc/openvpn/easyrsa3/*
	fi

	cp -r /root/easyrsa3 /etc/openvpn/ || true
	cp /root/wireguard/* /etc/wireguard/ || true
	cp /root/config/* /root/antizapret/config/ || true
	cp /root/knot-resolver/* /etc/knot-resolver/ || true
	cp /root/custom/* /root/antizapret/ || true
	mkdir -p /etc/ocserv
	cp -r /root/ocserv/* /etc/ocserv/ || true

	rm -rf /root/easyrsa3
	rm -rf /root/wireguard
	rm -rf /root/config
	rm -rf /root/knot-resolver
	rm -rf /root/custom
	rm -rf /root/ocserv

	./doall.sh ip
	initWireGuard
	initOpenVPN
	recreate

	echo "Configuration and clients restored from backup"
	reboot
}

if ! [[ "$OPTION" =~ ^([1-9]|1[0-2])$ ]]; then
	echo
	echo 'Please choose option:'
	echo '    1) OpenVPN - Add client/Renew client certificate'
	echo '    2) OpenVPN - Delete client'
	echo '    3) OpenVPN - List clients'
	echo '    4) WireGuard/AmneziaWG - Add client'
	echo '    5) WireGuard/AmneziaWG - Delete client'
	echo '    6) WireGuard/AmneziaWG - List clients'
	echo '    7) (Re)create client profile files'
	echo '    8) Backup configuration and clients'
	echo '    9) Restore configuration and clients from backup'
	echo '   10) OpenConnect - Add client/Change client password'
	echo '   11) OpenConnect - Delete client'
	echo '   12) OpenConnect - List clients'
	until [[ "$OPTION" =~ ^([1-9]|1[0-2])$ ]]; do
		read -rp 'Option choice [1-12]: ' -e OPTION
	done
fi

case "$OPTION" in
	1)
		echo "OpenVPN - Add client/Renew client certificate $CLIENT_NAME $CLIENT_CERT_EXPIRE"
		askClientName
		initOpenVPN
		addOpenVPN
		;;
	2)
		echo "OpenVPN - Delete client $CLIENT_NAME"
		listOpenVPN
		askClientName
		deleteOpenVPN
		;;
	3)
		echo 'OpenVPN - List clients'
		listOpenVPN
		;;
	4)
		echo "WireGuard/AmneziaWG - Add client $CLIENT_NAME"
		askClientName
		initWireGuard
		addWireGuard
		;;
	5)
		echo "WireGuard/AmneziaWG - Delete client $CLIENT_NAME"
		listWireGuard
		askClientName
		deleteWireGuard
		;;
	6)
		echo 'WireGuard/AmneziaWG - List clients'
		listWireGuard
		;;
	7)
		echo '(Re)create client profile files'
		recreate
		;;
	8)
		echo 'Backup configuration and clients'
		backup
		;;
	9)
		echo 'Restore configuration and clients from backup'
		restore
		;;
	10)
		echo "OpenConnect - Add client/Change client password $CLIENT_NAME"
		askClientName
		initOpenConnect
		mkdir -p /root/antizapret/client/openconnect/antizapret
		mkdir -p /root/antizapret/client/openconnect/vpn
		addOpenConnect
		;;
	11)
		echo "OpenConnect - Delete client $CLIENT_NAME"
		listOpenConnect
		askClientName
		deleteOpenConnect
		;;
	12)
		echo 'OpenConnect - List clients'
		listOpenConnect
		;;
esac
exit 0
