#!/bin/bash
# Генерирует файлы маршрутов для Keenetic (AmneziaWG) и OpenVPN
# из списка IP-адресов config/include-ips-custom.txt
#
# Использование: ./parse-custom.sh [каталог]
#   каталог - где лежит папка config и куда будут записаны результаты
#             (по умолчанию - каталог скрипта)
#
# Переменные окружения:
#   GATEWAY - шлюз для маршрутов Keenetic (по умолчанию 10.29.8.1,
#             либо <CLIENT_IP>.29.8.1 при ALTERNATIVE_CLIENT_IP=y в файле setup)

set -e
export LC_ALL=C

handle_error() {
	echo -e "\e[1;31mError at line $1: $2\e[0m" >&2
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
cd "$DIR"

INPUT=config/include-ips-custom.txt
KEENETIC_OUT=result/keenetic-awg-routes-custom.txt
OPENVPN_OUT=result/openvpn-routes-custom.txt

if [[ ! -f "$INPUT" ]]; then
	echo "File not found: $DIR/$INPUT" >&2
	exit 1
fi

if [[ -z "$GATEWAY" ]]; then
	IP=10
	if [[ -f setup ]]; then
		ALTERNATIVE_CLIENT_IP="$(sed -n 's/^ALTERNATIVE_CLIENT_IP=//p' setup | tr -d "\"'\r")"
		CLIENT_IP="$(sed -n 's/^CLIENT_IP=//p' setup | tr -d "\"'\r")"
		[[ "$ALTERNATIVE_CLIENT_IP" == 'y' ]] && IP="${CLIENT_IP:-172}"
	fi
	GATEWAY="$IP.29.8.1"
fi

sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' "$INPUT" | sort -u \
| awk -F'[/.]' 'NF==5 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 && $5>=1 && $5<=32 {print}' \
| awk -F'/' -v gw="$GATEWAY" -v keenetic="$KEENETIC_OUT" -v openvpn="$OPENVPN_OUT" '
	BEGIN { printf "" > keenetic; printf "" > openvpn }
	{
		net = $1; bits = $2
		mask = ""
		for (i = 0; i < 4; i++) {
			b = bits - i * 8
			if (b >= 8) o = 255
			else if (b <= 0) o = 0
			else o = 256 - 2 ^ (8 - b)
			mask = mask (i ? "." : "") o
		}
		print "route ADD " net " MASK " mask " " gw > keenetic
		print "route " net " " mask > openvpn
	}'

echo "$(wc -l < "$KEENETIC_OUT") - $KEENETIC_OUT"
echo "$(wc -l < "$OPENVPN_OUT") - $OPENVPN_OUT"
