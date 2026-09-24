#!/bin/bash
#
# Патч для обхода блокировки протокола OpenVPN
# Работает только для UDP соединений
#
# chmod +x patch-openvpn.sh && ./patch-openvpn.sh [1-4]
#
# Дополнительные параметры (переменные окружения):
#   JUNK_PACKETS=150  - сколько мусорных пакетов отправлять на каждый пакет начала соединения
#   JUNK_BEFORE=3     - сколько из них отправлять до настоящего пакета в режиме Strong,
#                       остальные отправляются после. Большие значения ухудшают доставку
#                       настоящего пакета на роутеры и через сети с ограничением скорости
#   Пример: JUNK_BEFORE=5 ./patch-openvpn.sh 3
#
set -e
export LC_ALL=C

handle_error() {
	echo "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

SRC_DIR=/usr/local/src/openvpn
MARKER='antizapret-openvpn-patch'
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Заменяет тело link_socket_write_udp() в socket.h на версию с патчем
# $1 - путь к socket.h, $2 - строка C-кода, задающая error_free,
# $3 - всего мусорных пакетов, $4 - сколько из них отправлять до настоящего пакета (режим Strong)
patch_source() {
	local file="$1" code
	code="$(cat <<'EOF'
link_socket_write_udp(struct link_socket *sock,
                      struct buffer *buf,
                      struct link_socket_actual *to)
{
	/* antizapret-openvpn-patch */
#ifdef _WIN32
#define AZ_LINK_WRITE(b) link_socket_write_win32(sock, (b), to)
#else
#define AZ_LINK_WRITE(b) link_socket_write_udp_posix(sock, (b), to)
#endif
	/* 7 - P_CONTROL_HARD_RESET_CLIENT_V2, 8 - P_CONTROL_HARD_RESET_SERVER_V2, 10 - P_CONTROL_HARD_RESET_CLIENT_V3 */
	const int opcode = BLEN(buf) > 0 ? (*BPTR(buf) >> 3) : 0;
	if (opcode == 7 || opcode == 8 || opcode == 10)
	{
		@PATCH_MODE@
		const int junk_total = @JUNK_TOTAL@;
		/*
		 * Strong: небольшая часть мусора уходит до настоящего пакета, остальное после.
		 * Если отправить весь мусор до настоящего пакета, то при маленьком буфере приёма
		 * или ограничении скорости на пути настоящий пакет теряется в хвосте очереди.
		 * Error-Free: настоящий пакет всегда уходит первым.
		 */
		const int junk_before = error_free ? 0 : @JUNK_BEFORE@;
		const int buffer_len = BLEN(buf);
		struct buffer junk = alloc_buf(buffer_len + 81);
		ssize_t buffer_sent;
		int n = 0;
		/* Каждый мусорный пакет уникален: случайные длина и содержимое */
#define AZ_SEND_JUNK(res) do { \
			const int junk_len = buffer_len + 1 + (int)(random() % 80); \
			buf_init(&junk, 0); \
			uint8_t *data = buf_write_alloc(&junk, junk_len); \
			ASSERT(data); \
			int k; \
			if (error_free) \
			{ \
				/* Копия пакета с opcode 5 (P_ACK_V1), key_id 0 и случайным хвостом */ \
				memcpy(data, BPTR(buf), buffer_len); \
				data[0] = (uint8_t)40; \
				k = buffer_len; \
			} \
			else \
			{ \
				/* Случайные данные с несуществующим opcode (0 или 12-31) */ \
				uint8_t first_byte; \
				do \
				{ \
					first_byte = (uint8_t)(random() & 0xff); \
				} while ((first_byte >> 3) >= 1 && (first_byte >> 3) <= 11); \
				data[0] = first_byte; \
				k = 1; \
			} \
			for (; k < junk_len; k++) \
			{ \
				data[k] = (uint8_t)(random() & 0xff); \
			} \
			res = (ssize_t)AZ_LINK_WRITE(&junk); \
		} while (0)
		/* При ошибке отправки (например, переполнен буфер сокета) мусор больше не шлём */
		for (; n < junk_before; n++)
		{
			ssize_t junk_sent;
			AZ_SEND_JUNK(junk_sent);
			if (junk_sent < 0)
			{
				break;
			}
		}
		buffer_sent = (ssize_t)AZ_LINK_WRITE(buf);
		if (buffer_sent >= 0)
		{
			for (n = junk_before; n < junk_total; n++)
			{
				ssize_t junk_sent;
				AZ_SEND_JUNK(junk_sent);
				if (junk_sent < 0)
				{
					break;
				}
			}
		}
#undef AZ_SEND_JUNK
		free_buf(&junk);
		return buffer_sent;
	}
	return AZ_LINK_WRITE(buf);
#undef AZ_LINK_WRITE
}
EOF
)"
	# Не ${code/.../...}: в bash 5.2+ символ & в замене подставляет найденный текст
	code="${code%%@PATCH_MODE@*}${2}${code#*@PATCH_MODE@}"
	code="${code%%@JUNK_TOTAL@*}${3}${code#*@JUNK_TOTAL@}"
	code="${code%%@JUNK_BEFORE@*}${4}${code#*@JUNK_BEFORE@}"
	# Заменяем всё от сигнатуры функции до закрывающей скобки в начале строки
	CODE="$code" awk '
		!done && /^link_socket_write_udp\(struct link_socket \*sock/ { skip = 1; print ENVIRON["CODE"]; next }
		skip { if ($0 ~ /^}/) { skip = 0; done = 1 } next }
		{ print }
		END { if (!done) exit 1 }
	' "$file" > "$file.patched" || {
		rm -f "$file.patched"
		echo "Function link_socket_write_udp() not found in $file"
		return 1
	}
	mv -f "$file.patched" "$file"
	if [[ "$(grep -c "$MARKER" "$file")" != '1' ]]; then
		echo "Failed to patch $file"
		return 1
	fi
}

JUNK_PACKETS="${JUNK_PACKETS:-150}"
JUNK_BEFORE="${JUNK_BEFORE:-3}"
if [[ ! "$JUNK_PACKETS" =~ ^[0-9]{1,4}$ || ! "$JUNK_BEFORE" =~ ^[0-9]{1,4}$ ]] || (( JUNK_BEFORE > JUNK_PACKETS )); then
	echo 'Error: JUNK_PACKETS and JUNK_BEFORE must be numbers, JUNK_BEFORE <= JUNK_PACKETS'
	exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
	echo 'Error: You need to run this as root!'
	exit 2
fi

if [[ "$1" =~ ^[1-4]$ ]]; then
	ALGORITHM="$1"
else
	echo
	echo 'Choose anti-censorship patch for OpenVPN (UDP only):'
	echo '    1) None        - Do not install anti-censorship patch, or remove if already installed'
	echo '    2) Random      - Recommended by default, randomly selects Strong or Error-Free'
	echo '    3) Strong      - Better protocol masking'
	echo '    4) Error-Free  - Use if Strong patch causes connection error, recommended for routers'
	until [[ "$ALGORITHM" =~ ^[1-4]$ ]]; do
		read -rp 'Version choice [1-4]: ' -e -i 2 ALGORITHM
	done
fi

export DEBIAN_FRONTEND=noninteractive

if [[ "$ALGORITHM" == '1' ]]; then
	if [[ -d "$SRC_DIR" ]]; then
		make -C "$SRC_DIR" uninstall || true
		rm -rf "$SRC_DIR"
		apt-get update
		apt-get dist-upgrade "${APT_OPTS[@]}"
		apt-get install "${APT_OPTS[@]}" openvpn
		apt-get autoremove --purge -y
		apt-get clean
		systemctl daemon-reload
		systemctl restart 'openvpn-server@*.service'
		echo
		echo 'OpenVPN patch remove successfully!'
		exit 0
	fi
	echo
	echo 'OpenVPN patch not installed!'
	exit 0
fi

if [[ "$ALGORITHM" == '2' ]]; then
	PATCH_MODE='const _Bool error_free = random() & 1;'
elif [[ "$ALGORITHM" == '3' ]]; then
	PATCH_MODE='const _Bool error_free = 0;'
else
	PATCH_MODE='const _Bool error_free = 1;'
fi

apt-get update
apt-get dist-upgrade "${APT_OPTS[@]}"
apt-get install "${APT_OPTS[@]}" openvpn curl tar build-essential pkg-config libssl-dev libsystemd-dev libnl-genl-3-dev libcap-ng-dev
apt-get autoremove --purge -y
apt-get clean

# Версию берём из пакетного бинарника, а не из /usr/local/sbin/openvpn
VERSION="$(/usr/sbin/openvpn --version | awk 'NR == 1 { print $2 }')"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?(_[a-z0-9]+)?$ ]]; then
	echo "Can't detect OpenVPN version: '$VERSION'"
	exit 3
fi

# Скачиваем и собираем во временном каталоге, чтобы при ошибке не остаться без рабочей версии
BUILD_DIR="$(mktemp -d /usr/local/src/openvpn.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT
curl -fL --connect-timeout 30 --retry 3 "https://build.openvpn.net/downloads/releases/openvpn-$VERSION.tar.gz" -o "$BUILD_DIR.tar.gz" || \
curl -fL --connect-timeout 30 --retry 3 "https://github.com/OpenVPN/openvpn/releases/download/v$VERSION/openvpn-$VERSION.tar.gz" -o "$BUILD_DIR.tar.gz"
tar --strip-components=1 -xzf "$BUILD_DIR.tar.gz" -C "$BUILD_DIR"
rm -f "$BUILD_DIR.tar.gz"

patch_source "$BUILD_DIR/src/openvpn/socket.h" "$PATCH_MODE" "$((10#$JUNK_PACKETS))" "$((10#$JUNK_BEFORE))"

(
	cd "$BUILD_DIR"
	chmod +x ./configure
	./configure \
		--enable-systemd \
		--enable-dco \
		--enable-comp-stub \
		--enable-small \
		--enable-port-share \
		--disable-static \
		--disable-debug \
		--disable-dns-updown-by-default \
		--disable-lzo \
		--disable-lz4 \
		--disable-ofb-cfb \
		--disable-plugins \
		--disable-fragment \
		--disable-unit-tests \
		--disable-ntlm \
		--disable-wolfssl-options-h \
		--disable-pam-dlopen \
		--disable-plugin-auth-pam \
		--disable-pkcs11 \
		--disable-selinux \
		--disable-plugin-down-root
	make -j"$(nproc)"
	./src/openvpn/openvpn --version | head -n 1
)

# Сборка прошла успешно - заменяем ранее установленную версию
if [[ -d "$SRC_DIR" ]]; then
	make -C "$SRC_DIR" uninstall || true
	rm -rf "$SRC_DIR"
fi
mv "$BUILD_DIR" "$SRC_DIR"
trap - EXIT
make -C "$SRC_DIR" install

systemctl daemon-reload
systemctl restart 'openvpn-server@*.service'
echo
echo 'OpenVPN patch installed successfully!'
exit 0
