#!/bin/bash
set -e
export LC_ALL=C

# Обработка ошибок
handle_error() {
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo -e "\e[1;31mError at line $1: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

REPO=https://raw.githubusercontent.com/TripleA150/RBP/refs/heads/main/setup/root/antizapret/config

FILES=(
	allow-ips.txt
	custom-block.txt
	deny-ips.txt
	drop-ips.txt
	exclude-adblock-hosts.txt
	exclude-hosts.txt
	exclude-ips.txt
	forward-ips.txt
	include-adblock-hosts.txt
	include-hosts.txt
	include-ips.txt
	remove-hosts.txt
	deny-rpz.txt
	deny2-rpz.txt
)

cd /root/antizapret
mkdir -p config temp result

TMP_DIR="$(mktemp -d /root/antizapret/.config-update.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

URLS=()
for FILE in "${FILES[@]}"; do
	URLS+=("$REPO/$FILE")
done

if ! curl -fL --parallel --connect-timeout 30 --max-time 300 --output-dir "$TMP_DIR" --remote-name-all "${URLS[@]}"; then
	echo 'Failed to download config files! Keeping current config files'
	exit 2
fi

for FILE in "${FILES[@]}"; do
	if [[ ! -s "$TMP_DIR/$FILE" ]]; then
		echo "Downloaded $FILE is empty! Keeping current config files"
		exit 3
	fi
done

for FILE in "${FILES[@]}"; do
	mv -f "$TMP_DIR/$FILE" "config/$FILE"
done

sed -E 's/[\r[:space:]]+//g; /^[[:punct:]]/d; /^$/d' config/custom-block.txt | sort -u > temp/custom-block.txt
echo "$(wc -l < temp/custom-block.txt) - custom-block.txt"
echo -e '$TTL 10800\n@ SOA . . (1 1 1 1 10800)' > result/custom.rpz
sed 's/$/ CNAME ./; p; s/^/*./' temp/custom-block.txt >> result/custom.rpz

if [[ -f result/custom.rpz ]] && ! diff -q result/custom.rpz /etc/knot-resolver/custom.rpz; then
	cp -f result/custom.rpz /etc/knot-resolver/custom.rpz.tmp
	mv -f /etc/knot-resolver/custom.rpz.tmp /etc/knot-resolver/custom.rpz
	sleep 5
fi

exit 0
