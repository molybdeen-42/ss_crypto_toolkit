#!/usr/bin/env bash

set -euo pipefail

targets_file="$1"

# Check voor het bestaan van de file met scan targets
if [[ ! -s "$targets_file" ]]; then
	echo "[!] De file met targets $targets_file is leeg of bestaat niet"
	exit 1
fi

# Declaren van target ip en port variable length arrays
ips=()
ports=()

# Vindt het ip en de port gegeven een line met structuur ip:port en voegt hen toe aan ips en ports
get_ip_and_port() {
	local line=$1
	local line_regex='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]):[0-9]{1,5}$'

	# Matcht de regex waaraan de line dient te voldoen
	if [[ ! "$line" =~ $line_regex ]]; then
		echo "[!] Ongeldige combinatie van ip adres en port: $line in $targets_file (geldig: \"ip:port\")" >&2
		exit 1
	fi

	# Definieren van lokale variabelen
	local ip="${line%:*}"
	local port="${line##*:}"

	# Controle of de port daadwerkelijk een geldige port is (1 < port < 65536)
	if [[ "$port" -gt 65535 ]] || [[ "$port" -lt 1 ]]; then
		echo "[!] Ongeldige port: $line in $targets_file" >&2
		exit 1
	fi

	# Toevoegen van de gevonden ip en port
	ips+=("$ip")
	ports+=("$port")
}

echo ""
echo "[+] Lijst met ip adressen in $targets_file verwerken"

# Loop voor het verwerken van de targets file naar input in de variable length arrays
while IFS= read -r line; do
	[[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

	get_ip_and_port "$line"
done <"$targets_file"
