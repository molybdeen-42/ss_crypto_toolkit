#!/usr/bin/env bash

set -uo pipefail

targets_file="$1"

# Check voor het bestaan van de file met scan targets
if [[ ! -s "$targets_file" ]]; then
	echo "[!] De file met targets $targets_file is leeg of bestaat niet"
	exit 1
fi

# Declaren van target host en port variable length arrays
hosts=()
ports=()

# Vindt het host en de port gegeven een line met structuur host:port en voegt hen toe aan hosts en ports
get_host_and_port() {
	local line=$1

	# Maken van regex
	local hostname_regex='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
	local ipv4_regex='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
	local port_regex='^[1-9][0-9]{0,4}$'

	# Definieren van lokale variabelen
	local host="${line%:*}"
	local port="${line##*:}"

	# Matcht de regex waaraan de line dient te voldoen
	if [[ "$line" != *:* || ! "$port" =~ $port_regex ]] ||
		(( port > 65535 )); then
		echo "[!] Ongeldig doel: $line (geldig: \"host:port\")" >&2
		exit 1
	fi

	# Check voor geldigheid van hostname of ipv4 adres
	if [[ "$host" =~ ^[0-9.]+$ && "$host" == *.* ]]; then
		if [[ ! "$host" =~ $ipv4_regex ]]; then
			echo "[!] Ongeldig ipv4 adres: $line" >&2
			exit 1
		fi
	elif [[ ! "$host" =~ $hostname_regex || ${#host} -gt 253 ]]; then
		echo "[!] Ongeldige hostname: $line" >&2
		exit 1
	fi

	# Toevoegen van de gevonden host en port
	hosts+=("$host")
	ports+=("$port")
}

echo ""
echo "[+] Lijst met host adressen in $targets_file verwerken"

# Loop voor het verwerken van de targets file naar input in de variable length arrays
while IFS= read -r line || [[ -n "$line" ]]; do
	[[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

	get_host_and_port "$line"
done <"$targets_file"
