#!/usr/bin/env bash

set -euo pipefail

start_dir="$(pwd)"
script_dir="$(cd "$(dirname "$0")" && pwd)"
base_dir="$(dirname "$script_dir")"

cd "$start_dir"

source "$base_dir/scanning/arguments.sh"

if [[ "$output" == "" ]] || [[ ! "$output" =~ ^[A-Za-z0-9._-]+$ ]]; then
	echo "[!] Geen naam voor output directory gespecificeerd, het script wordt gesloten. (Gebruik: testssl_scan.sh -o \"voorbeeld_directory\")"
	exit 1
fi

if [[ "$force" == true ]]; then
	echo "[+] Force flag gezet"
fi

testssl_log_dir="$base_dir/results/testssl/$output"
targets_file="$base_dir/targets/testssl_targets.txt"

echo ""

if [[ ! -d $testssl_log_dir ]]; then
	echo "[+] Log directory $testssl_log_dir wordt aangemaakt"
	mkdir -p "$testssl_log_dir"
else
	echo "[+] Logging directory $testssl_log_dir bestaat al"
fi

if [[ ! -d $testssl_log_dir ]]; then
	echo "[!] Fout bij het maken van $testssl_log_dir" >&2
	exit 1
fi

if [[ ! -s "$targets_file" ]]; then
	echo "[!] De file met targets $targets_file is leeg of bestaat niet"
	exit 1
fi

ips=()
ports=()

get_ip_and_port() {
	local line=$1
	local line_regex='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]):[0-9]{1,5}$'

	if [[ ! "$line" =~ $line_regex ]]; then
		echo "[!] Ongeldige combinatie van ip adres en port: $line in $targets_file (geldig: \"ip:port\")" >&2
		exit 1
	fi

	local ip="${line%:*}"
	local port="${line##*:}"

	if [[ "$port" -gt 65535 ]] || [[ "$port" -lt 1 ]]; then
		echo "[!] Ongeldige port: $line in $targets_file" >&2
		exit 1
	fi

	ips+=("$ip")
	ports+=("$port")
}

echo ""
echo "[+] Lijst met ip adressen in $targets_file verwerken"

while IFS= read -r line; do
	[[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

	get_ip_and_port "$line"
done <"$targets_file"

echo ""
echo "[+] Starten van testssl.sh scan, circa 2 minuten per target"

for index in "${!ips[@]}"; do
	doscan=0
	ip="${ips[$index]}"
	port="${ports[$index]}"

	newest_occurrence="$(find "$testssl_log_dir" -name "${ip}_$port.json" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d ' ' -f2-)"

	echo ""

	

	if [[ -n "$newest_occurrence" ]] && [[ "$targets_file" -nt "$newest_occurrence" ]] ; then
		echo "[+] Log aanwezig in $newest_occurrence, maar $targets_file is aangepast na de generatie van deze log. De scan wordt daarom alsnog uitgevoerd"
		rm "$newest_occurrence"

		doscan=1
	fi

	if [[ -n "$newest_occurrence" ]] && [[ $(date -r "$newest_occurrence" +%s) -lt $(date -d "30 days ago" +%s) ]]; then
		echo "[+] Log aanwezig in $newest_occurrence, maar deze log is ouder dan 30 dagen. De scan wordt daarom alsnog uitgevoerd"

		doscan=1
	fi

	if [[ -z "$newest_occurrence" ]]; then
		if [[ "$doscan" -eq 1 ]]; then
			rm "$newest_occurrence"

			if [[ -f "$newest_occurrence" ]]; then
				echo "[!] Fout bij het verwijderen van oude log. Scan voor $ip:$port wordt overgeslagen"
				continue
			fi
		else
			doscan=1
		fi
	fi

	if [[ "$force" == true ]]; then
		if [[ -f "$newest_occurrence" ]]; then
			rm "$newest_occurrence"

			if [[ -f "$newest_occurrence" ]]; then
				echo "[!] Fout bij het verwijderen van oude log. Scan voor $ip:$port wordt overgeslagen"
				continue
			fi
		fi

		doscan=1
	fi

	if [[ "$doscan" -eq 1 ]]; then
		echo "[+] Scan met testssl.sh uitvoeren voor $ip:$port, resultaat in $testssl_log_dir/${ip}_$port.json..."
		if ! /usr/bin/env bash "$base_dir/crypto_tools/testssl.sh-3.2.4/testssl.sh" --jsonfile "$testssl_log_dir/${ip}_$port.json" "$ip:$port" &>/dev/null; then
			echo "[!] Scan mislukt voor $ip:$port" >&2
		fi
	else
		echo "[!] Scan voor $ip:$port wordt overgeslagen doordat er nog een recente testssl.sh log bestaat, path: $newest_occurrence" >&2
	fi
done

echo ""
echo "[+] Scan met testssl.sh compleet"
