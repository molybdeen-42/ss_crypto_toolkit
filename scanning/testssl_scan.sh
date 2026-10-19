#!/usr/bin/env bash

set -uo pipefail

# Vinden van de base directory van de crypto toolkit
start_dir="$(pwd)"
script_dir="$(cd "$(dirname "$0")" && pwd)"
base_dir="$(dirname "$script_dir")"

cd "$start_dir"

# Parsen van command-line arguments
source "$base_dir/scanning/arguments.sh"

# Vereisen van target directory naam
if [[ "$output" == "" ]] || [[ ! "$output" =~ ^[A-Za-z0-9._-]+$ ]]; then
	echo "[!] Geen naam voor output directory gespecificeerd, het script wordt gesloten. (Gebruik: testssl_scan.sh -o \"voorbeeld_directory\")"
	exit 1
fi

# Verwerking van force flag
if [[ "$force" == true ]]; then
	echo "[+] Force flag gezet"
fi

# Initialisatie van log directory en target file variabelen
testssl_results_dir="$base_dir/results/testssl"
testssl_log_dir="$testssl_results_dir/$output"
targets_file="$base_dir/targets.txt"

# Aanroepen van creatie van ips en targets variable length arrays vanuit target.txt
source "$base_dir/scanning/get_targets.sh" "$targets_file" &>/dev/null

# Check voor het bestaan van de target logging directory, abort als deze al bestaat en de -f flag niet is gebruikt
if [[ -d "$testssl_log_dir" ]]; then
	if [[ "$force" == false ]]; then
		echo "[!] Log directory $testssl_log_dir bestaat al, eerdere scans worden niet overschreven. Gebruik een andere -o naam of de -f flag" >&2
		exit 1
	fi

	echo "[+] Logging directory $testssl_log_dir bestaat al, force flag gezet dus eerdere scans worden overschreven"
else
	echo "[+] Log directory $testssl_log_dir wordt aangemaakt"
	mkdir -p "$testssl_log_dir"
fi

# Check voor het correcte aanmaken van logging directory
if [[ ! -d $testssl_log_dir ]]; then
	echo "[!] Fout bij het maken van $testssl_log_dir" >&2
	exit 1
fi

echo ""
echo "[+] Starten van testssl.sh scan, circa 2 minuten per target"

# Loop voor het uitvoeren van de scan op elke gevonden ip + port combinatie
for index in "${!ips[@]}"; do
	# Aanname om niet te scannen en extracten van ip en port uit arrays
	doscan=0
	ip="${ips[$index]}"
	port="${ports[$index]}"

	# Vindt de meest recente log van deze combinatie van ip en port in alle output directories
	newest_occurrence="$(find "$testssl_results_dir" -name "${ip}_$port.json" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d ' ' -f2-)"

	# Als er een scan aanwezig is, maar de file met targets is recenter aangepast dan het uitvoeren van de voorgaande scan wordt de scan uitgevoerd
	if [[ -n "$newest_occurrence" ]] && [[ "$targets_file" -nt "$newest_occurrence" ]]; then
		echo "[+] Log aanwezig in $newest_occurrence, maar $targets_file is aangepast na de generatie van deze log. De scan wordt daarom alsnog uitgevoerd"

		doscan=1
	fi

	# Als er een scan aanwezig is, maar deze scan is ouder dan 6 dagen wordt de scan alsnog uitgevoerd
	if [[ -n "$newest_occurrence" ]] && [[ $(date -r "$newest_occurrence" +%s) -lt $(date -d "6 days ago" +%s) ]]; then
		echo "[+] Log aanwezig in $newest_occurrence, maar deze log is ouder dan 6 dagen. De scan wordt daarom alsnog uitgevoerd"

		doscan=1
	fi

	# Als er geen oude log is wordt de scan uitgevoerd
	if [[ -z "$newest_occurrence" ]]; then
		doscan=1
	fi

	# Voer de scan uit als de force flag is gezet
	if [[ "$force" == true ]]; then
		doscan=1
	fi

	# Als er bepaald is dat er gescand dient te worden, dan wordt de scan uitgevoerd. Elders wordt er een waarschuwing naar stdout geprint
	if [[ "$doscan" -eq 1 ]]; then
		echo "[+] Scan met testssl.sh uitvoeren voor $ip:$port, resultaat in $testssl_log_dir/${ip}_$port.json..."

		# Aanroepen van testssl.sh met als output een jsonfile in de gespecificeerde logging directory
		set +e
		/usr/bin/env bash "$base_dir/crypto_tools/testssl.sh-3.2.4/testssl.sh" --overwrite --jsonfile "$testssl_log_dir/${ip}_$port.json" "$ip:$port" &>/dev/null
		set -e

		exit_code="$?"

		# Waarschuwing naar stdout als de scan mislukt
		if [[ "$exit_code" -ne 0 ]]; then
			echo "[!] Scan mislukt voor $ip:$port" >&2
		fi
	else
		# Als de gevonden log in een andere output directory staat wordt deze gekopieerd, zodat de huidige output directory compleet is
		echo "[!] Scan voor $ip:$port wordt overgeslagen doordat er nog een recente testssl.sh log bestaat, path: $newest_occurrence" >&2

		if [[ "$(dirname "$newest_occurrence")" != "$testssl_log_dir" ]]; then
			echo "[+] De bestaande log $newest_occurrence wordt gekopieerd naar $testssl_log_dir"
			cp "$newest_occurrence" "$testssl_log_dir/${ip}_${port}.json"
		fi
	fi
done

echo ""
echo "[+] Scan met testssl.sh compleet"
