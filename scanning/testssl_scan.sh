#!/usr/bin/env bash

set -euo pipefail

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
testssl_log_dir="$base_dir/results/testssl/$output"
targets_file="$base_dir/targets.txt"

echo ""

# Check voor het bestaan van logging directory, aanmaken als nodig
if [[ ! -d $testssl_log_dir ]]; then
	echo "[+] Log directory $testssl_log_dir wordt aangemaakt"
	mkdir -p "$testssl_log_dir"
else
	echo "[+] Logging directory $testssl_log_dir bestaat al"
fi

# Check voor het correcte aanmaken van logging directory
if [[ ! -d $testssl_log_dir ]]; then
	echo "[!] Fout bij het maken van $testssl_log_dir" >&2
	exit 1
fi

# Aanroepen van creatie van ips en targets variable length arrays vanuit target.txt
source "$base_dir/scanning/get_targets.sh" "$targets_file"

echo ""
echo "[+] Starten van testssl.sh scan, circa 2 minuten per target"

# Loop voor het uitvoeren van de scan op elke gevonden ip + port combinatie
for index in "${!ips[@]}"; do
	# Aanname om niet te scannen en extracten van ip en port uit arrays
	doscan=0
	ip="${ips[$index]}"
	port="${ports[$index]}"

	# Vindt de meest recente log van deze combinatie van ip en port
	newest_occurrence="$(find "$testssl_log_dir" -name "${ip}_$port.json" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d ' ' -f2-)"

	echo ""

	# Als er een scan aanwezig is, maar de file met targets is recenter aangepast dan het uitvoeren van de voorgaande scan wordt de scan uitgevoerd
	if [[ -n "$newest_occurrence" ]] && [[ "$targets_file" -nt "$newest_occurrence" ]]; then
		echo "[+] Log aanwezig in $newest_occurrence, maar $targets_file is aangepast na de generatie van deze log. De scan wordt daarom alsnog uitgevoerd"

		doscan=1
	fi

	# Als er een scan aanwezig is, maar deze scan is ouder dan 30 dagen wordt de scan alsnog uitgevoerd
	if [[ -n "$newest_occurrence" ]] && [[ $(date -r "$newest_occurrence" +%s) -lt $(date -d "30 days ago" +%s) ]]; then
		echo "[+] Log aanwezig in $newest_occurrence, maar deze log is ouder dan 30 dagen. De scan wordt daarom alsnog uitgevoerd"

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
		if ! /usr/bin/env bash "$base_dir/crypto_tools/testssl.sh-3.2.4/testssl.sh" --jsonfile "$testssl_log_dir/${ip}_$port.json" "$ip:$port" &>/dev/null; then
			# Waarschuwing naar stdout als de scan mislukt
			echo "[!] Scan mislukt voor $ip:$port" >&2
		fi
	else
		echo "[!] Scan voor $ip:$port wordt overgeslagen doordat er nog een recente testssl.sh log bestaat, path: $newest_occurrence" >&2
	fi
done

echo ""
echo "[+] Scan met testssl.sh compleet"
