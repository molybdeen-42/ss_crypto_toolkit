#!/usr/bin/env bash

set -uo pipefail

# Vinden van de base directory van de crypto toolkit
start_dir="$(pwd)"
script_dir="$(cd "$(dirname "$0")" && pwd)"
base_dir="$(dirname "$(dirname "$script_dir")")"

cd "$start_dir"

# Parsen van command-line arguments
source "$base_dir/network/arguments.sh"

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
# The parent supplies its start date so a run crossing midnight stays together.
run_date="${SS_CRYPTO_RUN_DATE:-$(date +%Y-%m-%d)}"
if [[ ! "$run_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
	echo "[!] Ongeldige run-datum: $run_date" >&2
	exit 1
fi
run_output="${output}_${run_date}"
testssl_log_dir="$testssl_results_dir/$run_output"
targets_file="$base_dir/network/tls/tls_targets.txt"

# Aanroepen van creatie van hosts en targets variable length arrays vanuit tls_targets.txt
source "$base_dir/network/get_targets.sh" -t "$targets_file" >/dev/null

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

# Loop voor het uitvoeren van de scan op elke gevonden host + port combinatie
failed_targets_file="$testssl_log_dir/failed_targets.txt"
: >"$failed_targets_file" || exit 1
scan_failed=0
for index in "${!hosts[@]}"; do
	# Aanname om niet te scannen en extracten van hosts en port uit arrays
	doscan=0
	host="${hosts[$index]}"
	port="${ports[$index]}"

	# Vindt de meest recente log van deze combinatie van host en port in alle output directories
	newest_occurrence="$(find "$testssl_results_dir" -name "${host}_$port.json" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d ' ' -f2-)"

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
		echo "[+] Scan met testssl.sh uitvoeren voor $host:$port, resultaat in $testssl_log_dir/${host}_$port.json..."

		# Aanroepen van testssl.sh met als output een jsonfile in de gespecificeerde logging directory
		set +e
		/usr/bin/env bash "$base_dir/crypto_tools/testssl.sh-3.2.4/testssl.sh" --overwrite --jsonfile "$testssl_log_dir/${host}_$port.json" "$host:$port" >"$testssl_log_dir/${host}_${port}.log" 2>&1
		exit_code="$?"
		set -e

		# Waarschuwing naar stdout als de scan mislukt
		if [[ "$exit_code" -ne 0 ]]; then
			echo "[!] Geen succesvolle verbinding/scan voor $host:$port; overige targets gaan door. Zie $testssl_log_dir/${host}_${port}.log" >&2
			printf '%s\n' "$host:$port" >>"$failed_targets_file" || exit 1
			scan_failed=$((scan_failed + 1))
			# Keep failed output for diagnostics, but never reuse it as a cached scan.
			if [[ -f "$testssl_log_dir/${host}_${port}.json" ]]; then
				mv "$testssl_log_dir/${host}_${port}.json" \
					"$testssl_log_dir/${host}_${port}.failed.json" || exit 1
			fi
		fi
	else
		# Als de gevonden log in een andere output directory staat wordt deze gekopieerd, zodat de huidige output directory compleet is
		echo "[!] Scan voor $host:$port wordt overgeslagen doordat er nog een recente testssl.sh log bestaat, path: $newest_occurrence" >&2

		if [[ "$(dirname "$newest_occurrence")" != "$testssl_log_dir" ]]; then
			echo "[+] De bestaande log $newest_occurrence wordt gekopieerd naar $testssl_log_dir"
			cp "$newest_occurrence" "$testssl_log_dir/${host}_${port}.json"
		fi
	fi
done

echo ""
echo "[+] Scan met testssl.sh compleet"
if [[ "$scan_failed" -gt 0 ]]; then
	echo "[!] $scan_failed target(s) mislukt; zie $failed_targets_file" >&2
fi
# Individual target failures are warnings; setup failures still exit nonzero.
exit 0
