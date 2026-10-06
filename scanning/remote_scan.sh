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
	echo "[!] Geen naam voor output directory gespecificeerd, het script wordt gesloten. (Gebruik: -o \"voorbeeld_directory\")"
	exit 1
fi

# Verwerking van force flag
if [[ "$force" == true ]]; then
	echo "[+] Force flag gezet"
fi

bin_dir="$base_dir/scanning"
parse_dir="$base_dir/parsing"
cbom_dir="$base_dir/cboms"
targets_file="$base_dir/targets.txt"

# Scanning tools met de juiste flags starten
if [[ "$force" == true ]]; then
	/usr/bin/env bash "$bin_dir/testssl_scan.sh" "-f" "-o" "$output"
else
	/usr/bin/env bash "$bin_dir/testssl_scan.sh" "-o" "$output"
fi

echo ""
echo "[+] Parsen van logs naar CBOM's"

# Check voor het bestaan van de file met scan targets
if [[ ! -s "$targets_file" ]]; then
	echo "[!] De file met targets $targets_file is leeg of bestaat niet"
	exit 1
fi

# Aanmaken van target variable length arrays voor het bouwen van de CBOM's
source "$bin_dir/get_targets.sh" "$targets_file"

echo ""

for index in "${!ips[@]}"; do
	# Aanname om niet te scannen en extracten van ip en port uit arrays
	ip="${ips[$index]}"
	port="${ports[$index]}"

	if [[ -f "$cbom_dir/${ip}_${port}_cbom.json" ]]; then
		echo "[+] Oude CBOM wordt verwijderd"
		rm "$cbom_dir/${ip}_${port}_cbom.json" 
	fi

	echo "[+] Genereren van CBOM voor $ip:$port"
	if ! /usr/bin/env python3 "$parse_dir/testssl_parser.py" "$base_dir/results/testssl/$output/${ip}_${port}.json" | /usr/bin/env python3 "$parse_dir/cbom_generator.py" -o "$base_dir/cboms/${ip}_${port}_cbom.json"; then
		echo "[!] CBOM generatie voor $ip:$port is mislukt"
	fi

	verification=$("$base_dir/crypto_tools/cyclonedx-cli" "validate" "--input-file" "$cbom_dir/${ip}_${port}_cbom.json" "--input-format" "json" "--input-version" "v1_6" | tail -n 1)

	if [[ "$verification" == "BOM validated successfully." ]]; then
		echo "[+] ${ip}_${port}_cbom.json is successvol gevalideerd"
	else
		echo "
		[!] Valideren van ${ip}_${port}_cbom.json was niet successvol, run 'bash $base_dir/crypto_tools/cyclonedx-cli validate --input-file 
		$cbom_dir/${ip}_${port}_cbom.json --input-format json --input-version v1_6 --fail-on-errors' om het probleem te vinden
		" 
	fi
done
