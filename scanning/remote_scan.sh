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
	echo "[!] Geen naam voor output directory gespecificeerd, het script wordt gesloten. (Gebruik: -o \"voorbeeld_directory\")"
	exit 1
fi

bin_dir="$base_dir/scanning"
parse_dir="$base_dir/parsing"
cbom_dir="$base_dir/cboms"
csv_dir="$base_dir/csv"
targets_file="$base_dir/targets.txt"

# Aanmaken van target variable length arrays voor het bouwen van de CBOM's
source "$bin_dir/get_targets.sh" "$targets_file"

# Aanmaken en testen van CBOMs directory
if [[ ! -d "$cbom_dir" ]]; then
	echo "[+] Target directory voor CBOMs wordt aangemaakt: $cbom_dir"
	mkdir -p "$cbom_dir"
fi

if [[ ! -d "$cbom_dir" ]]; then
	echo "[!] Fout bij het aanmaken van $cbom_dir"
	exit 1
fi

# Aanmaken en testen van CSV directory als de --csv flag is gezet
if [[ "$csv" == true ]]; then
	if [[ ! -d "$csv_dir" ]]; then
		echo "[+] Target directory voor CSV bestanden wordt aangemaakt: $csv_dir"
		mkdir -p "$csv_dir"
	fi

	if [[ ! -d "$csv_dir" ]]; then
		echo "[!] Fout bij het aanmaken van $csv_dir"
		exit 1
	fi
fi

# Scanning tools met de juiste flags starten
if [[ "$force" == true ]]; then
	/usr/bin/env bash "$bin_dir/testssl_scan.sh" "-f" "-o" "$output"
else
	/usr/bin/env bash "$bin_dir/testssl_scan.sh" "-o" "$output"
fi

echo ""
echo "[+] Parsen van logs naar CBOM's"

for index in "${!ips[@]}"; do
	ip="${ips[$index]}"
	port="${ports[$index]}"

	if [[ -f "$cbom_dir/${ip}_${port}_cbom.json" ]]; then
		echo "[+] Oude CBOM wordt verwijderd"
		rm "$cbom_dir/${ip}_${port}_cbom.json"
	fi

	echo "[+] Genereren van CBOM voor $ip:$port"
	set +e
	/usr/bin/env python3 "$parse_dir/testssl_parser.py" "$base_dir/results/testssl/$output/${ip}_${port}.json" | /usr/bin/env python3 "$parse_dir/cbom_generator.py" -o "$base_dir/cboms/${ip}_${port}_cbom.json"

	exit_code="$?"
	set -e

	# Alert de gebruiker als de generatie van de CBOM niet is gelukt
	if [[ "$exit_code" -ne 0 ]]; then
		echo "[!] CBOM generatie voor $ip:$port is mislukt" >&2
		continue
	fi

	# Unset -e, zodat het falen van dit script de loop niet afbreekt.
	set +e
	verification=$("$base_dir/crypto_tools/cyclonedx-cli" "validate" "--input-file" "$cbom_dir/${ip}_${port}_cbom.json" "--input-format" "json" "--input-version" "v1_6" | tail -n 1)
	set -e

	if [[ "$verification" == "BOM validated successfully." ]]; then
		echo "[+] ${ip}_${port}_cbom.json is successvol gevalideerd"

		# Enkel .csv genereren als --csv flag aanwezig is
		if [[ "$csv" == true ]]; then
			echo "[+] Genereren van CSV voor $ip:$port"

			set +e
			/usr/bin/env python3 "$parse_dir/cbom_to_csv.py" "$cbom_dir/${ip}_${port}_cbom.json" -o "$csv_dir/${ip}_${port}_cbom.csv"

			exit_code="$?"
			set -e

			# Alert de gebruiker als de generatie van het .csv bestand niet successvol was
			if [[ "$exit_code" -ne 0 ]]; then
				echo "[!] Fout bij het genereren van een .csv bestand voor $ip:$port" >&2
			else
				echo "[+] ${ip}_${port}_cbom.csv is successvol gegenereerd"
			fi
		fi
	else
		echo "[!] Valideren van ${ip}_${port}_cbom.json was niet successvol, run '$base_dir/crypto_tools/cyclonedx-cli validate --input-file $cbom_dir/${ip}_${port}_cbom.json --input-format json --input-version v1_6 --fail-on-errors' om het probleem te vinden"
	fi
done
