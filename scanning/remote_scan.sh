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
run_date="$(date +%Y-%m-%d)"
run_output="${output}_${run_date}"
cbom_dir="$base_dir/cboms/$run_output"
raw_results_dir="$base_dir/results/testssl/$run_output"
csv_dir="$base_dir/csv/$run_output"
targets_file="$base_dir/targets.txt"

# Aanmaken van target variable length arrays voor het bouwen van de CBOM's
source "$bin_dir/get_targets.sh" "$targets_file"

# Check the dated output paths before creating any report directories.
if [[ "$force" == false && ( -d "$raw_results_dir" || -d "$cbom_dir" ||
    ( "$csv" == true && -d "$csv_dir" ) ) ]]; then
    echo "[!] Resultaat-, CBOM- of aangevraagde CSV-directory voor $run_output bestaat al. Gebruik een andere -o naam of de -f flag." >&2
    exit 1
fi

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

# Stop only for setup/orchestration failures; individual targets are recorded below.
scan_args=(-o "$output")
[[ "$force" == true ]] && scan_args+=(-f)
if ! SS_CRYPTO_RUN_DATE="$run_date" /usr/bin/env bash "$bin_dir/testssl_scan.sh" "${scan_args[@]}"; then
    echo "[!] Scan kon niet worden uitgevoerd; controleer de configuratie en scanlogs." >&2
    exit 1
fi

# Publish this run's failures, including an empty file when every target succeeded.
failed_targets_file="$cbom_dir/failed_targets.txt"
if ! cp "$raw_results_dir/failed_targets.txt" "$failed_targets_file"; then
    echo "[!] Kan failed_targets.txt niet opslaan in $cbom_dir" >&2
    exit 1
fi
declare -A failed_targets=()
while IFS= read -r failed_target; do
    [[ -n "$failed_target" ]] && failed_targets["$failed_target"]=1
done < "$failed_targets_file"
if [[ -s "$failed_targets_file" ]]; then
    echo "[!] Mislukte targets: $failed_targets_file. CBOM generatie gaat door voor overige targets." >&2
fi

echo "[+] Parsen van logs naar afzonderlijke CBOM's per endpoint"
report_failed=0
declare -A report_owners=()
for index in "${!hosts[@]}"; do
    host="${hosts[$index]}"
    port="${ports[$index]}"
    if [[ -n "${failed_targets["$host:$port"]+present}" ]]; then
        echo "[!] Geen CBOM voor $host:$port: scan mislukt; zie $failed_targets_file" >&2
        continue
    fi
    raw_file="$raw_results_dir/${host}_${port}.json"
    endpoint_dir="$raw_results_dir/endpoints/${host}_${port}"

    if endpoint_files=$(python3 "$parse_dir/split_testssl.py" "$raw_file" "$endpoint_dir"); then
        :
    else
        echo "[!] Splitsen mislukt voor $host:$port" >&2
        report_failed=1
        continue
    fi

    # Only consume files emitted by this invocation, never old directory entries.
    while IFS= read -r endpoint_file; do
        endpoint_name="$(basename "$endpoint_file" .json)"
        # Internal split filenames are ipvN_<safe-ip>_<port>_<hostname-hash>.
        # Hostname targets get a readable prefix; IP targets avoid repeating the IP.
        endpoint_identity="${endpoint_name#ipv[46]_}"
        endpoint_identity="${endpoint_identity%_*}"
        report_prefix=""
        if [[ ! "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            report_prefix="${host}_"
        fi
        report_name="${report_prefix}${endpoint_identity}_${run_date}_cbom"
        # Keep a collision guard so reports cannot silently overwrite another target.
        if [[ -n "${report_owners[$report_name]+present}" &&
              "${report_owners[$report_name]}" != "$host" ]]; then
            echo "[!] Bestandsnaamconflict voor $report_name: ${report_owners[$report_name]} en $host delen hetzelfde IP en poort; rapport wordt niet overschreven." >&2
            report_failed=1
            continue
        fi
        report_owners["$report_name"]="$host"
        cbom_file="$cbom_dir/${report_name}.json"
        csv_file="$csv_dir/${report_name}.csv"

        echo "[+] Genereren van CBOM: $report_name"
        if python3 "$parse_dir/testssl_parser.py" "$endpoint_file" |
            python3 "$parse_dir/cbom_generator.py" -o "$cbom_file"
        then
            :
        else
            echo "[!] CBOM generatie mislukt: $report_name" >&2
            report_failed=1
            continue
        fi

        if "$base_dir/crypto_tools/cyclonedx-cli" validate \
            --input-file "$cbom_file" --input-format json \
            --input-version v1_6 --fail-on-errors >/dev/null
        then
            echo "[+] CBOM gevalideerd: $report_name"
        else
            echo "[!] CBOM validatie mislukt: $report_name" >&2
            report_failed=1
            continue
        fi

        if [[ "$csv" == true ]]; then
            if python3 "$parse_dir/cbom_to_csv.py" "$cbom_file" -o "$csv_file"; then
                echo "[+] CSV gegenereerd: $report_name"
            else
                echo "[!] CSV generatie mislukt: $report_name" >&2
                report_failed=1
            fi
        fi
    done <<< "$endpoint_files"
done
exit "$report_failed"
