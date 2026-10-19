#!/usr/bin/env bash

set -uo pipefail

output=""
force=false

while [[ $# -gt 0 ]]; do
	case "$1" in
	-o | --output)
		if [[ $# -lt 2 ]] || [[ -z "${2:-}" ]]; then
			echo "[!] Geen directory naam genoemd bij -o flag"
			exit 1
		fi

		# Controle of de directory naam alleen uit letters en cijfers bestaat
		if [[ ! "$2" =~ ^[[:alnum:]]+$ ]]; then
			echo "[!] Ongeldige directory naam bij -o flag: $2 (alleen letters en cijfers toegestaan)" >&2
			exit 1
		fi

		output="$2"
		shift 2
		;;
	-f | --force)
		force=true
		shift 1
		;;
	*)
		echo "[!] Onbekende optie aangegeven: $1" >&2
		exit 1
		;;
	esac
done
