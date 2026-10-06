#!/usr/bin/env bash

output=""
force=false

while [[ $# -gt 0 ]]; do
	case "$1" in
	-o | --output)
		if [[ $# -lt 2 ]] || [[ -z "${2:-}" ]]; then
			echo "[!] Geen directory naam genoemd bij -o flag"
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
