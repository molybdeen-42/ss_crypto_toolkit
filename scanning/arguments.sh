#!/usr/bin/env bash

output=""
force=false

while [[ $# -gt 0 ]]; do
	case "$1" in
	-o | --output)
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
