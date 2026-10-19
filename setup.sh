#!/usr/bin/env bash

set -uo pipefail

# Vinden van het absolute pad naar de crypto_tools directory
# Het script staat in de root van de toolkit, dus de crypto_tools directory ligt naast het script
script_dir="$(cd "$(dirname "$0")" && pwd)"
tool_dir="$script_dir/crypto_tools"
scan_dir="$script_dir/scanning"

# Versies van de te installeren tools
testssl_version="3.2.4"
cyclonedx_version="0.33.1"

# Aanmaken van de crypto_tools directory als deze nog niet bestaat
if [[ ! -d "$tool_dir" ]]; then
	echo "[+] Tool directory $tool_dir wordt aangemaakt"
	mkdir -p "$tool_dir"
fi

# Maakt targets.txt file aan
echo "[+] Targets file targets.txt wordt aangemaakt"
touch "$script_dir/targets.txt"

# Executable maken van benodigde scripts
chmod +x "$scan_dir/remote_scan.sh"
chmod +x "$scan_dir/testssl_scan.sh"

# Bepalen van de juiste download voor de architectuur van deze machine
architecture="$(uname -m)"
case "$architecture" in
	x86_64)
		cyclonedx_asset="cyclonedx-linux-x64"
		;;
	aarch64)
		cyclonedx_asset="cyclonedx-linux-arm64"
		;;
	*)
		echo "[!] Ongesupporte architectuur voor cyclonedx-cli: $architecture" >&2
		exit 1
		;;
esac

# Installatie van testssl.sh als deze nog niet aanwezig is
if [[ -f "$tool_dir/testssl.sh-$testssl_version/testssl.sh" ]]; then
	echo "[+] testssl.sh versie $testssl_version is al geinstalleerd in $tool_dir"
else
	echo "[+] Downloaden en installeren van testssl.sh versie $testssl_version in $tool_dir"
	curl -fSL "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${testssl_version}.tar.gz" | tar -xz -C "$tool_dir"

	if [[ ! -f "$tool_dir/testssl.sh-$testssl_version/testssl.sh" ]]; then
		echo "[!] Installatie van testssl.sh versie $testssl_version is mislukt" >&2
		exit 1
	fi
fi

# Installatie van cyclonedx-cli als deze nog niet aanwezig is
if [[ -f "$tool_dir/cyclonedx-cli" ]]; then
	echo "[+] cyclonedx-cli is al geinstalleerd in $tool_dir"
else
	echo "[+] Downloaden en installeren van cyclonedx-cli versie $cyclonedx_version in $tool_dir"
	curl -fSL -o "$tool_dir/cyclonedx-cli" "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${cyclonedx_version}/${cyclonedx_asset}"
	chmod +x "$tool_dir/cyclonedx-cli"

	"$tool_dir/cyclonedx-cli" --version >/dev/null || {
		echo "[!] Installatie van cyclonedx-cli versie $cyclonedx_version is mislukt" >&2
		exit 1
	}
fi

echo ""
echo "[+] Installatie van de crypto tools in $tool_dir is compleet"
