import argparse
import ipaddress
import json
import sys
from pathlib import Path


# Splitsen van meerdere testssl-output files in resultaten
def split_findings(data: list[dict]) -> dict:
    if not isinstance(data, list):
        raise ValueError("[!] Verwachtte input van JSON-array met findings")
    groups = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("[!] Niet elke finding is een object")

        raw = entry.get("ip", "")

        if not isinstance(raw, str):
            raise ValueError("[!] Ongeldig IP-adres veld in JSON")

        hostname, separator, address = raw.rpartition("/")

        if not separator:
            hostname, address = "", raw

        try:
            ip = str(ipaddress.ip_address(address.strip("[]")))
            port_text = str(entry["port"])

            if not port_text.isascii() or not port_text.isdecimal():
                raise ValueError("[!] Ongeldige port")

            port = int(port_text)

            if not 1 <= port <= 65535:
                raise ValueError(
                    f"[!] Ongeldige port, port buiten geldige range: {port}"
                )

        except (ValueError, TypeError, KeyError):
            print(
                f"[!] Overslaan van finding zonder geldig eindpunt, of een fout bij het verbinden met eindpunt: {entry.get('id')}",
                file=sys.stderr,
            )

            continue

        groups.setdefault((hostname, ip, port), []).append(entry)

    if not groups:
        raise ValueError("[!] Geen valide eindpunten in scan-output")

    return groups


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output_dir")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as source:
        groups = split_findings(json.load(source))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for (hostname, address, port), findings in sorted(groups.items()):
        ip = ipaddress.ip_address(address)
        safe_ip = str(ip).replace(":", "-")
        prefix = ""

        if hostname:
            try:
                ipaddress.ip_address(hostname.strip("[]"))
            except ValueError:
                prefix = f"{hostname}_"

        path = output_dir / f"{prefix}ipv{ip.version}_{safe_ip}_{port}.json"

        with path.open("w", encoding="utf-8") as destination:
            json.dump(findings, destination, indent=4)
            destination.write("\n")

        print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError) as error:
        sys.exit(
            f"[!] Fout bij het splitsen van scan-output hostnames naar IP-adressen: {error}"
        )
