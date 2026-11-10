import argparse
import ipaddress
import json
import sys
from pathlib import Path
from testssl_parser import split_findings


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
