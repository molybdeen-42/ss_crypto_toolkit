"""Split flat testssl JSON into independently reportable endpoints."""
import argparse
import hashlib
import ipaddress
import json
import sys
from pathlib import Path


def split_findings(data: list[dict]) -> dict:
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of testssl findings")
    groups = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Expected each finding to be an object")
        raw = entry.get("ip", "")
        if not isinstance(raw, str):
            raise ValueError("Invalid IP field")
        hostname, separator, address = raw.rpartition("/")
        if not separator:
            hostname, address = "", raw
        try:
            ip = str(ipaddress.ip_address(address.strip("[]")))
            port_text = str(entry["port"])
            if not port_text.isascii() or not port_text.isdecimal():
                raise ValueError("Invalid port")
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError("Port outside valid range")
        except (ValueError, TypeError, KeyError):
            print(f"[!] Skipping finding without a valid endpoint: {entry.get('id')}",
                  file=sys.stderr)
            continue
        groups.setdefault((hostname, ip, port), []).append(entry)
    if not groups:
        raise ValueError("No valid endpoints found in scan output")
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
        # Preserve distinct virtual hosts even when their IP and port match.
        host_id = hashlib.sha256(hostname.encode()).hexdigest()[:12]
        path = output_dir / f"ipv{ip.version}_{safe_ip}_{port}_{host_id}.json"
        with path.open("w", encoding="utf-8") as destination:
            json.dump(findings, destination, indent=4)
            destination.write("\n")
        print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"[!] Splitting scan failed: {error}")
