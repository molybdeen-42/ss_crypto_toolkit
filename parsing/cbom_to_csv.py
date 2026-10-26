import argparse
import csv
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROTOCOLS = ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3", "SSLv2", "QUIC")


# Laadt CBOM
def load_cbom(path: str) -> dict:
    with open(path, encoding="utf-8") as input_file:
        cbom = json.load(input_file)

    if (
        not isinstance(cbom, dict)
        or cbom.get("bomFormat") != "CycloneDX"
        or cbom.get("specVersion") != "1.6"
    ):
        raise ValueError("De verwachte input is een CycloneDX 1.6 CBOM")

    return cbom


# Doorloopt alle componenten
def all_components(components: list):
    for component in components:
        yield component
        yield from all_components(component.get("components", []))


# Haalt alle waarden van een benoemde eigenschap op
def property_values(item: dict, name: str) -> list:
    return [
        p["value"]
        for p in item.get("properties", [])
        if p.get("name") == name and p.get("value")
    ]


# Bewaart unieke algoritmen
def json_algorithms(names: list) -> str:
    return json.dumps(list(dict.fromkeys(names)), ensure_ascii=False)


# Normaliseert een tijdstip met tijdzone naar UTC
def utc_timestamp(value: str | None) -> str:
    if not value:
        return ""
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError(f"Tijdzone ontbreekt in datum: {value}")
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Maakt één CSV-rij met algoritmen per protocol en certificaatgegevens
def cbom_to_row(cbom: dict) -> dict:
    metadata = cbom.get("metadata", {})
    addresses = property_values(metadata, "testssl:ip")
    if not addresses:
        raise ValueError("IP-adres ontbreekt in metadata")
    ip = str(ipaddress.ip_address(addresses[0]))

    components = list(all_components(cbom.get("components", [])))
    by_ref = {c["bom-ref"]: c for c in components if c.get("bom-ref")}
    protocols = {protocol: [] for protocol in PROTOCOLS}
    certificate_algorithms = []
    expiry_dates = []
    creation_dates = []
    hashes = []

    for component in components:
        crypto = component.get("cryptoProperties", {})
        if (
            component.get("type") == "cryptographic-asset"
            and crypto.get("assetType") == "algorithm"
        ):
            name = component.get("name")
            if name:
                for protocol in property_values(component, "testssl:protocol"):
                    if protocol in protocols:
                        protocols[protocol].append(name)
                if crypto.get("algorithmProperties", {}).get("primitive") == "hash":
                    hashes.append(name)

        hashes.extend(h["alg"] for h in component.get("hashes", []) if h.get("alg"))

        if (
            component.get("type") == "cryptographic-asset"
            and crypto.get("assetType") == "certificate"
        ):
            certificate = crypto.get("certificateProperties", {})
            algorithm = by_ref.get(certificate.get("subjectPublicKeyRef"), {})
            if algorithm.get("name"):
                certificate_algorithms.append(algorithm["name"])
            expiry_dates.append(utc_timestamp(certificate.get("notValidAfter")))
            creation_dates.append(utc_timestamp(certificate.get("notValidBefore")))

    return {
        "IP-adres": ip,
        "CI-eigenaar": "",
        **{protocol: json_algorithms(names) for protocol, names in protocols.items()},
        "Certificaat algoritmen": json_algorithms(certificate_algorithms),
        "Certificaat verloopdatum (UTC)": json.dumps(expiry_dates, ensure_ascii=False),
        "Certificaat aanmaakdatum (UTC)": json.dumps(
            creation_dates, ensure_ascii=False
        ),
        "Hash algoritmen": json_algorithms(hashes),
        "Datum": utc_timestamp(metadata.get("timestamp")),
    }


def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Converteer een CycloneDX 1.6 CBOM naar een TLS/SSL CSV-inventaris"
    )
    argument_parser.add_argument("input", help="Pad naar het CBOM JSON bestand")
    argument_parser.add_argument(
        "-o", "--output", help="Output bestand (default: input met .csv extensie)"
    )
    arguments = argument_parser.parse_args()
    input_path = Path(arguments.input)
    output_path = (
        Path(arguments.output) if arguments.output else input_path.with_suffix(".csv")
    )

    try:
        if input_path.resolve() == output_path.resolve():
            raise ValueError("Het input en output bestand moeten verschillend zijn")

        cbom = load_cbom(arguments.input)
        row = cbom_to_row(cbom)

        with open(output_path, "w", encoding="utf-8", newline="") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        sys.exit(f"[!] CSV generatie mislukt: {error}")


if __name__ == "__main__":
    main()
