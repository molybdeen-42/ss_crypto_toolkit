import argparse
import json
import re
import sys

# Regex matching voor het maken van cipher lijst met bijbehorende data
cipher_regex = re.compile(
    r"^(?P<protocol>TLSv1\.\d)\s+"
    r"x(?P<hexcode>[0-9a-fA-F]+)\s+"
    r"(?P<openssl_name>\S+)\s+"
    r"(?P<kx>RSA|DH|ECDH(?:/\w+)?(?:\s+\d+)?)\s+"
    r"(?P<bulk_cipher>\S+)\s+"
    r"(?P<key_size>\d+)\s+"
    r"(?P<iana_name>TLS_\S+)$"
)

# Regex matching voor certificates om key size te extracten
cert_key_size_regex = re.compile(
    r"^(?P<algorithm>RSA|EC|DSA)\s+(?P<bits>\d+)\s+bits(?:\s+\(exponent is (?P<exponent>\d+)\))?$"
)

# Protocollen
protocol_ids = {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "QUIC"}

# Te inventariseren testssl.sh ids & prefixes
ids = {
    "SSLv2",
    "SSLv3",
    "TLS1",
    "TLS1_1",
    "TLS1_2",
    "TLS1_3",
    "QUIC",
    "FS_KEMs",
    "FS_ECDHE_curves",
    "DH_groups",
    "FS_TLS12_sig_algs",
    "FS_TLS13_sig_algs",
    "cert_signatureAlgorithm",
    "cert_keySize",
    "cert_fingerprintSHA256",
    "cert_fingerprintSHA1",
    "cert_notBefore",
    "cert_notAfter",
    "ALPN",
}

prefixes = ("cipher-tls1_",)

# Lookup tabellen voor certificaten
certificate_fields = {
    "cert_signatureAlgorithm": ("signature_algorithm", "direct"),
    "cert_fingerprintSHA256": ("fingerprint_sha256", "direct"),
    "cert_fingerprintSHA1": ("fingerprint_sha1", "direct"),
    "cert_notBefore": ("not_before", "direct"),
    "cert_notAfter": ("not_after", "direct"),
    "cert_keySize": ("public_key", "parse"),
}

# Lookup tabellen voor key exchange algoritmen
key_exchange_fields = {
    "FS_KEMs": ("kems", "split"),
    "FS_ECDHE_curves": ("curves", "split"),
    "DH_groups": ("dh_groups", "split"),
    "FS_TLS12_sig_algs": ("sig_algs_tls12", "split"),
    "FS_TLS13_sig_algs": ("sig_algs_tls13", "split"),
}


# Checkt of het id van de input finding valt onder de valide ids of starten met een valide prefix
def check_id(finding: dict) -> bool:
    finding_id = finding.get("id")

    return finding_id in ids or (
        finding_id is not None and finding_id.startswith(prefixes)
    )


# Laadt de testssl output als een lijst van dictionaries zodat deze gebruikt kan worden
def load_testssl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as testssl_output:
        data = json.load(testssl_output)

    # Abort het programma wanneer de output geen json-array is
    if not isinstance(data, list):
        sys.exit(
            "[!] De parser verwacht een json-array met findings, run ./testssl.sh --jsonfile 'example_output_dir' 42.42.42.42"
        )

    return data


# Parsed findings naar een duidelijke output structuur
def parse_finding(finding: str) -> dict | None:
    match_regex = cipher_regex.match(finding)

    # Returned None in het geval dat de regex niet wordt gematcht
    if not match_regex:
        return None

    match_json = match_regex.groupdict()

    key_exchange_parts = match_json["kx"].split()

    return {
        "protocol": match_json["protocol"],
        "hexcode": "0x" + match_json["hexcode"],
        "openssl_name": match_json["openssl_name"],
        "key_exchange": key_exchange_parts[0],
        "key_exchange_bits": (
            key_exchange_parts[1] if len(key_exchange_parts) > 1 else None
        ),
        "bulk_algorithm": match_json["bulk_cipher"],
        "key_size_bits": int(match_json["key_size"]),
        "iana_name": match_json["iana_name"],
    }


# Parsed de key-sizes naar duidelijke output structuur
def parse_cert_key_size(finding: str) -> dict | None:
    key_size = cert_key_size_regex.match(finding)

    # Returned None in het geval dat de regex niet wordt gematcht
    if not key_size:
        return None

    return {
        "algorithm": key_size.group("algorithm"),
        "key_size_bits": int(key_size.group("bits")),
        "exponent": (
            int(key_size.group("exponent")) if key_size.group("exponent") else None
        ),
    }


# Maakt gebruik van testssl output om output te genereren die relevant is voor een CBOM in een duidelijke structuur
def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Parse testssl.sh output naar CycloneDX 1.6 CBOM relevante data"
    )

    argument_parser.add_argument(  # Input file argument
        "input",
        help="Pad naar de testssl output, run ./testssl.sh --jsonfile 'example_output_dir' 42.42.42.42",
    )
    argument_parser.add_argument(  # Output file optioneel argument
        "-o", "--output", help="Naam van het output bestand (default: stdout)"
    )

    arguments = argument_parser.parse_args()

    # Laadt de data en controleert of de ids valide zijn
    data = load_testssl(arguments.input)
    parsed_testssl_output = [entry for entry in data if check_id(entry)]

    # Declare variabelen voor de output
    cipher_suites = []
    protocols = {}
    key_exchange = {}
    certificate = {}

    # Loopt over alle entries met valide ids en verwerkt hen
    for entry in parsed_testssl_output:
        entry_id = entry["id"]
        finding = entry["finding"]

        if entry_id.startswith("cipher-"):  # Onderscheiding voor prefixes
            parsed_entry = parse_finding(finding)

            # Slaat de entry over mits de finding de regex niet matcht
            if parsed_entry is None:
                print(
                    f"[!] Geen match voor {entry['id']}: {entry['finding']!r}",
                    file=sys.stderr,
                )
                continue

            cipher_suites.append(parsed_entry)
        elif entry_id in protocol_ids:  # Onderscheiding voor protocollen
            protocols[entry_id] = finding
        elif (
            entry_id in key_exchange_fields
        ):  # Onderscheiding voor key exchange algoritmen
            target_key, action = key_exchange_fields[entry_id]
            key_exchange[target_key] = finding.split() if action == "split" else finding
        elif entry_id in certificate_fields:  # Onderscheiding voor certificaten
            target_key, action = certificate_fields[entry_id]

            # Key size vereist parsing
            if action == "parse":
                key_data = parse_cert_key_size(finding)
                if key_data is None:
                    print(
                        f"[!] Onbekend cert_keySize-formaat: {finding!r}",
                        file=sys.stderr,
                    )
                    continue

                certificate[target_key] = key_data
            else:
                certificate[target_key] = finding

    # Aggregatie van output variabelen in json
    output = json.dumps(
        {
            "cipher_suites": cipher_suites,
            "protocols": protocols,
            "key_exchange": key_exchange,
            "certificate": certificate,
        },
        indent=4,
    )

    # Output naar output file bij het aangeven van de -o flag, elders wordt de output geprint naar stdout
    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            output_file.write(output + "\n")
    else:
        print(output)


# Roept de main() functie aan bij het uitvoeren van het bestand
if __name__ == "__main__":
    main()
