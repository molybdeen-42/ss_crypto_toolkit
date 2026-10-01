import argparse
import json
import re
import sys

cipher_regex = re.compile(
    r"^(?P<protocol>TLSv1\.\d)\s+"
    r"x(?P<hexcode>[0-9a-fA-F]+)\s+"
    r"(?P<openssl_name>\S+)\s+"
    r"(?P<kx>RSA|DH|ECDH(?:/\w+)?(?:\s+\d+)?)\s+"
    r"(?P<bulk_cipher>\S+)\s+"
    r"(?P<key_size>\d+)\s+"
    r"(?P<iana_name>TLS_\S+)$"
)

cert_key_size_regex = re.compile(
    r"^(?P<algorithm>RSA|EC|DSA)\s+(?P<bits>\d+)\s+bits(?:\s+\(exponent is (?P<exponent>\d+)\))?$"
)

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

# Lookup tabellen
certificate_fields = {
    "cert_signatureAlgorithm": ("signature_algorithm", "direct"),
    "cert_fingerprintSHA256": ("fingerprint_sha256", "direct"),
    "cert_fingerprintSHA1": ("fingerprint_sha1", "direct"),
    "cert_notBefore": ("not_before", "direct"),
    "cert_notAfter": ("not_after", "direct"),
    "cert_keySize": ("public_key", "parse"),
}

key_exchange_fields = {
    "FS_KEMs": ("kems", "split"),
    "FS_ECDHE_curves": ("curves", "split"),
    "DH_groups": ("dh_groups", "split"),
    "FS_TLS12_sig_algs": ("sig_algs_tls12", "split"),
    "FS_TLS13_sig_algs": ("sig_algs_tls13", "split"),
}


def check_id(finding: dict) -> bool:
    finding_id = finding.get("id")

    return finding_id in ids or (
        finding_id is not None and finding_id.startswith(prefixes)
    )


def load_testssl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as testssl_output:
        data = json.load(testssl_output)

    if not isinstance(data, list):
        sys.exit(
            "[!] De parser verwacht een json-array met findings, run ./testssl.sh --jsonfile 'example_output_dir' 42.42.42.42"
        )

    return data


def parse_finding(finding: str) -> dict | None:
    match_regex = cipher_regex.match(finding)

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


def parse_cert_key_size(finding: str) -> dict | None:
    key_size = cert_key_size_regex.match(finding)

    if not key_size:
        return None

    return {
        "algorithm": key_size.group("algorithm"),
        "key_size_bits": int(key_size.group("bits")),
        "exponent": (
            int(key_size.group("exponent")) if key_size.group("exponent") else None
        ),
    }


def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Parse testssl.sh output naar CycloneDX 1.6 CBOM relevante data"
    )

    argument_parser.add_argument(
        "input",
        help="Pad naar de testssl output, run ./testssl.sh --jsonfile 'example_output_dir' 42.42.42.42",
    )
    argument_parser.add_argument(
        "-o", "--output", help="Naam van het output bestand (default: stdout)"
    )

    arguments = argument_parser.parse_args()

    data = load_testssl(arguments.input)
    parsed_testssl_output = [entry for entry in data if check_id(entry)]

    cipher_suites = []
    protocols = {}
    key_exchange = {}
    certificate = {}

    for entry in parsed_testssl_output:
        entry_id = entry["id"]
        finding = entry["finding"]

        if entry_id.startswith("cipher-"):
            parsed_entry = parse_finding(finding)

            if parsed_entry is None:
                print(
                    f"[!] Geen match voor {entry['id']}: {entry['finding']!r}",
                    file=sys.stderr,
                )
                continue

            cipher_suites.append(parsed_entry)
        elif entry_id in protocol_ids:
            protocols[entry_id] = finding
        elif entry_id in key_exchange_fields:
            target_key, action = key_exchange_fields[entry_id]
            key_exchange[target_key] = finding.split() if action == "split" else finding
        elif entry_id in certificate_fields:
            target_key, action = certificate_fields[entry_id]

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

    output = json.dumps(
        {
            "cipher_suites": cipher_suites,
            "protocols": protocols,
            "key_exchange": key_exchange,
            "certificate": certificate,
        },
        indent=4,
    )

    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            output_file.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
