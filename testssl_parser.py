import argparse
import json
import re
import sys

# Te inventatiseren testssl.sh ids & prefixes
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
    "cert_notBefore",
    "cert_notAfter",
    "ALPN",
}

prefixes = ("cipher-tls1_",)

cipher_regex = re.compile(
    r"^(?P<protocol>TLSv1\.\d)\s+"
    r"x(?P<hexcode>[0-9a-fA-F]+)\s+"
    r"(?P<openssl_name>\S+)\s+"
    r"(?P<kx>RSA|ECDH(?:/\w+)?(?:\s+\d+)?)\s+"
    r"(?P<bulk_cipher>\S+)\s+"
    r"(?P<key_size>\d+)\s+"
    r"(?P<iana_name>TLS_\S+)$"
)


def check_id(finding: dict) -> bool:
    return finding["id"] in ids or finding["id"].startswith(prefixes)

def load_testssl(path: "str") -> list[dict]:
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


def main() -> None:
    argument_parse = argparse.ArgumentParser(
        description="Parse testssl.sh output naar CycloneDX 1.6 CBOM relevante data"
    )

    argument_parse.add_argument(
        "input",
        help="Pad naar de testssl output, run ./testssl.sh --jsonfile 'example_output_dir' 42.42.42.42",
    )
    argument_parse.add_argument(
        "-o", "--output", help="Naam van het output bestand (default: stdout)"
    )

    arguments = argument_parse.parse_args()

    data = load_testssl(arguments.input)
    parsed_testssl_output = [entry for entry in data if check_id(entry)]

    cipher_suites = []

    for entry in parsed_testssl_output:
        if entry["id"].startswith("cipher-"):
            parsed_entry = parse_finding(entry["finding"])

            if parsed_entry is None:
                print(f"[!] Geen match voor {entry['id']}: {entry['finding']}!r", file=sys.stderr)
                continue

            cipher_suites.append(parsed_entry)

    output = json.dumps(cipher_suites, indent = 4)

    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            output_file.write(output)
    else:
        print(output)

if __name__ == "__main__":
    main()
