import argparse
import json
import re
import sys

hash_suite_regex = re.compile(r"_(MD5|SHA224|SHA256|SHA384|SHA512|SHA)$")

known_hashless_suite_regex = re.compile(r"_CCM(_8|_16|_32)?$")

hash_map = {
    "MD5": {"name": "MD5", "oid": "1.2.840.113549.2.5", "bits": "128"},
    "SHA": {"name": "SHA-1", "oid": "1.3.14.3.2.26", "bits": "160"},
    "SHA224": {"name": "SHA-224", "oid": "2.16.840.1.101.3.4.2.4", "bits": "224"},
    "SHA256": {"name": "SHA-256", "oid": "2.16.840.1.101.3.4.2.1", "bits": "256"},
    "SHA384": {"name": "SHA-384", "oid": "2.16.840.1.101.3.4.2.2", "bits": "384"},
    "SHA512": {"name": "SHA-512", "oid": "2.16.840.1.101.3.4.2.3", "bits": "512"},
}

cryptographic_primitive_map = {
    "AESGCM": ("ae", "gcm"),
    "AESCCM": ("ae", "ccm"),
    "AES": ("block-cipher", "cbc"),
    "ChaCha20": ("ae", None),
    "Camellia": ("block-cipher", "cbc"),
    "ARIAGCM": ("ae", "gcm"),
}

curve_map = {
    # NIST prime curves
    "prime256v1": {"name": "P-256", "oid": "1.2.840.10045.3.1.7", "bits": "256"},
    "secp384r1": {"name": "P-384", "oid": "1.3.132.0.34", "bits": "384"},
    "secp521r1": {"name": "P-521", "oid": "1.3.132.0.35", "bits": "521"},
    "secp256k1": {"name": "secp256k1", "oid": "1.3.132.0.10", "bits": "256"},
    "prime192v1": {"name": "P-192", "oid": "1.2.840.10045.3.1.1", "bits": "192"},
    "secp224r1": {"name": "P-224", "oid": "1.3.132.0.33", "bits": "224"},
    # X-curves
    "X25519": {"name": "X25519", "oid": "1.3.101.110", "bits": "253"},
    "X448": {"name": "X448", "oid": "1.3.101.111", "bits": "448"},
    # Brainpool
    "brainpoolP256r1": {
        "name": "brainpoolP256r1",
        "oid": "1.3.36.3.3.2.8.1.1.7",
        "bits": "256",
    },
    "brainpoolP384r1": {
        "name": "brainpoolP384r1",
        "oid": "1.3.36.3.3.2.8.1.1.11",
        "bits": "384",
    },
    "brainpoolP512r1": {
        "name": "brainpoolP512r1",
        "oid": "1.3.36.3.3.2.8.1.1.13",
        "bits": "512",
    },
    # Binary curves
    "sect163k1": {"name": "sect163k1", "oid": "1.3.132.0.1", "bits": "163"},
    "sect233k1": {"name": "sect233k1", "oid": "1.3.132.0.26", "bits": "233"},
    "sect283k1": {"name": "sect283k1", "oid": "1.3.132.0.16", "bits": "283"},
    "sect409k1": {"name": "sect409k1", "oid": "1.3.132.0.36", "bits": "409"},
    "sect571k1": {"name": "sect571k1", "oid": "1.3.132.0.38", "bits": "571"},
}

dh_group_map = {
    "ffdhe2048": "2048",
    "ffdhe3072": "3072",
    "ffdhe4096": "4096",
    "ffdhe6144": "6144",
    "ffdhe8192": "8192",
}

kem_map = {
    "X25519MLKEM768": {"oid": "2.16.840.1.101.3.4.4.2", "bits": "1184"},
    "X448MLKEM1024": {"oid": "2.16.840.1.101.3.4.4.5", "bits": "1608"},
    "SecP256r1MLKEM768": {"oid": "2.16.840.1.101.3.4.4.6", "bits": "1280"},
    "SecP384r1MLKEM1024": {"oid": "2.16.840.1.101.3.4.4.7", "bits": "1920"},
    "MLKEM512": {"oid": "2.16.840.1.101.3.4.4.1", "bits": "512"},
    "MLKEM768": {"oid": "2.16.840.1.101.3.4.4.2", "bits": "768"},
    "MLKEM1024": {"oid": "2.16.840.1.101.3.4.4.3", "bits": "1024"},
}


def extract_hash_from_suite(iana_name: str) -> dict | None:
    if known_hashless_suite_regex.search(iana_name):
        return None

    name = hash_suite_regex.search(iana_name)

    if not name:
        print(
            f"[!] Geen hash gevonden in suite-naam: {iana_name}, controleer of dit kloppend is.",
            file=sys.stderr,
        )
        return None

    return hash_map[name.group(1)]


def hash_bom_ref(hash_data: dict) -> str:
    return f"crypto-{hash_data['name'].lower().replace('-', '')}"


def hash_to_component(hash_data: dict) -> dict:
    reference = hash_bom_ref(hash_data)

    return {
        "type": "cryptographic-asset",
        "bom-ref": reference,
        "name": hash_data["name"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "hash",
                "parameterSetIdentifier": hash_data["bits"],
            },
            "oid": hash_data["oid"],
        },
    }


def cipher_suite_to_component(
    data: dict, used_hashes: dict, suite_dependencies: list[dict]
) -> dict | None:
    if data["bulk_algorithm"] not in cryptographic_primitive_map:
        print(
            f"[!] Onbekend bulk-algoritme: {data['bulk_algorithm']} in {data['iana_name']}",
            file=sys.stderr,
        )
        return None

    primitive, mode = cryptographic_primitive_map[data["bulk_algorithm"]]
    algorithm_properties = {
        "primitive": primitive,
        "parameterSetIdentifier": str(data["key_size_bits"]),
    }

    if mode:
        algorithm_properties["mode"] = mode

    cbom_component = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto-{data['iana_name']}",
        "name": data["iana_name"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
            "oid": data["iana_name"],
        },
        "properties": [
            {"name": "testssl:protocol", "value": data["protocol"]},
            {"name": "testssl:hexcode", "value": data["hexcode"]},
            {"name": "testssl:opensslName", "value": data["openssl_name"]},
            {"name": "testssl:keyExchange", "value": data["key_exchange"]},
            {
                "name": "testssl:keyExchangeBits",
                "value": data["key_exchange_bits"] or "-",
            },
        ],
    }

    hash_data = extract_hash_from_suite(data["iana_name"])

    if hash_data:
        reference = hash_bom_ref(hash_data)
        used_hashes.setdefault(reference, hash_to_component(hash_data))
        suite_dependencies.append(
            {"ref": f"crypto-{data['iana_name']}", "dependsOn": [reference]}
        )

    return cbom_component


def public_key_component(public_key: dict) -> dict | None:
    if not public_key:
        return None

    return {
        "type": "cryptographic-asset",
        "bom-ref": "crypto-pubkey-0",
        "name": f"{public_key['algorithm']}-{public_key['key_size_bits']}",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "pke",
                "parameterSetIdentifier": str(public_key["key_size_bits"]),
            },
        },
    }


def certificate_to_component(certificate: dict) -> dict | None:
    if not certificate:
        return None

    certificate_properties: dict = {}

    not_before = certificate.get("not_before")
    not_after = certificate.get("not_after")
    public_key = certificate.get("public_key")

    if not_before:
        certificate_properties["notValidBefore"] = (
            not_before.replace(" ", "T") + ":00Z"
        )  # Aanname dat de scanserver in UTC tijd staat

    if not_after:
        certificate_properties["notValidAfter"] = (
            not_after.replace(" ", "T") + ":00Z"
        )  # Aanname dat de scanserver in UTC tijd staat

    if public_key:
        certificate_properties["subjectPublicKeyRef"] = "crypto-pubkey-0"

    fingerprint_sha256 = certificate.get("fingerprint_sha256")
    certificate_name = "certificate-" + (
        fingerprint_sha256[:12] if fingerprint_sha256 else "unknown"
    )

    cbom_component = {
        "type": "cryptographic-asset",
        "bom-ref": "crypto-certificate-0",
        "name": certificate_name,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": certificate_properties,
        },
        "hashes": [],
        "properties": [],
    }

    fingerprint_sha1 = certificate.get("fingerprint_sha1")

    if fingerprint_sha256:
        cbom_component["hashes"].append(
            {"alg": "SHA-256", "content": fingerprint_sha256}
        )

    if fingerprint_sha1:
        cbom_component["hashes"].append({"alg": "SHA-1", "content": fingerprint_sha1})

    exponent = public_key.get("exponent") if public_key else None

    if exponent:
        cbom_component["properties"].append(
            {"name": "testssl:rsaExponent", "value": str(exponent)}
        )

    signature_algorithm = certificate.get("signature_algorithm")

    if signature_algorithm:
        cbom_component["properties"].append(
            {"name": "testssl:certSignatureAlgorithm", "value": signature_algorithm}
        )

    return cbom_component


def key_exchange_components(key_exchange: dict) -> list[dict]:
    if not key_exchange:
        return []

    cbom_components: list[dict] = []

    for kem in key_exchange.get("kems", []):
        kem_data = kem_map.get(kem)

        if kem_data is None:
            print(
                f"[!] Onbekend KEM: {kem}, toegevoegd zonder oid en bits", file=sys.stderr
            )
            kem_data = {"oid": None, "bits": None}

        crypto_properties: dict = {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "kem"},
        }

        oid = kem_data.get("oid")
        bits = kem_data.get("bits")

        if oid:
            crypto_properties["oid"] = oid

        if bits:
            crypto_properties["algorithmProperties"]["parameterSetIdentifier"] = bits

        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-kem-{kem.lower()}",
                "name": kem,
                "cryptoProperties": crypto_properties,
            }
        )

    for curve in key_exchange.get("curves", []):
        curve_data = curve_map.get(curve)

        if curve_data is None:
            print(
                f"[!] Onbekende curve: {curve}, toegevoegd zonder oid/bits",
                file=sys.stderr,
            )
            cbom_components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto-curve-{curve.lower()}",
                    "name": curve,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "key-agree"},
                    },
                }
            )
            continue

        crypto_properties = {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "key-agree",
                "parameterSetIdentifier": curve_data["bits"],
            },
            "oid": curve_data["oid"],
        }

        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-curve-{curve.lower()}",
                "name": curve_data["name"],
                "cryptoProperties": crypto_properties,
            }
        )

    for group in key_exchange.get("dh_groups", []):
        if group == "Custom":
            cbom_components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto-dhgroup-custom",
                    "name": "Custom DH parameters",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "key-agree"},
                    },
                }
            )
            continue

        group_bits = dh_group_map.get(group)

        if group_bits is None:
            print(
                f"[!] Onbekende Diffie-Hellman groep: {group}, toegevoegd zonder bits",
                file=sys.stderr,
            )

        group_properties: dict = {"primitive": "key-agree"}

        if group_bits:
            group_properties["parameterSetIdentifier"] = group_bits

        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-dhgroup-{group.lower()}",
                "name": group,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": group_properties,
                },
            }
        )

    signature_algorithms = sorted(
        set(
            key_exchange.get("sig_algs_tls12", [])
            + key_exchange.get("sig_algs_tls13", [])
        )
    )

    for signature_algorithm in signature_algorithms:
        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-sigalg-{signature_algorithm.lower().replace('+', '-')}",
                "name": signature_algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "signature"},
                },
            }
        )

    return cbom_components


def protocols_to_metadata(protocols: dict) -> dict | None:
    if not protocols:
        return None

    return {
        "properties": [
            {"name": f"testssl:protocol:{protocol_id}", "value": finding}
            for protocol_id, finding in protocols.items()
        ]
    }


def generate_cbom(scan_data: dict, metadata: dict | None = None) -> dict:
    used_hashes: dict = {}
    suite_dependencies: list[dict] = []

    cbom_components = []

    for suite in scan_data.get("cipher_suites", []):
        cbom_component = cipher_suite_to_component(
            suite, used_hashes, suite_dependencies
        )

        if cbom_component is not None:
            cbom_components.append(cbom_component)

    cbom_components += used_hashes.values()

    certificate = certificate_to_component(scan_data.get("certificate", {}))
    public_key = public_key_component(
        scan_data.get("certificate", {}).get("public_key", {})
    )

    if certificate is not None:
        cbom_components.append(certificate)

    if public_key is not None:
        cbom_components.append(public_key)

    cbom_components += key_exchange_components(scan_data.get("key_exchange", {}))

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": cbom_components,
    }

    if suite_dependencies:
        cbom["dependencies"] = suite_dependencies

    protocol_metadata = protocols_to_metadata(scan_data.get("protocols", {}))

    if protocol_metadata:
        if metadata:
            metadata["properties"] = (
                metadata.get("properties", []) + protocol_metadata["properties"]
            )
        else:
            metadata = protocol_metadata

    if metadata:
        cbom["metadata"] = metadata

    return cbom


def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Genereer CycloneDX 1.6 CBOM vanuit geparsede testssl.sh resultaten"
    )

    argument_parser.add_argument(
        "input", nargs="?", help="Pad naar het geparsede .json bestand (default: stdin)"
    )
    argument_parser.add_argument(
        "-o", "--output", help="Output bestand (default: stdout)"
    )

    arguments = argument_parser.parse_args()

    if arguments.input:
        with open(arguments.input, encoding="utf-8") as input_file:
            cipher_suites = json.load(input_file)
    else:
        cipher_suites = json.load(sys.stdin)

    if isinstance(cipher_suites, list):
        scan_data = {"cipher_suites": cipher_suites}
    elif isinstance(cipher_suites, dict):
        scan_data = cipher_suites
    else:
        sys.exit("[!] De verwachte input is een JSON bestand uit testssl_parser.py")

    cbom = generate_cbom(scan_data)

    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            json.dump(cbom, output_file, indent=4)
            output_file.write("\n")
    else:
        print(json.dumps(cbom, indent=4))


if __name__ == "__main__":
    main()
