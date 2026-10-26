import argparse
import json
import sys
from datetime import datetime, timezone

from cbom_algorithms import (cryptographic_primitive_map, curve_map,
                             dh_group_map, hash_map, hash_suite_regex, kem_map,
                             known_hashless_suite_regex)


# Extract de hash vanuit de cipher suite
def extract_hash_from_suite(iana_name: str) -> dict | None:
    # Returned None als de suite geen hash bevat
    if known_hashless_suite_regex.search(iana_name):
        return None

    name = hash_suite_regex.search(iana_name)

    # Geeft error als de hash niet matcht met de regex
    if not name:
        print(
            f"[!] Geen hash gevonden in suite-naam: {iana_name}, controleer of dit kloppend is.",
            file=sys.stderr,
        )
        return None

    return hash_map[name.group(1)]


# Maakt de bom-ref voor een hash
def hash_bom_ref(hash_data: dict) -> str:
    return f"crypto-{hash_data['name'].lower().replace('-', '')}"


# Maakt van de geleverde hash-data een CBOM-component
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


# Maakt van de gegeven cipher suite een CBOM-component
def cipher_suite_to_component(
    data: dict, used_hashes: dict, suite_dependencies: list[dict]
) -> dict | None:
    # Geeft een error als het algoritme niet aanwezig is in de mapping en returned None
    if data["bulk_algorithm"] not in cryptographic_primitive_map:
        print(
            f"[!] Onbekend bulk-algoritme: {data['bulk_algorithm']} in {data['iana_name']}",
            file=sys.stderr,
        )
        return None

    # Initializatie van variabelen
    primitive, mode = cryptographic_primitive_map[data["bulk_algorithm"]]
    algorithm_properties = {
        "primitive": primitive,
        "parameterSetIdentifier": str(data["key_size_bits"]),
    }

    if mode:
        algorithm_properties["mode"] = mode

    # Initializeert het CBOM-component
    cbom_component = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto-{data['iana_name']}",
        "name": data["iana_name"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
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

    # Als er een hash bij deze suite hoort wordt deze toegevoegd aan de lijst met gebruikte hashes
    if hash_data:
        reference = hash_bom_ref(hash_data)
        used_hashes.setdefault(reference, hash_to_component(hash_data))
        suite_dependencies.append(
            {"ref": f"crypto-{data['iana_name']}", "dependsOn": [reference]}
        )

    # Enkel het CBOM-component wordt gereturned, niet de hash zodat duplicates worden voorkomen
    return cbom_component


# Genereert een CBOM-component voor public keys
def public_key_component(public_key: dict) -> dict | None:
    # Als er geen public key is wordt er None gereturned
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


# Genereert een CBOM-component voor een certificaat
def certificate_to_component(certificate: dict) -> dict | None:
    # Als er geen certificaat is wordt er None gereturned
    if not certificate:
        return None

    # Variabelen worden gedeclared / geinitialiseerd
    certificate_properties: dict = {}

    not_before = certificate.get("not_before")
    not_after = certificate.get("not_after")
    public_key = certificate.get("public_key")

    # Verwerking van time-frame m.b.t. geldigheid van het certificaat
    if not_before:
        certificate_properties["notValidBefore"] = (
            not_before.replace(" ", "T") + ":00Z"
        )  # Tijd in UTC
    if not_after:
        certificate_properties["notValidAfter"] = (
            not_after.replace(" ", "T") + ":00Z"
        )  # Tijd in UTC

    # Verwerking public key van het certificaat
    if public_key:
        certificate_properties["subjectPublicKeyRef"] = "crypto-pubkey-0"

    # Verwerking van SHA fingerprints van het certificaat
    fingerprint_sha256 = certificate.get("fingerprint_sha256")
    fingerprint_sha1 = certificate.get("fingerprint_sha1")
    certificate_name = "certificate-" + (
        fingerprint_sha256[:12] if fingerprint_sha256 else "unknown"
    )

    # Initializatie van het CBOM-component
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

    # Toevoegen van fingerprints aan het CBOM-component
    if fingerprint_sha256:
        cbom_component["hashes"].append(
            {"alg": "SHA-256", "content": fingerprint_sha256}
        )

    if fingerprint_sha1:
        cbom_component["hashes"].append({"alg": "SHA-1", "content": fingerprint_sha1})

    # Initializeert de public key exponent en verwerkt deze in het CBOM-component
    exponent = public_key.get("exponent") if public_key else None

    if exponent:
        cbom_component["properties"].append(
            {"name": "testssl:rsaExponent", "value": str(exponent)}
        )

    # Verwerking van het gebruikte digital signature algoritme
    signature_algorithm = certificate.get("signature_algorithm")

    if signature_algorithm:
        cbom_component["properties"].append(
            {"name": "testssl:certSignatureAlgorithm", "value": signature_algorithm}
        )

    return cbom_component


# Genereert een CBOM-component voor een key-exchange algoritme
def key_exchange_components(key_exchange: dict) -> list[dict]:
    # Returned een leeg list object als er geen key exchange algortmen zijn
    if not key_exchange:
        return []

    # Declaration en initialization van de output
    cbom_components: list[dict] = []

    # Loop over alle key exchange algoritmen, ofwel KEMs (Key Encapsulation Mechanisms)
    for kem in key_exchange.get("kems", []):
        kem_data = kem_map.get(kem)

        # Returned lege oid en bits als het KEM niet in de mapping bekend is en geeft een error
        if kem_data is None:
            print(
                f"[!] Onbekend KEM: {kem}, toegevoegd zonder oid en bits",
                file=sys.stderr,
            )
            kem_data = {"oid": None, "bits": None}

        # Aggregatie van alle cryptographische eigenschappen
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

        # Toevoegen van dit KEM aan de output list
        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-kem-{kem.lower()}",
                "name": kem,
                "cryptoProperties": crypto_properties,
            }
        )

    # Loop over alle beschikbare ECC curves
    for curve in key_exchange.get("curves", []):
        curve_data = curve_map.get(curve)

        # Returned een output zonder oid en bits als de curve niet bekend is in de mapping
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

        # Output met oid en bits
        crypto_properties = {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "key-agree",
                "parameterSetIdentifier": curve_data["bits"],
            },
            "oid": curve_data["oid"],
        }

        # Toevoegen van deze curve aan de output list
        cbom_components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-curve-{curve.lower()}",
                "name": curve_data["name"],
                "cryptoProperties": crypto_properties,
            }
        )

    # Loop over alle beschikbare Diffie-Hellman groepen
    for group in key_exchange.get("dh_groups", []):
        # In het geval van een custom groep wordt er generieke output gegenereert
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

        # Geeft een error in het geval de de DH groep niet in de mapping lijst aanwezig is
        if group_bits is None:
            print(
                f"[!] Onbekende Diffie-Hellman groep: {group}, toegevoegd zonder bits",
                file=sys.stderr,
            )

        group_properties: dict = {"primitive": "key-agree"}

        # Voegt bits toe aan de output als de DH groep in de mapping lijst stond
        if group_bits:
            group_properties["parameterSetIdentifier"] = group_bits

        # Toevoegen van deze Diffie-Hellman groep aan de output list
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

    # Initializatie van set object met signature algoritmen
    signature_algorithms = sorted(
        set(
            key_exchange.get("sig_algs_tls12", [])
            + key_exchange.get("sig_algs_tls13", [])
        )
    )

    # Loop over alle beschikbare digital signature algoritmen
    for signature_algorithm in signature_algorithms:
        # Toevoegen van de digital signature algoritmen aan de output list
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

    # Returned de lijst met output
    return cbom_components


# Genereert een lijst met metadata vanuit de lijst met protocllen, deze lijst bevat ook niet beschikbare protocollen
def protocols_to_metadata(protocols: dict) -> dict | None:
    # Returned None als er geen protocollen zijn
    if not protocols:
        return None

    return {
        "properties": [
            {"name": f"testssl:protocol:{protocol_id}", "value": finding}
            for protocol_id, finding in protocols.items()
        ]
    }


# Genereert de CBOM in CycloneDX 1.6 format
def generate_cbom(scan_data: dict, metadata: dict | None = None) -> dict:
    # Declaration en initalizatie van variabelen
    used_hashes: dict = {}
    suite_dependencies: list[dict] = []

    cbom_components = []

    # Loop over alle cipher suites en voeg de geparsede versie toe aan de CBOM-componenten
    for suite in scan_data.get("cipher_suites", []):
        cbom_component = cipher_suite_to_component(
            suite, used_hashes, suite_dependencies
        )

        if cbom_component is not None:
            cbom_components.append(cbom_component)

    # Voegt alle gebruikte hashes die met de cipher_suite_to_component functie zijn gevonden toe aan de CBOM-componenten
    cbom_components += used_hashes.values()

    # Creatie van certificaat en public key componenten
    certificate = certificate_to_component(scan_data.get("certificate", {}))
    public_key = public_key_component(
        scan_data.get("certificate", {}).get("public_key", {})
    )

    # Toevoegen van certificaat en public key componenten in het geval dat de functie relevante output levert
    if certificate is not None:
        cbom_components.append(certificate)

    if public_key is not None:
        cbom_components.append(public_key)

    # Voegt de key_exchange componenten toe aan de CBOM-componenten
    cbom_components += key_exchange_components(scan_data.get("key_exchange", {}))

    # Declaratie en initializatie van CBOM
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": cbom_components,
    }

    # Als er hashes aan de dependencies van een suite zijn toegevoegd worden deze ook hier toegevoegd
    if suite_dependencies:
        cbom["dependencies"] = suite_dependencies

    # Voeg de aanmaakdatum in UTC toe zonder meegegeven metadata te wijzigen
    metadata = dict(metadata or {})
    metadata.setdefault(
        "timestamp",
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )

    # IP in metadata
    if scan_data.get("ip"):
        metadata["properties"] = metadata.get("properties", []) + [
            {"name": "testssl:ip", "value": scan_data["ip"]}
        ]

    # Toevoegen van (on)gebruikte protocollen als metadata met classificatie of zij gebruikt worden
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


# Maakt gebruik van eerder geparsede output om een CBOM te genereren in het CycloneDX 1.6 format
def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Genereer CycloneDX 1.6 CBOM vanuit geparsede testssl.sh resultaten"
    )

    argument_parser.add_argument(  # Input bestand kan optioneel worden aangegeven, de standaard input in stdin
        "input", nargs="?", help="Pad naar het geparsede .json bestand (default: stdin)"
    )
    argument_parser.add_argument(  # Optioneel kan de naam van een output file worden aangegeven, de standaard output int stdout
        "-o", "--output", help="Output bestand (default: stdout)"
    )

    arguments = argument_parser.parse_args()

    # Leest input uit file of initializeert de suites direct via stdin
    if arguments.input:
        with open(arguments.input, encoding="utf-8") as input_file:
            cipher_suites = json.load(input_file)
    else:
        cipher_suites = json.load(sys.stdin)

    # Controleert of de input file een dictionary object geeft en abort elders
    if isinstance(cipher_suites, dict):
        scan_data = cipher_suites
    else:
        sys.exit("[!] De verwachte input is een JSON bestand uit testssl_parser.py")

    # Genereert de CBOM met de verkregen input data
    cbom = generate_cbom(scan_data)

    # Schrijft de output uit naar een file of print het in stdout
    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            json.dump(cbom, output_file, indent=4)
            output_file.write("\n")
    else:
        print(json.dumps(cbom, indent=4))


# Roept de main() functie aan
if __name__ == "__main__":
    main()
