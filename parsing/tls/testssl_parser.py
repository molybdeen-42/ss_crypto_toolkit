import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from testssl_algorithms import (cert_key_size_regex, certificate_fields,
                                cipher_regex, cryptographic_primitive_map,
                                curve_map, dh_group_map, hash_map,
                                hash_suite_regex, ids, kem_map,
                                key_exchange_fields,
                                known_hashless_suite_regex, prefixes,
                                protocol_ids)


# Checkt of het id van de input finding valt onder de valide ids of starten met een valide prefix
def check_id(finding: dict) -> bool:
    finding_id = finding.get("id")

    return finding_id in ids or (
        finding_id is not None and finding_id.startswith(prefixes)
    )


# Laadt de ruwe testssl JSON-array uit een bestand of stdin.
def load_testssl(path: str | None = None) -> list[dict]:
    if path and path != "-":
        with open(path, encoding="utf-8") as testssl_output:
            data = json.load(testssl_output)
    else:
        data = json.load(sys.stdin)

    return data


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

        # Een IP-adres voor de slash is geen hostname; normaliseer dezelfde endpoint.
        try:
            ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            pass
        else:
            hostname = ""

        groups.setdefault((hostname, ip, port), []).append(entry)

    if not groups:
        raise ValueError("[!] Geen valide eindpunten in scan-output")

    return groups


# Haalt het gescande IP-adres uit testssl's hostname/ip-veld
def extract_target(data: list[dict]) -> dict:
    for entry in data:
        raw = entry.get("ip", "")
        host_part, _, ip_part = raw.rpartition("/")

        # Continue naar volgende entry bij geen geldig IP
        try:
            ip = str(ipaddress.ip_address(ip_part.strip("[]")))
        except ValueError:
            continue

        # Store enkel het IP als er geen geldige hostname is
        hostname = None
        try:
            ipaddress.ip_address(host_part.strip("[]"))
        except ValueError:
            hostname = host_part.strip("[]") or None

        return {"ip": ip, "hostname": hostname}

    # Return tweemaal None als er zowel geen IP als hostname in de data zit
    return {"ip": None, "hostname": None}


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


# Parsed ruwe findings in geheugen voor de CBOM-generatie.
def parse_testssl(data: list[dict]) -> dict:
    if not isinstance(data, list):
        raise ValueError(
            "De parser verwacht een JSON-array met findings uit testssl.sh --jsonfile"
        )

    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Elke testssl finding moet een JSON-object zijn")
        if not isinstance(entry.get("id"), str):
            raise ValueError("Elke testssl finding moet een tekstveld 'id' hebben")
        if not isinstance(entry.get("finding"), str):
            raise ValueError("Elke testssl finding moet een tekstveld 'finding' hebben")
        if not isinstance(entry.get("ip", ""), str):
            raise ValueError("Het IP-adresveld van een finding moet tekst zijn")

    # Laadt de data en controleert of de ids valide zijn
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

    target = extract_target(data)

    return {
        "ip": target["ip"],
        "hostname": target["hostname"],
        "cipher_suites": cipher_suites,
        "protocols": protocols,
        "key_exchange": key_exchange,
        "certificate": certificate,
    }


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

    if scan_data.get("hostname"):
        metadata["properties"] = metadata.get("properties", []) + [
            {"name": "testssl:hostname", "value": scan_data["hostname"]}
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


# Genereer iedere endpoint apart, zodat algoritmen en certificaten niet mengen.
def generate_endpoint_cboms(data: list[dict]) -> list[tuple[tuple, dict]]:
    groups = split_findings(data)
    return [
        (endpoint, generate_cbom(parse_testssl(findings)))
        for endpoint, findings in sorted(groups.items())
    ]


# Genereer CBOM file naam
def endpoint_report_name(endpoint: tuple, timestamp: str) -> str:
    hostname, address, port = endpoint
    prefix = quote(hostname, safe=".-") + "_" if hostname else ""
    safe_ip = address.replace(":", "-")

    return f"{prefix}{safe_ip}_{port}_{timestamp}_cbom.json"


# Converteert alle endpoints uit ruwe testssl.sh JSON naar CycloneDX 1.6.
def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Converteer testssl.sh JSON naar een afzonderlijke CBOM per endpoint"
    )

    argument_parser.add_argument(
        "input",
        nargs="?",
        help="testssl.sh --jsonfile JSON-array (default: stdin; '-' mag ook)",
    )

    output_group = argument_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-o",
        "--output",
        help="Outputbestand: een CBOM of, bij meerdere endpoints, een JSON-array van CBOMs",
    )

    output_group.add_argument(
        "--output-dir",
        help="Schrijf een CBOM per endpoint en print de gegenereerde paden op stdout",
    )

    argument_parser.add_argument(
        "--timestamp",
        metavar="YYYY-MM-DD_HH:MM",
        help="Starttijd voor bestandsnamen bij --output-dir (default: lokale tijd)",
    )

    arguments = argument_parser.parse_args()

    if arguments.timestamp and not arguments.output_dir:
        argument_parser.error("--timestamp vereist --output-dir")
    try:
        timestamp = arguments.timestamp or datetime.now().strftime("%Y-%m-%d_%H:%M")
        parsed_timestamp = datetime.strptime(timestamp, "%Y-%m-%d_%H:%M")

        if parsed_timestamp.strftime("%Y-%m-%d_%H:%M") != timestamp:
            raise ValueError("Ongeldige timestamp; gebruik YYYY-MM-DD_HH:MM")

        # Genereer alles voordat bestanden geschreven worden.
        documents = generate_endpoint_cboms(load_testssl(arguments.input))
        source_path = (
            Path(arguments.input).resolve()
            if arguments.input and arguments.input != "-"
            else None
        )

        if arguments.output_dir:
            output_dir = Path(arguments.output_dir)
            paths = [
                output_dir / endpoint_report_name(endpoint, timestamp)
                for endpoint, _ in documents
            ]

            if len(set(paths)) != len(paths):
                raise ValueError("Meerdere endpoints hebben dezelfde CBOM-bestandsnaam")

            if source_path in [path.resolve() for path in paths]:
                raise ValueError("Een CBOM mag het invoerbestand niet overschrijven")

            output_dir.mkdir(parents=True, exist_ok=True)

            for path, (_, cbom) in zip(paths, documents):
                with path.open("w", encoding="utf-8") as destination:
                    json.dump(cbom, destination, indent=4)
                    destination.write("\n")

            for path in paths:
                print(path)
        else:
            document = (
                documents[0][1]
                if len(documents) == 1
                else [cbom for _, cbom in documents]
            )

            if arguments.output:
                if Path(arguments.output).resolve() == source_path:
                    raise ValueError(
                        "Een CBOM mag het invoerbestand niet overschrijven"
                    )

                with open(arguments.output, "w", encoding="utf-8") as destination:
                    json.dump(document, destination, indent=4)
                    destination.write("\n")
            else:
                print(json.dumps(document, indent=4))

    except (OSError, ValueError, TypeError) as error:
        argument_parser.exit(1, f"[!] CBOM generatie mislukt: {error}\n")


if __name__ == "__main__":
    main()
