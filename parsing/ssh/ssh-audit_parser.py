import argparse
import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import quote

from ssh_algorithms import (aead_details_regex, algorithm_catalog,
                            algorithm_groups, algorithm_rules,
                            certificate_suffix_regex, cipher_details_regex,
                            dh_group_bits, hash_map, hash_regex,
                            legacy_mode_regex, md5_regex, mode_aliases,
                            pseudo_algorithm_regex)


# Laadt een enkele standaard serveraudit; policy- en batchoutput vallen erbuiten.
def load_ssh_audit(path: str | None = None) -> dict:
    if path and path != "-":
        with open(path, encoding="utf-8") as source:
            return json.load(source)

    return json.load(sys.stdin)


# Controleert de structuur voordat CBOM-componenten worden gemaakt.
def parse_ssh_audit(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError(
            "Verwacht een JSON-object uit een enkele ssh-audit -j serveraudit"
        )

    if "policy" in data or "dh-gex-modulus-size" in data:
        raise ValueError(
            "Policy- en GEX-diagnostiek bevatten geen volledige auditinventaris"
        )

    subject = data.get("target", data.get("client_ip"))

    if not isinstance(subject, str) or not subject.strip():
        raise ValueError(
            "De audit moet een niet-leeg tekstveld 'target' of 'client_ip' bevatten"
        )

    for group in algorithm_groups:
        entries = data.get(group)
        if not isinstance(entries, list):
            raise ValueError(f"De serveraudit moet een lijst '{group}' bevatten")

        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"Elke entry in '{group}' moet een object zijn")

            if (
                not isinstance(entry.get("algorithm"), str)
                or not entry["algorithm"].strip()
            ):
                raise ValueError(
                    f"Elke entry in '{group}' moet een algoritmenaam hebben"
                )

            if not isinstance(entry.get("notes", {}), dict):
                raise ValueError(
                    f"De notes voor '{entry['algorithm']}' moeten een object zijn"
                )

            if "keysize" in entry and (
                type(entry["keysize"]) is not int or entry["keysize"] < 0
            ):
                raise ValueError(f"Ongeldige keysize voor '{entry['algorithm']}'")

    if not isinstance(data.get("banner", {}), dict):
        raise ValueError("Het banner-veld moet een object zijn")

    fingerprints = data.get("fingerprints", [])

    if not isinstance(fingerprints, list):
        raise ValueError("Het fingerprints-veld moet een lijst zijn")

    for fingerprint in fingerprints:
        if not isinstance(fingerprint, dict) or any(
            not isinstance(fingerprint.get(field), str)
            for field in ("hostkey", "hash_alg", "hash")
        ):
            raise ValueError("Een fingerprint moet hostkey, hash_alg en hash bevatten")

    result = deepcopy(data)
    result["target"] = subject

    return result


def property_value(name: str, value) -> dict:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)

    return {"name": f"ssh-audit:{name}", "value": value}


# Alle naamherkenning staat in ssh_algorithms.py.
def identify_algorithm(group: str, name: str) -> dict:
    base_name = certificate_suffix_regex.sub("", name)

    for pattern, properties in algorithm_rules[group]:
        match = pattern.fullmatch(base_name)

        if match is None:
            continue

        result = dict(properties)
        fields = match.groupdict()

        if fields.get("bits"):
            result["parameterSetIdentifier"] = fields["bits"]

        if fields.get("group"):
            result["parameterSetIdentifier"] = dh_group_bits[fields["group"]]

        if fields.get("mode"):
            result["mode"] = fields["mode"]

            if fields["mode"] == "gcm":
                result["primitive"] = "ae"

        return result

    primitive = algorithm_catalog[group].get(name)

    if primitive is None and group == "key":
        primitive = algorithm_catalog[group].get(base_name)

    if primitive is None and group == "kex":
        for pattern, candidate in algorithm_catalog[group].items():
            if pattern.endswith("*") and name.startswith(pattern[:-1]):
                primitive = candidate
                break

    if primitive is not None:
        result = {"primitive": primitive}

        if group == "enc":
            match = cipher_details_regex.fullmatch(name)

            if match:
                result.update(
                    parameterSetIdentifier=match["bits"],
                    mode=mode_aliases.get(match["mode"], match["mode"]),
                )
            else:
                match = aead_details_regex.fullmatch(name)
                if match:
                    result.update(parameterSetIdentifier=match["bits"], mode="gcm")
                else:
                    match = legacy_mode_regex.fullmatch(name)

                    if match:
                        result["mode"] = match["mode"]

        return result

    print(
        f"[!] Onbekend {group}-algoritme: {name}; toegevoegd zonder aannames",
        file=sys.stderr,
    )

    return {"primitive": "other"}


def hash_to_component(data: dict) -> dict:
    return {
        "type": "cryptographic-asset",
        "bom-ref": "crypto-" + data["name"].lower().replace("-", ""),
        "name": data["name"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "hash",
                "parameterSetIdentifier": data["bits"],
            },
            "oid": data["oid"],
        },
    }


def extract_hash(group: str, name: str) -> dict | None:
    if group not in ("kex", "key", "mac"):
        return None

    name = certificate_suffix_regex.sub("", name)
    match = hash_regex.search(name)

    if match:
        return hash_map[match["bits"]]

    if group == "mac" and md5_regex.search(name):
        return hash_map["MD5"]

    return None


# Maakt een component van ieder algoritme in een entry
def algorithm_to_component(group: str, entry: dict, fingerprints: list) -> dict:
    name = entry["algorithm"]
    algorithm_properties = identify_algorithm(group, name)

    if entry.get("keysize", 0) > 0:
        algorithm_properties["parameterSetIdentifier"] = str(entry["keysize"])

    properties = [property_value("category", group)]
    cipher_match = cipher_details_regex.fullmatch(name) if group == "enc" else None

    if cipher_match and cipher_match["mode"] in mode_aliases:
        properties.append(property_value("mode", cipher_match["mode"]))

    for field, value in entry.items():
        if field != "algorithm":
            properties.append(property_value(field, value))

    fingerprint_name = name

    if name in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa-sha2-256", "ssh-rsa-sha2-512"):
        fingerprint_name = "ssh-rsa"

    if group == "key":
        for fingerprint in fingerprints:
            if fingerprint["hostkey"] == fingerprint_name:
                properties.append(
                    property_value(
                        "fingerprint:" + fingerprint["hash_alg"], fingerprint["hash"]
                    )
                )

    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto-ssh-{group}-{quote(name, safe='')}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
        "properties": properties,
    }


# Bouwt dezelfde CycloneDX-basisstructuur als testssl_parser.py.
def generate_cbom(scan_data: dict, metadata: dict | None = None) -> dict:
    components = {}
    used_hashes = {}
    dependencies = {}
    markers = []
    fingerprints = scan_data.get("fingerprints", [])

    for group in algorithm_groups:
        for entry in scan_data[group]:
            name = entry["algorithm"]

            if group == "kex" and pseudo_algorithm_regex.fullmatch(name):
                if entry not in markers:
                    markers.append(entry)
                continue

            component = algorithm_to_component(group, entry, fingerprints)
            reference = component["bom-ref"]

            if reference in components:
                # Houd aanvullende notes uit dubbele findings beschikbaar.
                for prop in component["properties"]:
                    if prop not in components[reference]["properties"]:
                        components[reference]["properties"].append(prop)

                continue

            components[reference] = component

            hash_data = (
                extract_hash(group, name)
                if component["cryptoProperties"]["algorithmProperties"]["primitive"]
                != "other"
                else None
            )

            if hash_data:
                hash_component = hash_to_component(hash_data)
                hash_ref = hash_component["bom-ref"]
                used_hashes.setdefault(hash_ref, hash_component)
                dependencies[reference] = {"ref": reference, "dependsOn": [hash_ref]}

    metadata = deepcopy(metadata or {})
    metadata.setdefault(
        "timestamp",
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )

    properties = metadata.setdefault("properties", [])
    properties.append(property_value("target", scan_data["target"]))
    properties.append(property_value("scope", "advertised SSH algorithms"))
    properties.append(
        property_value("auditType", "client" if "client_ip" in scan_data else "server")
    )

    # Bewaar alle top-level velden, ook onbekende toekomstige extensies.
    for field, value in scan_data.items():
        if field not in algorithm_groups and field != "target":
            properties.append(property_value(field, value))

    if markers:
        properties.append(property_value("negotiationMarkers", markers))

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": list(components.values()) + list(used_hashes.values()),
        "metadata": metadata,
    }

    if dependencies:
        cbom["dependencies"] = list(dependencies.values())

    return cbom


def generate_document(data) -> dict:
    if not isinstance(data, list):
        return generate_cbom(parse_ssh_audit(data))

    if not data:
        raise ValueError("Een batch moet minstens een audit bevatten")

    # Valideer de hele batch voordat een gedeeltelijk rapport geschreven wordt.
    audits = [parse_ssh_audit(entry) for entry in data]
    combined = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [],
        "dependencies": [],
        "metadata": {
            "timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "properties": [],
        },
    }

    for index, audit in enumerate(audits):
        bom = generate_cbom(audit)
        prefix = f"scan-{index}-"

        for component in bom["components"]:
            component["bom-ref"] = prefix + component["bom-ref"]
            component.setdefault("properties", []).append(
                property_value("target", audit["target"])
            )
            combined["components"].append(component)

        for dependency in bom.get("dependencies", []):
            combined["dependencies"].append(
                {
                    "ref": prefix + dependency["ref"],
                    "dependsOn": [
                        prefix + reference for reference in dependency["dependsOn"]
                    ],
                }
            )

        combined["metadata"]["properties"].append(
            property_value(f"scan:{index}", bom["metadata"])
        )

    return combined


def main() -> None:
    argument_parser = argparse.ArgumentParser(
        description="Converteer ssh-audit -j JSON naar een CycloneDX 1.6 CBOM"
    )

    argument_parser.add_argument(
        "input",
        nargs="?",
        help="JSON server-/clientaudit of batcharray (default: stdin; '-' mag ook)",
    )

    argument_parser.add_argument(
        "-o", "--output", help="Output bestand (default: stdout)"
    )

    arguments = argument_parser.parse_args()

    try:
        cbom = generate_document(load_ssh_audit(arguments.input))

        if arguments.output:
            with open(arguments.output, "w", encoding="utf-8") as output_file:
                json.dump(cbom, output_file, indent=4)
                output_file.write("\n")
        else:
            print(json.dumps(cbom, indent=4))

    except (OSError, ValueError) as error:
        argument_parser.exit(1, f"[!] SSH CBOM generatie mislukt: {error}\n")


if __name__ == "__main__":
    main()
