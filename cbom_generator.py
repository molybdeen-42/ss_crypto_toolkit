import argparse
import json
import sys

cryptographic_primitive_map = {
    "AESGCM": ("aes", "gcm"),
    "AESCCM": ("aes", "ccm"),
    "AES": ("aes", "cbc"),
    "ChaCha20": ("chacha20", "poly1305"),
    "Camellia": ("camellia", None),
    "ARIAGCM": ("aria", "gcm"),
}

def cipher_suite_to_component(data: dict) -> dict:
    algorithm, mode = cryptographic_primitive_map[data["bulk_algorithm"]]
    parameters = [{"type": "keylen", "value": str(data["key_size_bits"])}]

    if mode:
        parameters.append({"type": "mode", "value": mode.upper()})

    return {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{data['iana_name']}",
            "name": data["iana_name"],
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "encryption",
                    "parameterSets": parameters,
                    },
                "oid": data["iana_name"],
                },
            "properties": [
                {"name": "testssl:protocol", "value": data["protocol"]},
                {"name": "testssl:hexcode", "value": data["hexcode"]},
                {"name": "testssl:opensslName", "value": data["openssl_name"]},
                {"name": "testssl:keyExchange", "value": data["key_exchange"]},
                {"name": "testssl:keyExchangeBits", "value": data["key_exchange_bits"] or "-"}
            ],
    }

def generate_cbom(cipher_suites: list[dict], metadata: dict | None = None) -> dict:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [cipher_suite_to_component(suite) for suite in cipher_suites],
    }

    if metadata:
        cbom["metadata"] = metadata

    return cbom

def main() -> None:
    argument_parser = argparse.ArgumentParser(description="Genereer CycloneDX 1.6 CBOM vanuit geparsede testssl.sh resultaten")

    argument_parser.add_argument("input", nargs="?", help="Pad naar het geparsede .json bestand (default: stdin)")
    argument_parser.add_argument("-o", "--output", help="Output bestand (default: stdout)")

    arguments = argument_parser.parse_args()

    if arguments.input:
        with open(arguments.input, encoding="utf-8") as input_file:
            cipher_suites = json.load(input_file)
    else:
        cipher_suites = json.load(sys.stdin)

    cbom = generate_cbom(cipher_suites)

    if arguments.output:
        with open(arguments.output, "w", encoding="utf-8") as output_file:
            json.dump(cbom, output_file, indent=4)
    else:
        print(json.dumps(cbom, indent=4))

if __name__ == "__main__":
    main()
