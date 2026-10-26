# Matching voor cbom_generator.py

import re

# Hash regex
hash_suite_regex = re.compile(r"_(MD5|SHA224|SHA256|SHA384|SHA512|SHA)$")

# Suites zonder hash
known_hashless_suite_regex = re.compile(r"_CCM(_8|_16|_32)?$")

# Map van testssl output format naar data die vereist is voor cbom
hash_map = {
    "MD5": {"name": "MD5", "oid": "1.2.840.113549.2.5", "bits": "128"},
    "SHA": {"name": "SHA-1", "oid": "1.3.14.3.2.26", "bits": "160"},
    "SHA224": {"name": "SHA-224", "oid": "2.16.840.1.101.3.4.2.4", "bits": "224"},
    "SHA256": {"name": "SHA-256", "oid": "2.16.840.1.101.3.4.2.1", "bits": "256"},
    "SHA384": {"name": "SHA-384", "oid": "2.16.840.1.101.3.4.2.2", "bits": "384"},
    "SHA512": {"name": "SHA-512", "oid": "2.16.840.1.101.3.4.2.3", "bits": "512"},
}

# Idem maar voor cryptographic primitives
cryptographic_primitive_map = {
    "AESGCM": ("ae", "gcm"),
    "AESCCM": ("ae", "ccm"),
    "AESCCM8": ("ae", "ccm"),
    "AES": ("block-cipher", "cbc"),
    "ChaCha20": ("ae", None),
    "Camellia": ("block-cipher", "cbc"),
    "CamelliaGCM": ("ae", "gcm"),
    "ARIAGCM": ("ae", "gcm"),
    "ARIA": ("block-cipher", "cbc"),
    "3DES": ("block-cipher", "cbc"),
    "DES": ("block-cipher", "cbc"),
    "IDEA": ("block-cipher", "cbc"),
    "SEED": ("block-cipher", "cbc"),
    "RC4": ("stream-cipher", None),
    "RC2": ("stream-cipher", None),
    "GOST": ("stream-cipher", None),
}

# Idem maar voor elliptic curves gebruikt voor ECC gebaseerde algoritmen
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

# Idem maar voor Diffie-Hellman groepen
dh_group_map = {
    "ffdhe2048": "2048",
    "ffdhe3072": "3072",
    "ffdhe4096": "4096",
    "ffdhe6144": "6144",
    "ffdhe8192": "8192",
}

# Idem maar voor KEMs
kem_map = {
    "X25519MLKEM768": {"oid": None, "bits": "1184"},
    "X448MLKEM1024": {"oid": None, "bits": "1608"},
    "SecP256r1MLKEM768": {"oid": None, "bits": "1280"},
    "SecP384r1MLKEM1024": {"oid": None, "bits": "1920"},
    "MLKEM512": {"oid": "2.16.840.1.101.3.4.4.1", "bits": "512"},
    "MLKEM768": {"oid": "2.16.840.1.101.3.4.4.2", "bits": "768"},
    "MLKEM1024": {"oid": "2.16.840.1.101.3.4.4.3", "bits": "1024"},
}
