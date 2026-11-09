# Matching voor testssl_parser.py

import re

# Regex matching voor het maken van cipher lijst met bijbehorende data
cipher_regex = re.compile(
    r"^(?P<protocol>SSLv2|SSLv3|TLSv1(?:\.\d)?)\s+"
    r"x(?P<hexcode>[0-9a-fA-F]+)\s+"
    r"(?P<openssl_name>\S+)\s+"
    r"(?P<kx>\S+(?:\s+\d+)?)\s+"
    r"(?P<bulk_cipher>\S+)\s+"
    r"(?P<key_size>\d+)\s+"
    r"(?P<iana_name>(?:SSL|TLS)_\S+)$"
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

prefixes = (
    "cipher-ssl2_",
    "cipher-ssl3_",
    "cipher-tls1_",
)

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
