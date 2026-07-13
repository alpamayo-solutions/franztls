#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from franztls import CertManager


STATE_DIR = Path("/etc/certs")
ACCOUNT_KEY = STATE_DIR / "account.key"
ACCOUNT_FILE = STATE_DIR / "account.json"
DOMAIN_KEY = STATE_DIR / "prekit-tls.key"
CSR_FILE = STATE_DIR / "prekit-tls.csr"
CERT_FILE = STATE_DIR / "prekit-tls.pem"


def certificate_record() -> tuple[dict[str, str], int]:
    certificate_bytes = CERT_FILE.read_bytes()
    certificates = x509.load_pem_x509_certificates(certificate_bytes)
    if len(certificates) < 2:
        raise RuntimeError("certificate chain does not include an issuer")

    private_key = serialization.load_pem_private_key(
        DOMAIN_KEY.read_bytes(),
        password=None,
    )
    leaf_public_key = certificates[0].public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if leaf_public_key != private_public_key:
        raise RuntimeError("certificate and private key do not match")

    leaf = certificates[0]
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if "franztls-client" not in san.get_values_for_type(x509.DNSName):
        raise RuntimeError("certificate does not contain the expected DNS identity")
    now = datetime.now(timezone.utc)
    if now < leaf.not_valid_before_utc or now >= leaf.not_valid_after_utc:
        raise RuntimeError("certificate is outside its validity window")
    for issuer in certificates[1:]:
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise RuntimeError("certificate chain contains a non-CA issuer")

    expiry = leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z")
    return {
        "serial": str(leaf.serial_number),
        "expiry": expiry,
    }, leaf.serial_number


def manager() -> CertManager:
    return CertManager(
        domain="franztls-client",
        acme_directory="https://ca:9000/acme/acme/directory",
        ca_file=str(STATE_DIR / "prekit-ca.crt"),
        account_key_path=str(ACCOUNT_KEY),
        domain_key_path=str(DOMAIN_KEY),
        csr_path=str(CSR_FILE),
        cert_path=str(CERT_FILE),
        renewal_buffer_hours=24,
    )


def run(mode: str) -> dict[str, str]:
    if mode == "issue":
        managed_paths = (
            ACCOUNT_KEY,
            ACCOUNT_FILE,
            DOMAIN_KEY,
            CSR_FILE,
            CERT_FILE,
        )
        if any(path.exists() for path in managed_paths):
            raise RuntimeError("issue requires empty certificate state")

    certificate_manager = manager()
    if mode == "load":
        record, _ = certificate_record()
        return record

    if mode == "renew":
        _, previous_serial = certificate_record()
        certificate_manager.force_renew()
        CERT_FILE.chmod(0o644)
        record, current_serial = certificate_record()
        if current_serial == previous_serial:
            raise RuntimeError("renewal did not change the certificate serial")
        return record

    if mode == "issue":
        certificate_manager.force_renew()
        # The Go reader intentionally requires public certificate material at
        # 0644 while private Python-created state remains protected by umask.
        CERT_FILE.chmod(0o644)
        record, _ = certificate_record()
        return record

    raise ValueError("unsupported mode")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"issue", "load", "renew"}:
        print("franztls-python-interop: invalid command", file=sys.stderr)
        return 2
    if os.getuid() != 65532 or os.getgid() != 65532:
        print("franztls-python-interop: unexpected process identity", file=sys.stderr)
        return 1

    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        record = run(argv[1])
    except Exception:
        print(f"franztls-python-interop: {argv[1]} failed", file=sys.stderr)
        return 1

    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
