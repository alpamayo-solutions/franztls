import os
import base64
import threading
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from josepy import JWKRSA
from acme.client import ClientNetwork
from acme import client, messages, errors, challenges


logger = logging.getLogger("CertManager")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


class CertManager:
    def __init__(
        self,
        service_id: str,
        domain: str,
        acme_directory: Optional[str] = "https://ca.localhost:9000/acme/acme/directory",
        ca_file: Optional[str] = "/etc/certs/ca.crt",
        account_key_path: Optional[str] = "/etc/certs/account.key",
        domain_key_path: Optional[str] = "/etc/certs/domain.key",
        csr_path: Optional[str] = "/etc/certs/domain.csr",
        cert_path: Optional[str] = "/etc/certs/domain.pem",
        renewal_buffer_hours: int = 24
    ) -> None:
        self.service_id = service_id
        self.domain = domain
        self.acme_directory = acme_directory
        self.ca_file = ca_file

        self.account_key_path = account_key_path
        self.domain_key_path = domain_key_path
        self.csr_path = csr_path
        self.cert_path = cert_path

        self.challenge_responses = {}
        self.httpd: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._expiration_date: Optional[datetime] = None

        self.acct_key = self._load_or_create_key(self.account_key_path)
        self.jwkey = JWKRSA(key=self.acct_key)
        self.client_net = ClientNetwork(
            self.jwkey,
            user_agent="franzTLS/1.0",
            verify_ssl=self.ca_file
        )
        self.acme = self._connect_acme()
        self.domain_key = self._load_or_create_key(self.domain_key_path)
        self.renewal_buffer_hours = renewal_buffer_hours

    @property
    def cert_file(self) -> str:
        return self.cert_path

    @property
    def key_file(self) -> str:
        return self.domain_key_path

    @property
    def cert(self) -> Optional[bytes]:
        if os.path.exists(self.cert_file):
            with open(self.cert_file, "rb") as f:
                return f.read()
        logger.error(f"🔐 No certificate found at {self.cert_file}. Do you still need to create it?")
        return None

    @property
    def key(self) -> Optional[bytes]:
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        logger.error(f"🔐 No key found at {self.key_file}. Do you still need to create it?")
        return None

    @property
    def ca(self) -> str:
        return self.ca_file

    @property
    def expiration_date(self) -> Optional[datetime]:
        if self._expiration_date is None and self.cert:
            try:
                cert = x509.load_pem_x509_certificate(self.cert, default_backend())
                self._expiration_date = cert.not_valid_after_utc
            except Exception as e:
                logger.warning(f"⚠️ Failed to parse expiration date: {e}")
        return self._expiration_date

    def _load_or_create_key(self, path: str):
        if os.path.exists(path):
            logger.debug(f"🔑 Loading existing key from {path}")
            with open(path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        logger.info(f"🔐 Generating new key at {path}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        return key

    def _generate_csr(self) -> x509.CertificateSigningRequest:
        logger.info("📄 Generating CSR...")

        san_list = [
            x509.DNSName(self.domain),
        ]

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
        ])).add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

        csr = csr_builder.sign(self.domain_key, hashes.SHA256())

        with open(self.csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr

    def _connect_acme(self) -> client.ClientV2:
        logger.info("🔗 Connecting to ACME server...")
        directory = messages.Directory.from_json(self.client_net.get(self.acme_directory).json())
        acme = client.ClientV2(directory, self.client_net)
        try:
            acme.new_account(messages.NewRegistration.from_data(
                terms_of_service_agreed=True,
                email="admin@localhost"
            ))
            logger.info("✅ Account registered.")
        except errors.ConflictError as e:
            logger.info("🧾 Already registered, using existing account.")
            acme.net.account = {"uri": e.location}
        return acme

    def _start_http_challenge_server(self) -> None:
        class ChallengeHandler(BaseHTTPRequestHandler):
            def do_GET(inner_self):
                token = inner_self.path.split("/")[-1]
                if token in self.challenge_responses:
                    inner_self.send_response(200)
                    inner_self.send_header("Content-Type", "text/plain")
                    inner_self.end_headers()
                    inner_self.wfile.write(self.challenge_responses[token].encode())
                else:
                    inner_self.send_response(404)
                    inner_self.end_headers()

        logger.debug("🌐 Starting HTTP-01 challenge server on port 80...")
        self.httpd = ReusableHTTPServer(("0.0.0.0", 80), ChallengeHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def _stop_http_challenge_server(self) -> None:
        if self.httpd:
            logger.info("🛑 Stopping HTTP-01 challenge server...")
            self.httpd.shutdown()
            self.thread.join()
            self.httpd.server_close()  # Ensure socket is released
            self.httpd = None
            self.thread = None

    @property
    def needs_renewal(self) -> bool:
        return self.expiration_date is None or datetime.now(timezone.utc) + timedelta(hours=self.renewal_buffer_hours) >= self.expiration_date

    def renew_if_necessary(self) -> None:
        exp = self.expiration_date
        if exp is None:
            logger.info("⏳ No certificate found or unable to parse — forcing renewal...")
            self.force_renew()
            return
        if datetime.now(timezone.utc) + timedelta(hours=self.renewal_buffer_hours) >= exp:
            logger.info(f"⏳ Certificate expiring soon ({exp}) — renewing...")
            self.force_renew()
        else:
            logger.info(f"✅ Certificate is still valid until {exp}. No renewal needed.")

    def force_renew(self) -> None:
        logger.info("🔄 Starting forced renewal...")
        self.challenge_responses.clear()
        csr = self._generate_csr()
        self._start_http_challenge_server()

        try:
            order = self.acme.new_order(csr.public_bytes(serialization.Encoding.PEM))
            for authz in order.authorizations:
                chall = next(c for c in authz.body.challenges if isinstance(c.chall, challenges.HTTP01))
                token = (base64.urlsafe_b64encode(chall.token).decode("utf-8").rstrip("=")
                         if isinstance(chall.token, bytes) else chall.token)
                response, validation = chall.response_and_validation(self.jwkey)
                self.challenge_responses[token] = validation

                logger.info(f"🧪 Starting challenge validation for {authz.body.identifier} and token {token}")
                self.acme.answer_challenge(chall, response)

                for _ in range(30):
                    status = self.acme.net.post(authz.uri, obj=None).json()["status"]
                    logger.debug(f"🔁 Challenge status: {status}")
                    if status == "valid":
                        logger.info("✅ Challenge validated!")
                        break
                    elif status == "invalid":
                        logger.error("❌ Challenge validation failed.")
                        raise Exception("Challenge validation failed.")
                    time.sleep(2)
                else:
                    raise TimeoutError("❌ Challenge validation timed out.")

            logger.info("🔐 Finalizing order...")
            order = self.acme.poll_and_finalize(order)
            with open(self.cert_file, "wb") as f:
                f.write(order.fullchain_pem.encode())

            try:
                self._expiration_date = x509.load_pem_x509_certificate(
                    order.fullchain_pem.encode(), default_backend()
                ).not_valid_after_utc
            except Exception as e:
                logger.warning(f"⚠️ Could not parse newly issued cert expiration: {e}")

            logger.info(f"✅ Certificate saved to {self.cert_file}")

        finally:
            self._stop_http_challenge_server()
