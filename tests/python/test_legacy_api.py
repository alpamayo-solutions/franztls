from __future__ import annotations

import http.client
import inspect
import logging
import threading
from datetime import datetime, timezone
from importlib import metadata
from types import SimpleNamespace
from unittest.mock import Mock

from acme import challenges
from cryptography.hazmat.primitives.asymmetric import rsa
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import franztls
import franztls.cert_manager as cert_manager_module
from franztls import CertManager
from franztls.exceptions import CertificateExpiredException


EXPECTED_CONSTRUCTOR_PARAMETERS = [
    ("domain", inspect.Parameter.empty),
    ("acme_directory", "https://ca.localhost:9000/acme/acme/directory"),
    ("ca_file", "/etc/certs/ca.crt"),
    ("account_key_path", "/etc/certs/account.key"),
    ("domain_key_path", "/etc/certs/domain.key"),
    ("csr_path", "/etc/certs/domain.csr"),
    ("cert_path", "/etc/certs/domain.pem"),
    ("renewal_buffer_hours", 24),
]

EXPECTED_PROPERTIES = {
    "ca",
    "cert",
    "cert_file",
    "expiration_date",
    "key",
    "key_file",
    "needs_renewal",
}

EXPECTED_METHODS = {
    "force_renew",
    "renew_if_necessary",
}

EXPECTED_RUNTIME_REQUIREMENTS = {
    ("acme", ">=2.0"),
    ("cryptography", ">=42.0"),
    ("josepy", ">=1.13.0"),
}

EXPECTED_DEV_REQUIREMENTS = {
    ("build", ">=1.2.1"),
    ("pytest", "<9,>=8"),
    ("twine", ">=5.0.0"),
}


def test_cert_manager_constructor_remains_compatible(monkeypatch, tmp_path):
    signature = inspect.signature(CertManager)
    assert [
        (name, parameter.default)
        for name, parameter in signature.parameters.items()
    ] == EXPECTED_CONSTRUCTOR_PARAMETERS
    assert all(
        parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        for parameter in signature.parameters.values()
    )

    generated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    loaded_paths = []
    acme_marker = object()

    def load_key_without_writing(_manager, path):
        loaded_paths.append(path)
        return generated_key

    monkeypatch.setattr(CertManager, "_load_or_create_key", load_key_without_writing)
    monkeypatch.setattr(CertManager, "_connect_acme", lambda _manager: acme_marker)

    account_key = tmp_path / "account.key"
    domain_key = tmp_path / "domain.key"
    manager = CertManager(
        "historian.internal",
        account_key_path=str(account_key),
        domain_key_path=str(domain_key),
    )

    assert manager.domain == "historian.internal"
    assert manager.acme_directory == EXPECTED_CONSTRUCTOR_PARAMETERS[1][1]
    assert manager.ca_file == EXPECTED_CONSTRUCTOR_PARAMETERS[2][1]
    assert manager.renewal_buffer_hours == 24
    assert manager.acme is acme_marker
    assert loaded_paths == [str(account_key), str(domain_key)]
    assert list(tmp_path.iterdir()) == []


def test_cert_manager_public_class_api_remains_compatible():
    public_members = {
        name: member
        for name, member in vars(CertManager).items()
        if not name.startswith("_")
    }
    assert set(public_members) == EXPECTED_PROPERTIES | EXPECTED_METHODS
    assert all(isinstance(public_members[name], property) for name in EXPECTED_PROPERTIES)
    assert all(inspect.isfunction(public_members[name]) for name in EXPECTED_METHODS)


def test_certificate_expired_exception_export_remains_compatible():
    assert franztls.CertificateExpiredException is CertificateExpiredException
    assert issubclass(CertificateExpiredException, Exception)


def test_module_export_list_is_exact():
    assert franztls.__all__ == [
        "CertManager",
        "CertificateExpiredException",
        "__version__",
    ]


def test_distribution_and_module_versions_are_0_2_0():
    distribution = metadata.distribution("franztls")
    assert distribution.version == "0.2.0"
    assert franztls.__version__ == distribution.version

    dev_requirements = set()
    for raw_requirement in distribution.requires or []:
        requirement = Requirement(raw_requirement)
        if requirement.marker is not None and requirement.marker.evaluate(
            {"extra": "dev"}
        ):
            dev_requirements.add(
                (canonicalize_name(requirement.name), str(requirement.specifier))
            )
    assert dev_requirements == EXPECTED_DEV_REQUIREMENTS


def test_runtime_packaging_contract_remains_compatible():
    distribution = metadata.distribution("franztls")
    runtime_requirements = set()
    for raw_requirement in distribution.requires or []:
        requirement = Requirement(raw_requirement)
        if requirement.marker is None:
            runtime_requirements.add(
                (requirement.name.lower(), str(requirement.specifier))
            )

    assert runtime_requirements == EXPECTED_RUNTIME_REQUIREMENTS
    assert distribution.metadata["Requires-Python"] == ">=3.10"


def test_http_challenge_secrets_never_reach_logs_or_stderr(
    monkeypatch,
    tmp_path,
    caplog,
    capfd,
):
    known_token = "task11-known-token"
    key_authorization = "task11-known-token.secret-key-authorization"
    response_marker = object()
    observed_response = {}

    fake_acme = Mock()
    challenge_resource = Mock()
    challenge_resource.chall = challenges.HTTP01(token=known_token.encode("ascii"))
    challenge_resource.token = known_token
    challenge_resource.response_and_validation.return_value = (
        response_marker,
        key_authorization,
    )
    authorization = SimpleNamespace(
        body=SimpleNamespace(
            challenges=[challenge_resource],
            identifier="historian.internal",
        ),
        uri="https://ca.test/acme/authz/1",
    )
    order = SimpleNamespace(authorizations=[authorization])
    fake_acme.new_order.return_value = order
    fake_acme.net.post.return_value.json.return_value = {"status": "valid"}
    fake_acme.poll_and_finalize.return_value = SimpleNamespace(
        fullchain_pem="test certificate chain"
    )

    generated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        CertManager,
        "_load_or_create_key",
        lambda _manager, _path: generated_key,
    )
    monkeypatch.setattr(CertManager, "_connect_acme", lambda _manager: fake_acme)

    manager = CertManager(
        "historian.internal",
        ca_file=str(tmp_path / "ca.crt"),
        account_key_path=str(tmp_path / "account.key"),
        domain_key_path=str(tmp_path / "domain.key"),
        csr_path=str(tmp_path / "domain.csr"),
        cert_path=str(tmp_path / "domain.pem"),
    )
    fake_csr = Mock()
    fake_csr.public_bytes.return_value = b"test csr"
    monkeypatch.setattr(manager, "_generate_csr", lambda: fake_csr)
    monkeypatch.setattr(
        cert_manager_module.x509,
        "load_pem_x509_certificate",
        lambda *_args, **_kwargs: SimpleNamespace(
            not_valid_after_utc=datetime(2030, 1, 1, tzinfo=timezone.utc)
        ),
    )

    real_server_type = cert_manager_module.ReusableHTTPServer

    def loopback_ephemeral_server(_requested_address, handler_type):
        return real_server_type(("127.0.0.1", 0), handler_type)

    monkeypatch.setattr(
        cert_manager_module,
        "ReusableHTTPServer",
        loopback_ephemeral_server,
    )

    def bounded_stop(instance):
        server = instance.httpd
        worker = instance.thread
        if server is None:
            return

        shutdown_timed_out = False
        worker_timed_out = False
        try:
            shutdown = threading.Thread(target=server.shutdown, daemon=True)
            shutdown.start()
            shutdown.join(timeout=2)
            shutdown_timed_out = shutdown.is_alive()

            if worker is not None:
                worker.join(timeout=2)
                worker_timed_out = worker.is_alive()
        finally:
            try:
                server.server_close()
            finally:
                instance.httpd = None
                instance.thread = None

        assert not shutdown_timed_out, "HTTP challenge shutdown exceeded 2s"
        assert not worker_timed_out, "HTTP challenge worker exceeded 2s"

    monkeypatch.setattr(CertManager, "_stop_http_challenge_server", bounded_stop)

    def request_live_challenge(_challenge, _response):
        assert manager.httpd is not None
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            manager.httpd.server_port,
            timeout=2,
        )
        try:
            connection.request(
                "GET",
                f"/.well-known/acme-challenge/{known_token}",
            )
            response = connection.getresponse()
            observed_response["status"] = response.status
            observed_response["body"] = response.read().decode("utf-8")
        finally:
            connection.close()

    fake_acme.answer_challenge.side_effect = request_live_challenge

    caplog.set_level(logging.DEBUG, logger=cert_manager_module.logger.name)
    caplog.clear()
    capfd.readouterr()
    manager.force_renew()
    stderr = capfd.readouterr().err
    log_output = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == cert_manager_module.logger.name
    )

    assert observed_response == {"status": 200, "body": key_authorization}
    leaks = []
    for secret in (known_token, key_authorization):
        if secret in log_output:
            leaks.append(f"logger exposed {secret!r}")
        if secret in stderr:
            leaks.append(f"stderr exposed {secret!r}")
    assert leaks == []
