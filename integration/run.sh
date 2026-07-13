#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPOSITORY_ROOT}"

COMPOSE=(docker compose -f integration/compose.yaml)
RUNTIME_DIR="integration/.runtime"
COMPOSE_LOG_FILE="${FRANZTLS_COMPOSE_LOG_FILE:-}"

cleanup() {
    local status=$?
    trap - EXIT
    if [[ "${status}" -ne 0 && -n "${COMPOSE_LOG_FILE}" ]]; then
        "${COMPOSE[@]}" logs --no-color >"${COMPOSE_LOG_FILE}" 2>&1 || true
        chmod 0600 "${COMPOSE_LOG_FILE}" 2>/dev/null || true
    fi
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf -- "${RUNTIME_DIR}"
    exit "${status}"
}
trap cleanup EXIT

umask 077
rm -rf -- "${RUNTIME_DIR}"
install -d -m 0700 "${RUNTIME_DIR}"
openssl rand -hex 32 >"${RUNTIME_DIR}/step-password"
chmod 0444 "${RUNTIME_DIR}/step-password"

GO_INITIAL_SERIAL=""
GO_RENEWED_SERIAL=""
PYTHON_RENEWED_SERIAL=""

fail() {
    printf 'franztls integration: %s\n' "$1" >&2
    return 1
}

wait_for_healthy() {
    local service=$1
    local container_id health_status process_status
    local attempt
    for ((attempt = 1; attempt <= 60; attempt++)); do
        container_id="$("${COMPOSE[@]}" ps -q "${service}")"
        if [[ -n "${container_id}" ]]; then
            process_status="$(docker inspect --format '{{.State.Status}}' "${container_id}")"
            health_status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container_id}")"
            if [[ "${health_status}" == "healthy" ]]; then
                return 0
            fi
            if [[ "${process_status}" == "exited" || "${process_status}" == "dead" ]]; then
                fail "${service} stopped before becoming healthy"
                return 1
            fi
        fi
        sleep 1
    done
    fail "${service} did not become healthy within 60 seconds"
}

assert_no_published_port() {
    local service=$1
    local port=$2
    if "${COMPOSE[@]}" port "${service}" "${port}" 2>/dev/null | grep -q .; then
        fail "${service} publishes host port ${port}"
    fi
}

certificate_serial() {
    python3 -c '
import json
import sys

value = json.load(sys.stdin)
if set(value) != {"serial", "expiry"}:
    raise SystemExit(1)
serial = value["serial"]
expiry = value["expiry"]
if not isinstance(serial, str) or not serial.isdecimal() or serial.startswith("0"):
    raise SystemExit(1)
if not isinstance(expiry, str) or not expiry.endswith("Z"):
    raise SystemExit(1)
print(serial)
'
}

peer_serial() {
    python3 -c '
import json
import sys

value = json.load(sys.stdin)
if set(value) != {"serial"}:
    raise SystemExit(1)
serial = value["serial"]
if not isinstance(serial, str) or not serial.isdecimal() or serial.startswith("0"):
    raise SystemExit(1)
print(serial)
'
}

assert_storage_record() {
    python3 -c '
import json
import sys

value = json.load(sys.stdin)
expected = {
    "uid": 65532,
    "gid": 65532,
    "state_mode": "0700",
    "state_writable": True,
    "ca_readable": True,
    "ca_write_error": "EROFS",
}
if value != expected:
    raise SystemExit(1)
'
}

require_equal() {
    local actual=$1
    local expected=$2
    local description=$3
    if [[ "${actual}" != "${expected}" ]]; then
        fail "${description} did not preserve the expected serial"
    fi
}

require_different() {
    local current=$1
    local previous=$2
    local description=$3
    if [[ "${current}" == "${previous}" ]]; then
        fail "${description} did not change the certificate serial"
    fi
}

file_mode() {
    local service=$1
    local path=$2
    "${COMPOSE[@]}" run -T --rm --no-deps \
        --entrypoint /usr/bin/stat "${service}" --format=%a "${path}"
}

require_mode() {
    local service=$1
    local path=$2
    local expected=$3
    local actual
    actual="$(file_mode "${service}" "${path}")"
    if [[ "${actual}" != "${expected}" ]]; then
        fail "${service} state has an unexpected file mode"
    fi
}

wait_for_handshake() {
    local output serial
    local attempt
    for ((attempt = 1; attempt <= 30; attempt++)); do
        if output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client handshake 2>/dev/null)"; then
            serial="$(peer_serial <<<"${output}")"
            printf '%s\n' "${serial}"
            return 0
        fi
        sleep 1
    done
    fail "mTLS server did not accept a verified client within 30 seconds"
}

start_ca() {
    "${COMPOSE[@]}" config --quiet
    "${COMPOSE[@]}" up -d ca
    wait_for_healthy ca
    assert_no_published_port ca 9000
}

copy_root_ca() {
    "${COMPOSE[@]}" cp ca:/home/step/certs/root_ca.crt "${RUNTIME_DIR}/root_ca.crt"
    chmod 0644 "${RUNTIME_DIR}/root_ca.crt"
    if [[ ! -s "${RUNTIME_DIR}/root_ca.crt" ]] ||
        ! grep -q -- '-----BEGIN CERTIFICATE-----' "${RUNTIME_DIR}/root_ca.crt"; then
        fail "copied root CA is not a nonempty PEM certificate"
    fi
}

issue_with_go() {
    local output
    "${COMPOSE[@]}" build go-client python-client
    output="$("${COMPOSE[@]}" run -T --rm --no-deps --use-aliases go-client issue)"
    GO_INITIAL_SERIAL="$(certificate_serial <<<"${output}")"
    assert_no_published_port go-client 80
}

prove_storage_and_offline_reuse() {
    local output offline_serial
    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client storage-check)"
    assert_storage_record <<<"${output}"

    "${COMPOSE[@]}" stop ca
    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client ensure --renew-before=1m)"
    offline_serial="$(certificate_serial <<<"${output}")"
    require_equal "${offline_serial}" "${GO_INITIAL_SERIAL}" "offline ensure"
    if [[ -n "$("${COMPOSE[@]}" ps --status running -q ca)" ]]; then
        fail "offline ensure restarted the CA"
    fi

    "${COMPOSE[@]}" up -d ca
    wait_for_healthy ca
}

prove_mtls_and_go_renewal() {
    local output observed_before observed_after
    "${COMPOSE[@]}" run -T --rm --no-deps server-cert
    "${COMPOSE[@]}" up -d --no-deps mtls-server
    assert_no_published_port mtls-server 8443

    observed_before="$(wait_for_handshake)"
    require_equal "${observed_before}" "${GO_INITIAL_SERIAL}" "initial mTLS handshake"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps --use-aliases go-client renew --renew-before=48h)"
    GO_RENEWED_SERIAL="$(certificate_serial <<<"${output}")"
    require_different "${GO_RENEWED_SERIAL}" "${GO_INITIAL_SERIAL}" "Go renewal"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client handshake)"
    observed_after="$(peer_serial <<<"${output}")"
    require_equal "${observed_after}" "${GO_RENEWED_SERIAL}" "renewed Go mTLS handshake"
}

renew_go_state_with_python() {
    local output loaded_serial observed_serial
    output="$("${COMPOSE[@]}" run -T --rm --no-deps python-client load)"
    loaded_serial="$(certificate_serial <<<"${output}")"
    require_equal "${loaded_serial}" "${GO_RENEWED_SERIAL}" "Python load of Go state"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps --use-aliases python-client renew)"
    PYTHON_RENEWED_SERIAL="$(certificate_serial <<<"${output}")"
    require_different "${PYTHON_RENEWED_SERIAL}" "${GO_RENEWED_SERIAL}" "Python renewal of Go state"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client load)"
    loaded_serial="$(certificate_serial <<<"${output}")"
    require_equal "${loaded_serial}" "${PYTHON_RENEWED_SERIAL}" "Go reload of Python-renewed state"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-client handshake)"
    observed_serial="$(peer_serial <<<"${output}")"
    require_equal "${observed_serial}" "${PYTHON_RENEWED_SERIAL}" "Python-renewed mTLS handshake"
}

issue_with_python_and_load_with_go() {
    local output python_initial go_loaded go_renewed
    output="$("${COMPOSE[@]}" run -T --rm --no-deps --use-aliases python-first issue)"
    python_initial="$(certificate_serial <<<"${output}")"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-from-python load)"
    go_loaded="$(certificate_serial <<<"${output}")"
    require_equal "${go_loaded}" "${python_initial}" "Go load of Python-created state"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps --use-aliases go-from-python renew --renew-before=48h)"
    go_renewed="$(certificate_serial <<<"${output}")"
    require_different "${go_renewed}" "${python_initial}" "Go renewal of Python-created state"

    output="$("${COMPOSE[@]}" run -T --rm --no-deps go-from-python load)"
    go_loaded="$(certificate_serial <<<"${output}")"
    require_equal "${go_loaded}" "${go_renewed}" "Go reload after account recovery"

    require_mode go-client /etc/certs/account.key 600
    require_mode go-client /etc/certs/account.json 600
    require_mode go-client /etc/certs/prekit-tls.key 600
    require_mode go-client /etc/certs/prekit-tls.pem 644

    require_mode go-from-python /etc/certs/account.key 600
    require_mode go-from-python /etc/certs/account.json 600
    require_mode go-from-python /etc/certs/prekit-tls.key 600
    require_mode go-from-python /etc/certs/prekit-tls.pem 644
}

start_ca
copy_root_ca
issue_with_go
prove_storage_and_offline_reuse
prove_mtls_and_go_renewal
renew_go_state_with_python
issue_with_python_and_load_with_go
echo "franztls integration: PASS"
