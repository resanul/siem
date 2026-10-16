#!/usr/bin/env bash
# ==============================================================================
# OpenSOC Forge - TLS Certificate Generation Utility
# Generates Certificate Authority (CA) and signed node/service certificates
# for Elasticsearch, Kibana, Syslog (Vector), and Management Plane.
# ==============================================================================

set -euo pipefail

# Disable MSYS POSIX path translation on Windows/Git-Bash environments
export MSYS_NO_PATHCONV=1

CERTS_DIR="${1:-${CERTS_DIR:-/etc/opensoc/certs}}"
FORCE="${FORCE:-false}"
DAYS_VALID="${DAYS_VALID:-3650}"

if [[ "${2:-}" == "--force" || "${1:-}" == "--force" ]]; then
    FORCE="true"
fi

echo "================================================================="
echo " OpenSOC Forge - TLS Certificate Provisioning"
echo " Target Directory: ${CERTS_DIR}"
echo " Validity Period:  ${DAYS_VALID} days"
echo " Force Overwrite:  ${FORCE}"
echo "================================================================="

# Ensure OpenSSL is available
if ! command -v openssl >/dev/null 2>&1; then
    echo "[-] ERROR: openssl binary not found in PATH. Please install openssl." >&2
    exit 1
fi

# Create target directory
mkdir -p "${CERTS_DIR}"

# Check existing CA validity
if [[ -f "${CERTS_DIR}/ca.crt" && -f "${CERTS_DIR}/ca.key" && "${FORCE}" != "true" ]]; then
    echo "[*] Existing CA found at ${CERTS_DIR}/ca.crt. Verifying expiration..."
    if openssl x509 -checkend 86400 -noout -in "${CERTS_DIR}/ca.crt" >/dev/null 2>&1; then
        echo "[+] CA certificate is valid. Skipping CA generation (use --force to overwrite)."
    else
        echo "[!] CA certificate is expiring or invalid. Regenerating..."
        FORCE="true"
    fi
fi

# 1. Generate Root CA if needed
if [[ ! -f "${CERTS_DIR}/ca.crt" || ! -f "${CERTS_DIR}/ca.key" || "${FORCE}" == "true" ]]; then
    echo "[*] Generating Root Certificate Authority (OpenSOC Forge CA)..."
    openssl req -x509 -new -nodes -newkey rsa:4096 \
        -keyout "${CERTS_DIR}/ca.key" \
        -out "${CERTS_DIR}/ca.crt" \
        -days "${DAYS_VALID}" \
        -subj "/C=US/ST=State/L=Security/O=OpenSOC Forge/OU=Data Plane Security/CN=OpenSOC-Forge-Root-CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"
    echo "[+] Root CA successfully generated."
fi

# Helper function to generate and sign service certificates
generate_service_cert() {
    local service_name="$1"
    local common_name="$2"
    local san_list="$3"

    local key_file="${CERTS_DIR}/${service_name}.key"
    local csr_file="${CERTS_DIR}/${service_name}.csr"
    local crt_file="${CERTS_DIR}/${service_name}.crt"
    local ext_file="${CERTS_DIR}/${service_name}.ext"

    if [[ -f "${crt_file}" && -f "${key_file}" && "${FORCE}" != "true" ]]; then
        if openssl x509 -checkend 86400 -noout -in "${crt_file}" >/dev/null 2>&1; then
            echo "[+] Service '${service_name}' certificate is valid. Skipping."
            return 0
        fi
    fi

    echo "[*] Generating certificate for service: ${service_name} (${common_name})..."

    # Generate Private Key and CSR
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "${key_file}" \
        -out "${csr_file}" \
        -subj "/C=US/ST=State/L=Security/O=OpenSOC Forge/OU=${service_name}/CN=${common_name}"

    # Build OpenSSL extension file with SAN
    cat > "${ext_file}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${san_list}
EOF

    # Sign with Root CA
    openssl x509 -req \
        -in "${csr_file}" \
        -CA "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${crt_file}" \
        -days "${DAYS_VALID}" \
        -sha256 \
        -extfile "${ext_file}" >/dev/null 2>&1

    # Cleanup temporary CSR and ext files
    rm -f "${csr_file}" "${ext_file}"

    # Verify signature
    openssl verify -CAfile "${CERTS_DIR}/ca.crt" "${crt_file}" >/dev/null
    echo "[+] Verified certificate for ${service_name}."
}

# 2. Elasticsearch Certificate (SAN with hostnames & IPs)
generate_service_cert \
    "elasticsearch" \
    "elasticsearch" \
    "DNS:elasticsearch,DNS:opensoc-elasticsearch,DNS:localhost,DNS:opensoc-forge,IP:127.0.0.1,IP:172.28.0.2"

# 3. Kibana Certificate
generate_service_cert \
    "kibana" \
    "kibana" \
    "DNS:kibana,DNS:opensoc-kibana,DNS:localhost,IP:127.0.0.1"

# 4. Syslog Receiver Certificate (RFC 5425 TLS)
generate_service_cert \
    "syslog" \
    "syslog-collector" \
    "DNS:syslog-collector,DNS:opensoc-syslog,DNS:localhost,IP:127.0.0.1"

# 5. Management API Certificate
generate_service_cert \
    "mgmt" \
    "opensoc-forge-mgmt" \
    "DNS:opensoc-forge-mgmt,DNS:localhost,IP:127.0.0.1"

# 6. Apply secure permissions
chmod 755 "${CERTS_DIR}"
chmod 600 "${CERTS_DIR}"/*.key
chmod 644 "${CERTS_DIR}"/*.crt
if [[ -f "${CERTS_DIR}/ca.srl" ]]; then
    chmod 600 "${CERTS_DIR}/ca.srl"
fi

# In container environments, elasticsearch runs as UID 1000. Ensure readable keys or group access
# If running as root, set group ownership or permissions so UID 1000 can read certs
if [[ ${EUID:-0} -eq 0 ]]; then
    chmod 640 "${CERTS_DIR}"/*.key 2>/dev/null || true
    chmod 644 "${CERTS_DIR}"/*.crt 2>/dev/null || true
    if command -v getent >/dev/null 2>&1 && getent group 1000 >/dev/null 2>&1; then
        chgrp -R 1000 "${CERTS_DIR}" 2>/dev/null || true
    fi
fi

echo "================================================================="
echo "[+] All TLS certificates successfully generated and verified in:"
echo "    ${CERTS_DIR}"
echo "================================================================="
