# Security Policy & Architecture

## Security Principles in OpenSOC Forge

OpenSOC Forge is built with secure-by-default architecture:

1. **Principle of Least Privilege**:
   - The Management API runs under unprivileged service accounts.
   - Operations that require root (e.g. binding port 514 or raw packet capture) are executed via narrowly scoped helpers or container capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`).
   - Management plane failure does not interrupt running packet sniffing or agent logging.

2. **Role-Based Access Control (RBAC)**:
   - Enforced by the FastAPI backend layer on every API request.
   - Distinct roles: `SecOps Viewer`, `Incident Responder`, `Detection Engineer`, `Recovery Operator`, `Platform Admin`.

3. **Tamper-Evident Audit Trail**:
   - Every administrative, deployment, and configuration event is recorded in an append-only JSONL log.
   - Each entry includes a cryptographic SHA-256 hash chaining to the previous entry (`prev_hash`).
   - The integrity verification endpoint detects any unauthorized file mutation or log line truncation.

4. **Secrets & Diagnostic Redaction**:
   - Passwords, tokens, and private keys must never be committed to source control or embedded in diagnostic bundles.
   - The diagnostic collector automatically redacts credentials, keystore entries, and Wazuh auth tokens.

5. **Encryption in Transit**:
   - TLS is strictly enforced for REST APIs, Elasticsearch transport, Filebeat ingestion, and Syslog RFC 5425.
   - Certificate verification is never disabled as a workaround.

6. **Threat Intelligence & CTI Data Hygiene**:
   - Ingested open-source threat feeds (URLs, malicious domains, IPs) are treated as untrusted data and strictly sanitized.
   - Sensitive credentials such as GitHub Personal Access Tokens and threat feed API keys are stored in secure local configuration files and masked (`********`) on all API responses.

## Reporting a Vulnerability

Please report security issues responsibly to: `security@opensoc-forge.internal` or open a confidential security advisory.
Include reproduction steps, impacted components, and proposed remediations.
