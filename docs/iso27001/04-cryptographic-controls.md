# Cryptographic Controls

**Document ID:** ALUSKORT-ISMS-04
**Version:** 1.0
**Classification:** Confidential
**Owner:** Security Architect
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.8.24

---

## 1. Purpose

This document defines the cryptographic controls implemented within the ALUSKORT SOC Platform, covering encryption at rest, encryption in transit, integrity verification (hash-chain audit trail), key management, and certificate management.

---

## 2. Cryptographic Policy

### 2.1 Principles

1. All data classified as Confidential or Restricted shall be encrypted at rest and in transit.
2. Industry-standard, well-reviewed cryptographic algorithms shall be used; custom or proprietary cryptography is prohibited.
3. Cryptographic keys shall be managed through their full lifecycle: generation, distribution, storage, rotation, archival, and destruction.
4. Key lengths shall meet or exceed current industry recommendations (NIST SP 800-131A Rev. 2).
5. The immutable audit trail shall use cryptographic hash chains to ensure integrity and tamper detection.

### 2.2 Approved Algorithms

| Purpose | Algorithm | Key Length / Parameters | Standard |
|---|---|---|---|
| Symmetric encryption (at rest) | AES-256-GCM | 256-bit | NIST FIPS 197 |
| Symmetric encryption (TLS) | AES-256-GCM, ChaCha20-Poly1305 | 256-bit | NIST FIPS 197 / RFC 8439 |
| Asymmetric encryption (TLS) | ECDHE | P-256, P-384 | NIST FIPS 186-5 |
| Digital signatures (JWT) | RS256, ES256 | 2048-bit RSA / P-256 ECDSA | RFC 7518 |
| Digital signatures (mTLS) | ECDSA | P-256 | NIST FIPS 186-5 |
| Hash function (audit trail) | SHA-256 | 256-bit | NIST FIPS 180-4 |
| Hash function (password) | Argon2id | Memory: 64MB, Iterations: 3 | RFC 9106 |
| Key derivation | HKDF-SHA-256 | 256-bit | RFC 5869 |
| Random number generation | CSPRNG (OS-provided) | -- | NIST SP 800-90A |

### 2.3 Prohibited Algorithms

| Algorithm | Reason |
|---|---|
| MD5 | Collision attacks; broken |
| SHA-1 | Collision attacks; deprecated |
| DES / 3DES | Insufficient key length; deprecated |
| RC4 | Multiple known vulnerabilities |
| RSA < 2048-bit | Insufficient key length |
| TLS < 1.2 | Known protocol vulnerabilities |
| SSL (all versions) | Broken protocol |
| Custom/proprietary algorithms | Unreviewed; no security assurance |

---

## 3. Encryption at Rest

### 3.1 Data Store Encryption

| Data Store | Encryption Method | Key Management | Details |
|---|---|---|---|
| **PostgreSQL 16** | Transparent Data Encryption (TDE) via filesystem-level encryption (LUKS/dm-crypt) or cloud provider encryption | Cloud KMS or K8s Secrets | All database files encrypted; performance impact < 5% |
| **Redis 7** | TLS for data in transit; persistence files encrypted at filesystem level | K8s Secrets for AUTH password | `requirepass` enforced; RDB/AOF files on encrypted volume |
| **Qdrant** | Filesystem-level encryption (LUKS/dm-crypt) or cloud provider encryption | Cloud KMS | Vector data encrypted at rest on storage volume |
| **Neo4j 5** | Filesystem-level encryption (LUKS/dm-crypt) or cloud provider encryption | Cloud KMS | Graph data encrypted at rest on storage volume |
| **Kafka / Redpanda** | Log segment encryption at filesystem level; topic-level encryption (planned) | K8s Secrets | Message data encrypted at rest on broker storage |
| **MinIO** | Server-Side Encryption (SSE-S3) with AES-256-GCM | MinIO KMS (Vault integration planned) | Per-object encryption; evidence packages encrypted |
| **Kubernetes Secrets** | etcd encryption at rest using AES-CBC or AES-GCM | K8s encryption configuration | `EncryptionConfiguration` with `aescbc` or `aesgcm` provider |
| **Backup storage** | AES-256-GCM encryption before storage | Backup encryption key in Vault | All backups encrypted regardless of storage destination |

### 3.2 Sensitive Data Field Encryption

| Data Type | Encryption Method | Key Scope |
|---|---|---|
| Anthropic API keys | AES-256-GCM (application-level) | Platform-wide key in K8s Secrets |
| Database credentials | AES-256-GCM (K8s Secrets encryption) | etcd encryption key |
| Deanonymisation maps | AES-256-GCM (application-level) | Per-tenant encryption key |
| mTLS private keys | PEM-encoded, stored in K8s Secrets | etcd encryption key |
| OIDC client secrets | AES-256-GCM (K8s Secrets encryption) | etcd encryption key |
| Tenant encryption keys | Envelope encryption (DEK encrypted by KEK) | Platform KEK in Vault (planned) |

---

## 4. Encryption in Transit

### 4.1 TLS Configuration

| Connection Type | TLS Version | Cipher Suites | Certificate Type |
|---|---|---|---|
| External client → Ingress | TLS 1.3 (minimum TLS 1.2) | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256 | Public CA certificate (Let's Encrypt or commercial) |
| Ingress → Services | mTLS (TLS 1.3) | Same as above | Internal CA certificates (cert-manager) |
| Service → Service | mTLS (TLS 1.3) | Same as above | Internal CA certificates (cert-manager) |
| Service → PostgreSQL | TLS 1.3 | Same as above | Internal CA certificate |
| Service → Redis | TLS 1.3 | Same as above | Internal CA certificate |
| Service → Qdrant | TLS 1.3 | Same as above | Internal CA certificate |
| Service → Neo4j | TLS 1.3 (bolt+s://) | Same as above | Internal CA certificate |
| Service → Kafka | mTLS (TLS 1.3) | Same as above | Internal CA certificate |
| Service → MinIO | TLS 1.3 | Same as above | Internal CA certificate |
| LLM Router → Anthropic | TLS 1.3 | Anthropic server configuration | Anthropic's public CA certificate |
| Dashboard → Browser | TLS 1.3 (HTTPS) | Browser-negotiated from approved set | Public CA certificate |
| WebSocket connections | WSS (TLS 1.3) | Same as HTTPS | Same as HTTPS |

### 4.2 mTLS Architecture

```
┌──────────────┐    mTLS     ┌──────────────┐    mTLS     ┌──────────────┐
│   Alert      │◄───────────►│   Triage     │◄───────────►│ Investigation│
│   Ingestion  │             │   Service    │             │   Service    │
└──────────────┘             └──────────────┘             └──────┬───────┘
                                                                 │ mTLS
                                                           ┌─────┴────────┐
                                                           │   Context    │
                                                           │   Gateway    │
                                                           └─────┬────────┘
                                                                 │ mTLS
                                                           ┌─────┴────────┐
                                                           │   LLM        │
                                                           │   Router     │
                                                           └─────┬────────┘
                                                                 │ TLS 1.3
                                                           ┌─────┴────────┐
                                                           │   Anthropic  │
                                                           │   Claude API │
                                                           └──────────────┘

All inter-service communication: mTLS with 24-hour auto-rotated certificates
Internal CA: cert-manager (Kubernetes)
```

### 4.3 TLS Hardening

| Control | Setting |
|---|---|
| Minimum TLS version | 1.2 (external); 1.3 preferred |
| HSTS header | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| Certificate transparency | All public certificates logged to CT logs |
| OCSP stapling | Enabled for public-facing certificates |
| Session resumption | TLS 1.3 0-RTT disabled (replay attack prevention) |
| Renegotiation | Disabled |

---

## 5. Hash-Chain Integrity (SHA-256 Audit Trail)

### 5.1 Design Overview

The ALUSKORT audit trail uses a per-tenant SHA-256 hash chain to provide cryptographic proof of integrity and tamper detection. Each audit record includes the hash of the previous record, creating an immutable chain.

### 5.2 Hash Computation

```
hash[n] = SHA-256(
    hash[n-1] ||           -- Previous record hash (chain link)
    tenant_id ||           -- Tenant identifier
    event_type ||          -- Type of audited event
    timestamp ||           -- ISO 8601 UTC timestamp
    actor_id ||            -- User or service identifier
    action ||              -- Action performed
    resource ||            -- Resource acted upon
    payload_hash           -- SHA-256 hash of the event payload
)
```

### 5.3 Genesis Block

Each tenant's hash chain begins with a genesis block:

```
hash[0] = SHA-256(
    "GENESIS" ||
    tenant_id ||
    creation_timestamp ||
    "ALUSKORT-SOC-AUDIT-CHAIN-v1"
)
```

### 5.4 Verification

- **Real-time verification**: Each new record's previous hash is verified before insertion
- **Periodic verification**: Full chain verification runs daily per tenant
- **On-demand verification**: Admin can trigger full chain verification via API
- **Alert on failure**: Any hash-chain break triggers a Critical severity alert

See document **ALUSKORT-ISMS-13** for the full audit trail technical specification.

---

## 6. Key Management

### 6.1 Key Lifecycle

| Phase | Procedure | Responsible |
|---|---|---|
| **Generation** | Keys generated using CSPRNG; minimum key lengths per approved algorithms table | DevOps Lead |
| **Distribution** | Keys distributed via Kubernetes Secrets; never transmitted in plaintext | DevOps Lead |
| **Storage** | K8s Secrets (encrypted etcd); Vault integration planned for production | DevOps Lead |
| **Usage** | Keys accessed via environment variable injection; never hardcoded | Platform Engineers |
| **Rotation** | Scheduled rotation per key type; emergency rotation on suspected compromise | DevOps Lead |
| **Archival** | Expired keys archived in encrypted backup for audit purposes (90 days) | DevOps Lead |
| **Destruction** | Cryptographic erasure; key material overwritten; documented in audit trail | DevOps Lead |

### 6.2 Key Rotation Schedule

| Key Type | Rotation Frequency | Rotation Method | Downtime |
|---|---|---|---|
| mTLS certificates | 24 hours (automatic) | cert-manager auto-renewal | Zero (graceful rotation) |
| Anthropic API keys | 90 days | Manual rotation via provider console; update K8s Secret | Zero (rolling update) |
| Database credentials | 90 days | Credential rotation script; rolling service restart | Zero (connection pool drain) |
| Redis AUTH password | 90 days | Update K8s Secret; rolling service restart | Zero (reconnection) |
| MinIO access keys | 90 days | Key rotation via MinIO admin; update K8s Secret | Zero (rolling update) |
| Kafka credentials | 90 days | Credential update; rolling broker restart | Zero (Kafka rolling restart) |
| OIDC client secrets | 180 days | Regenerate via IdP; update K8s Secret | Zero (rolling update) |
| Backup encryption keys | Annual | New key for new backups; old key retained for restoration | None |
| Tenant encryption keys (DEK) | Annual | Re-encrypt with new DEK; old DEK destroyed | Maintenance window |
| Platform KEK | Annual | Rotate via Vault; re-wrap all DEKs | Maintenance window |
| etcd encryption key | Annual | K8s encryption config update; etcd re-encryption | Maintenance window |

### 6.3 Emergency Key Rotation

Triggered when:
- Suspected key compromise
- Employee with key access departs
- Vulnerability discovered in cryptographic implementation
- Audit trail anomaly detected

Emergency rotation procedure:
1. Assess scope of potential compromise
2. Generate new key material
3. Distribute via secure channel (K8s Secret update)
4. Rolling restart of affected services
5. Revoke compromised key material
6. Document in incident record and audit trail
7. Verify service restoration

---

## 7. Certificate Management

### 7.1 Certificate Inventory

| Certificate Type | Issuer | Lifetime | Auto-Renewal | Monitoring |
|---|---|---|---|---|
| Ingress TLS (public) | Let's Encrypt / Commercial CA | 90 days (LE) / 1 year | cert-manager ACME solver | Expiry alert at 14 days |
| mTLS service certificates | Internal CA (cert-manager) | 24 hours | cert-manager auto-rotation | Expiry alert at 1 hour |
| Internal CA certificate | Self-signed root | 5 years | Manual rotation with planning | Expiry alert at 90 days |
| Database TLS certificates | Internal CA | 30 days | cert-manager auto-rotation | Expiry alert at 7 days |

### 7.2 cert-manager Configuration

| Setting | Value |
|---|---|
| Issuer type | ClusterIssuer (internal CA) + Issuer (public CA) |
| Private key algorithm | ECDSA P-256 |
| Certificate duration | Service-specific (see table above) |
| Renewal window | 1/3 of certificate lifetime |
| Failure handling | Alert via Prometheus; retry with exponential backoff |
| Certificate storage | Kubernetes TLS Secrets |

---

## 8. LLM API Key Protection

### 8.1 Anthropic API Key Security

| Control | Implementation |
|---|---|
| Storage | Kubernetes Secret, encrypted in etcd |
| Access | Only LLM Router service has access (service account RBAC) |
| Environment injection | Mounted as environment variable `ANTHROPIC_API_KEY` |
| Rotation | 90-day rotation; emergency rotation on suspected compromise |
| Usage monitoring | All API calls logged with token count and cost |
| Rate limiting | Spend guard enforces per-tenant quotas |
| Fallback keys | Separate OpenAI API key for failover (same security controls) |
| Audit | All key usage recorded in audit trail |
| CI/CD protection | Pre-commit hooks scan for API key patterns; CI pipeline secret scanning |
| Log sanitisation | API keys redacted from all application logs |

---

## 9. Cryptographic Control Monitoring

| Metric | Source | Alert Condition |
|---|---|---|
| Certificate expiry | cert-manager + Prometheus | Certificate expires within threshold |
| mTLS handshake failures | Service mesh metrics | > 10 failures in 5 minutes |
| TLS version negotiation | Ingress controller logs | Any connection below TLS 1.2 |
| Hash-chain verification | Audit Service | Any chain break detected |
| Encryption errors | Application logs | Any encryption/decryption failure |
| Key rotation overdue | Operations calendar | Key past rotation deadline |
| Weak cipher usage | TLS scanner (scheduled) | Any connection using non-approved cipher |

---

## 10. Compliance Mapping

| ISO 27001:2022 Control | Implementation |
|---|---|
| A.8.24 Use of cryptography | This document; approved algorithms; key management lifecycle |
| A.8.20 Networks security | TLS 1.3; mTLS inter-service communication |
| A.8.15 Logging | Hash-chain audit trail with SHA-256 integrity |
| A.8.5 Secure authentication | mTLS, OIDC with JWT (RS256/ES256), Argon2id passwords |
| A.5.33 Protection of records | Encrypted storage of audit records; hash-chain tamper detection |

---

## 11. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Security Architect | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon changes to cryptographic standards, key management procedures, or platform architecture.*
