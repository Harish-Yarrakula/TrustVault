# TrustVault threat model

This summary lists the main security risks, protections, and limits. It is not
an independent security audit or a guarantee that every deployment is
configured safely.

## Main threats

| Severity | Threat | Protection | Remaining risk |
| --- | --- | --- | --- |
| 🔴 **Critical** | A user accesses another tenant's files or a file they were not granted. | The API checks tenant, owner, and document permissions on protected requests. Admin status alone does not grant file access. | Test every document route. Revocation cannot remove copies already downloaded. |
| 🟠 **High** | Stolen passwords, brute force, or stolen sessions. | Password hashing, request rate limits, session checks, logout revocation, and mandatory admin MFA. | No SSO, phishing-resistant MFA, password reset, or central device/session manager is promised. |
| 🟠 **High** | A harmful, fake, or oversized upload is accepted. | The API checks file type, size, signature, and checksum; ClamAV scans files before availability. Scanner errors fail closed. | Keep the 10 MiB UI and 25 MiB API limits aligned. Keep scanner signatures updated. |
| 🟠 **High** | Private documents, secrets, or audit records are exposed or altered. | Private storage, short-lived upload forms, API-authorized reads, restricted services, and a separate Object Lock audit archive. | Verify real cloud IAM, bucket retention, TLS, firewall, and secret settings. Privileged cloud or app compromise is not prevented. |
| 🟠 **High** | Audit records miss or misattribute denied activity. | Audit events use a sequence and hash chain; configured production archives are checked against Object Lock storage. | **Known gap:** cookie-only failures and invalid identities are not reliably attributable. Failed-login audit coverage still needs end-to-end verification. |
| 🟡 **Medium** | A share link or email code is stolen or forwarded. | Share and OTP secrets are stored hashed. Links expire and can be revoked; OTPs expire, have attempt limits, and are cleared after use. | A stolen link can be used until expiry or revocation. A compromised mailbox can expose the OTP. |
| 🟡 **Medium** | Cross-site requests or unsafe deployment settings bypass protections. | Mutating cookie requests require an allowed origin. Production cookies are HttpOnly and Secure. | Verify production CORS, proxy, host, and CSP settings. Never use wildcard credentialed CORS. |

Severity is a simple priority label, not a CVSS score.

## Security rules

| Rule | Expected behavior |
| --- | --- |
| Document access | The backend authorizes every document read and write. UI hiding is not access control. |
| Permissions | Grants apply to one user and one document. Categories do not grant access. |
| Revocation | Expired, revoked, suspended, or stale access fails on the next server request. |
| External users | External clients can receive READ access, never WRITE. |
| Uploads | Files are unavailable until size, checksum, signature, and malware checks pass. |
| AI suggestions | Suggestions never grant access without owner approval. |
| Audit | Verify the database chain and configured immutable archive; do not claim complete denial attribution. |

## Tests to keep

| Test file | Main coverage |
| --- | --- |
| `../backend/tests/test_authorization.py` | Access control, roles, MFA, OTP, audit, and shares. |
| `../backend/tests/test_document_deletion.py` | Soft deletion, related access revocation, and audit history. |
| `../backend/tests/test_codebase_fixes.py` | Security regression fixes. |
| `../backend/tests/test_schema_migrations.py` | Database migrations. |
| `../backend/tests/test_secret_config.py` | Secret configuration. |
| `../backend/tests/test_database_config.py` | Required database settings. |

Add tests when changing authorization or audit behavior. Include negative tests
that call the API as an unauthorized user. Use isolated test tenants and
harmless files; never use production credentials or real customer documents.

## Out of scope

| Not guaranteed |
| --- |
| Removing files already downloaded by recipients. |
| Folder-based permission inheritance, file version history, or user restore. |
| Protection from a fully compromised application, cloud account, or host administrator. |
| Complete attribution of unauthenticated or invalid-token requests. |
| Support or sanitization for every file type. |
| Correct AI recommendations or security of a recipient's email account. |
