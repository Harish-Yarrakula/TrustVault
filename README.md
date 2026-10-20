# 🛡️ TrustVault

> **Secure Corporate Document Sharing & Governance Platform**

TrustVault is an enterprise-grade document sharing platform built on a zero-trust, deny-by-default architecture. Designed for security-conscious organizations, TrustVault enforces strict per-document access controls, instant permission revocation, pre-storage payload validation, and an immutable append-only audit trail for full compliance and data integrity.

---

### ✨ Key Features

- **Zero-Trust Access Control (RBAC):** Strict separation between system administrators, resource owners, and viewers. Admins govern compliance without having unwarranted access to document contents.
- **Granular Per-Document Permissions:** Explicit `READ` and `EDIT` entitlements assigned to named users, enforced server-side on every request.
- **Instant Revocation:** Dynamic access invalidation that takes effect immediately, blocking cached session bypasses.
- **Pre-Storage Upload Validation:** Deep inspection of magic bytes, MIME types, payload size quotas, and filename sanitization to eliminate malicious file uploads.
- **Append-Only Audit Trail:** Comprehensive, immutable logging tracking uploads, downloads, edits, permission shifts, and unauthorized access attempts.
- **Unified User Workspace:** Seamless interface separating personal assets (`My Documents`) from shared enterprise files (`Shared With Me`) with context-aware action controls.
- **Multi-Parameter Search:** Real-time query filtering across filenames, document owners, categories, and date ranges.
