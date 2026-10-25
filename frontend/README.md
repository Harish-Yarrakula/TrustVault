# TrustVault

TrustVault is a tenant-scoped document workspace for secure file uploads,
document-specific access, external sharing, and auditable activity. This
repository contains the React frontend. The FastAPI backend is a separate
sibling project at `../backend/`; deploy and configure the two projects
separately.

> **Documentation status:** This is the project guide for developers,
> evaluators, and operators. It describes the intended design and current
> documented behavior; verify cloud settings in the target environment.

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture guide](docs/architecture.html) | Components, trust boundaries, upload and download data flows, and deployment. Published at `/docs/architecture.html`. |
| [User workflow guide](docs/user-workflows.html) | Roles, invitations, sharing, user-facing features, and email behavior. Published at `/docs/user-workflows.html`. |
| [Threat model](THREATS.md) | Highest-priority risks, controls, known gaps, and test expectations. |
| [AI work log](PROMPTS.md) | Short retrospective of recorded AI-assisted changes; not a prompt transcript. |

## Features

| Feature | Description |
| --- | --- |
| Authentication | Account sign-in/out, server sessions, and TOTP MFA for administrators, with one-time recovery codes. |
| Document library | Tenant-scoped documents, categories, metadata, and browser-side filters. |
| Secure upload | PDF, PNG, and JPEG uploads with server-side size, checksum, signature, MIME, and malware checks before a file is available. |
| Document permissions | Named-user `READ` and `WRITE` grants, per-document expiry, and revocation. |
| External clients | Email invitation and activation; external clients are read-only and only see documents explicitly granted to them. |
| Share links | Expiry, revocation, download limits, optional passcode, and optional email OTP. |
| Audit and administration | Audit history and verification, administrator analytics, and persisted notifications. |
| Access suggestions | AI-assisted suggestions that do not grant access until a person approves them. |

### Roles and access

| Role / relationship | What it can do |
| --- | --- |
| `ADMIN` | Manage tenant members and settings, permissions, audit history, and analytics. Admin status alone does not grant document-byte access. Admins must enroll in MFA. |
| `MEMBER` | Access documents they own or documents with an active named grant. Owners manage access to their documents. |
| `EXTERNAL_CLIENT` | Access explicitly granted documents with `READ` permission only. |
| Document owner | A user who uploaded a document; can read it and manage its grants and share links. Ownership is not an account role. |

`WRITE` includes read access and the application's write-authorized document
operations. Grants apply to one user and one document. Categories organize the
library but do not inherit or widen permissions.

### Account creation

| Account | How it is created |
| --- | --- |
| Personal account | Self-registration is available for email domains classified by the backend as personal. A personal account has its own tenant. |
| First corporate administrator | An operator runs `backend/bootstrap_admin.py` with the target PostgreSQL configuration and enters a corporate-domain email. |
| Corporate member | An existing administrator sends an invitation; the member activates it from the emailed link. |
| External client | A document owner invites the client while granting access to a specific document. External clients are read-only. |

## Technology and architecture

| Layer | Technology / responsibility |
| --- | --- |
| Frontend | React 19, Vite, Tailwind CSS, and React Router. |
| Backend | Python 3.12 container, FastAPI, SQLModel, and PostgreSQL. |
| Document storage | Private S3-compatible bucket; the browser uploads with a short-lived presigned POST. |
| Malware scanning | ClamAV, reachable by the backend on a private network. |
| Email | Amazon SES for invitations, share links, and OTP messages. |
| Audit archive | Optional production archive in a separate versioned S3 Object Lock bucket. |
| Hosting | Static frontend and backend API are deployed independently; production API is intended to sit behind HTTPS reverse proxy. |

The backend is authoritative for authentication, tenant boundaries, document
permissions, revocation, and share status. The browser requests permission and
the backend checks current database state for each protected operation. A
document read is served through the API after authorization. Upload bytes go
directly to private storage, but the backend validates the object before
making it available.

In production, the backend Compose configuration binds its API port to
`127.0.0.1:8000`; expose it only through a trusted TLS reverse proxy. ClamAV
must remain private to the backend network.

## Known product limitations

| Area | Current limitation |
| --- | --- |
| Search | Search and owner/date filters operate on documents already loaded in the browser; they are not tenant-wide server search. |
| Owner filter | Matches owner ID rather than display name. |
| Folder access | Categories do not have inherited permissions. |
| Revocation | Blocks future server-mediated access but cannot recall a downloaded copy. |
| Recovery | End-user document version history and restore are not promised. |
| Audit attribution | Cookie-only failed requests and invalid identities are not comprehensively attributable; see [THREATS.md](THREATS.md). |

## Repository layout

```text
TrustVault/
├── backend/                 # sibling FastAPI / PostgreSQL project
│   ├── server.py
│   ├── db.py
│   ├── bootstrap_admin.py
│   ├── models/
│   └── tests/
└── frontend/                # this repository
    ├── src/
    │   ├── components/
    │   ├── pages/
    │   ├── layouts/
    │   └── utils/
    ├── docs/
    │   ├── architecture.html
    │   └── user-workflows.html
    ├── public/
    ├── README.md
    ├── THREATS.md
    └── PROMPTS.md
```

## Local development

### Prerequisites

| Tool / service | Needed for |
| --- | --- |
| Git | Cloning the frontend and backend repositories. |
| Node.js and npm | Installing and running the frontend. |
| Python 3.12 | Running the backend and backend tests. |
| PostgreSQL | Required backend database. SQLite is not the supported runtime database. |
| AWS credentials or compatible storage | Upload and document storage workflows. Use a local profile or isolated test credentials. |
| ClamAV | Malware scanning. Configure it for realistic upload testing; production requires it. |
| Amazon SES | Invitation and email workflows. Use a development-safe SES setup; do not use production recipients for tests. |

### 1. Clone both repositories

Replace the placeholders with the clone URLs for the frontend and backend
repositories. The backend is not nested in this frontend Git repository.

```powershell
New-Item -ItemType Directory -Force A:\TrustVault | Out-Null
Set-Location A:\TrustVault
git clone <FRONTEND_GITHUB_URL> frontend
git clone <BACKEND_GITHUB_URL> backend
```

### 2. Configure and start the backend

Create a local PostgreSQL database and user first. In a backend PowerShell
window:

```powershell
Set-Location A:\TrustVault\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

$env:DB_HOSTNAME = "localhost"
$env:DB_USERNAME = "<LOCAL_POSTGRES_USER>"
$env:DB_PASSWORD = "<LOCAL_POSTGRES_PASSWORD>"
$env:DB_NAME = "<LOCAL_DATABASE_NAME>"
$env:DB_PORT = "5432"
$env:DB_SSLMODE = "prefer"
$env:SECRET_KEY = "<LOCAL_RANDOM_SECRET_AT_LEAST_32_CHARACTERS>"
$env:ENVIRONMENT = "development"
$env:CORS_ORIGINS = "http://localhost:5173"
$env:ALLOWED_HOSTS = "localhost,127.0.0.1"
$env:FRONTEND_URL = "http://localhost:5173"
```

Use a local database setting appropriate to your PostgreSQL installation. The
defaults for `DB_PORT` and `DB_SSLMODE` are `5432` and `require`. Keep secrets
and credentials local; do not paste them into source files, commits, or chat.

Create the first administrator using the interactive bootstrap script:

```powershell
python bootstrap_admin.py
```

The script prompts for email, name, company, and password, and requires a
corporate email domain. It creates the first administrator for that tenant;
the bootstrap password must be 12-128 characters. It does not provide a
shared/default password. Admin users enroll in TOTP MFA when they sign in.
Keep the backend environment variables set in this window.

Start the API:

```powershell
python -m uvicorn server:app --reload --host 127.0.0.1 --port 8000
```

Backend startup creates/updates the supported database schema. For tests,
always use a separate disposable database, never a production database.

### 3. Start the frontend

In a second PowerShell window:

```powershell
Set-Location A:\TrustVault\frontend
npm install
$env:VITE_API_URL = "http://localhost:8000"
npm run dev
```

Open the Vite URL printed in the terminal, normally
`http://localhost:5173`. Vite may load ignored local environment files such as
`.env.local`; do not put secrets in frontend variables because `VITE_` values
are embedded in the browser build.

### 4. Configure optional integrations

Basic UI and authentication development need the API and PostgreSQL. Upload,
scan, and email features also need their respective services. The production
Compose file expects `/etc/trustvault/backend.env` and a private ClamAV service;
it is a deployment configuration, not a complete local database stack.

## Test account placeholders

There are no pre-created demo accounts or default passwords in this project.
Create isolated local test accounts and record their values in a password
manager or private local notes. Do not commit actual credentials here.

| Test account | Placeholder email | Role / setup | Password placeholder |
| --- | --- | --- | --- |
| Administrator | `<LOCAL_ADMIN_EMAIL>` | Create with `backend/bootstrap_admin.py`; use a corporate-domain email and enroll in TOTP MFA at first sign-in. | `<SET_A_UNIQUE_LOCAL_PASSWORD_12_PLUS_CHARACTERS>` |
| Internal member | `<LOCAL_MEMBER_EMAIL>` | Invite from the local administrator account, then accept the invitation. | `<SET_DURING_INVITATION>` |
| External client | `<LOCAL_EXTERNAL_EMAIL>` | Invite for one document and grant `READ`; verify that `WRITE` is unavailable. | `<SET_DURING_INVITATION>` |

These are **placeholders, not working accounts**. Use test-only email
addresses and services. If SES is unavailable, invitation and share-email
tests require a fake email service or appropriate backend tests.

## Configuration reference

Supply backend settings through process environment, a protected local
environment file, deployment secrets, or a secrets manager. The server loads
dotenv files, but never commit real `.env` files.

### Backend variables

| Variable | Required / default | Purpose |
| --- | --- | --- |
| `DB_HOSTNAME` | Required | PostgreSQL host. |
| `DB_USERNAME` | Required | PostgreSQL user. |
| `DB_PASSWORD` | Required | PostgreSQL password. |
| `DB_NAME` | Required | PostgreSQL database. |
| `DB_PORT` | `5432` | PostgreSQL port. |
| `DB_SSLMODE` | `require` | PostgreSQL TLS mode; select an appropriate local value for development. |
| `SECRET_KEY` | Required when signing/authentication is used; at least 32 characters | Signs tokens and encrypts MFA secret data. Use a cryptographically random value. |
| `ENVIRONMENT` | `development` | Set `production` to enable production cookie/HSTS behavior and production startup checks. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Session/access-token lifetime. |
| `ALGORITHM` | `HS256` | JWT signing algorithm; do not change without compatibility review. |
| `S3_BUCKET` | Required for readiness and document storage | Private document bucket. |
| `AWS_REGION` | AWS SDK configuration | Region for S3 and AWS integrations; AWS credentials should come from a protected profile or workload identity. |
| `S3_ENDPOINT_URL` | Optional | Custom S3-compatible endpoint. |
| `AUDIT_ARCHIVE_BUCKET` | Required by production startup | Separate versioned bucket with Object Lock enabled. |
| `AUDIT_RETENTION_DAYS` | `2555` | Positive Object Lock audit retention period. |
| `CLAMAV_HOST` | Required for production and scanning | Private ClamAV hostname. In Compose, the service name is `clamav`. |
| `CLAMAV_PORT` | `3310` | ClamAV port. |
| `CLAMAV_TIMEOUT_SECONDS` | `15` | Scanner connection and response timeout. |
| `MAX_DOCUMENT_SIZE_BYTES` | `26214400` (25 MiB) | Backend document size limit. Current frontend limit is 10 MiB. |
| `SES_FROM_EMAIL` | Required for email | Verified SES sender address. |
| `SES_REGION` | `AWS_REGION`, then `REGION` | SES region override. |
| `SES_CONFIGURATION_SET` | Optional | SES configuration set. |
| `FRONTEND_URL` | Local default `http://localhost:5173`; required HTTPS origin in production | Base URL used in invitation and share emails. Must match an allowed production CORS origin. |
| `CORS_ORIGINS` | Local default `http://localhost:5173` | Comma-separated exact origins allowed to make credentialed API requests. |
| `ALLOWED_HOSTS` | Local defaults `localhost,127.0.0.1` | Comma-separated API hostnames accepted by TrustedHost middleware. |
| `TRUST_PROXY` | `false` | Enable only when the app is behind a trusted proxy that sets forwarding headers. |

In production, the backend requires a configured ClamAV host and audit archive.
It verifies that the archive bucket has versioning and Object Lock enabled.
Keep the document and audit buckets private; do not grant the runtime role
unnecessary permissions, particularly deletion of locked audit versions.

### Frontend build variables

| Variable | Use |
| --- | --- |
| `VITE_API_URL` | Local development API origin; set to `http://localhost:8000`. Production builds use same-origin `/` paths through the static host proxy. |
| `VITE_S3_UPLOAD_ORIGIN` | Optional exact HTTPS origin allowed by the frontend CSP for presigned uploads. Configure it to match the storage origin returned by the API. |

`VITE_` variables are public build-time configuration, never secrets. The
production `public/_redirects` file proxies `/api/*` and `/users/me` to the
configured API host. Update that proxy when the production API host changes.
The production static host should also set CSP as an HTTP response header;
the HTML meta CSP cannot enforce `frame-ancestors`. Vite copies the HTML guides
from `docs/` into `dist/docs/` during production builds.

## User workflows

| Workflow | Summary |
| --- | --- |
| Administrator setup | Bootstrap the first corporate administrator, sign in, and complete TOTP MFA. |
| Member onboarding | Administrator invites a company member; the member activates their account from email. |
| Document sharing | Owner uploads a document, chooses one named recipient, and grants `READ` or `WRITE` as appropriate. |
| External access | Owner invites an external client with a `READ` grant on a specific document. |
| Link sharing | Owner creates an expiring, optionally protected link; recipient completes required passcode/OTP checks. |
| Audit and review | Administrators review audit events, analytics, and notifications; audit verification checks the chain/archive. |

Email delivery failures are errors, not successful invitations. Invitation,
share, OTP, MFA, and recovery secrets must not be copied into tickets, logs,
or screenshots.

## API reference map

The backend implements the API in `../backend/server.py`. These are route
groups, not a substitute for the request/response schemas in the source.

| Area | Representative routes |
| --- | --- |
| Health/readiness | `GET /health`, `GET /ready` |
| Authentication/MFA | `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/mfa/*`, `/users/me` |
| Members and guests | `/api/company/invitations`, `/api/company/members`, `/api/guests/*` |
| Documents and upload | `/api/documents`, `/api/documents/{id}`, `/api/documents/{id}/upload-url`, `/api/documents/{id}/complete-upload`, `/api/documents/{id}/content` |
| Permissions | `/api/documents/{id}/permissions` |
| Sharing | `/api/documents/{id}/shares`, `/api/shares/*` |
| AI access suggestions | `/api/ai/access-suggestions/*` |
| Audit/notifications | `/api/audit`, `/api/audit/verify`, `/api/notifications/*` |
| Administrator analytics | `/api/admin/analytics` |

## Tests and quality checks

Run frontend checks from this repository:

```powershell
npm run lint
npm run build
```

Run backend checks from the sibling backend directory, with isolated test
database configuration:

```powershell
python -m py_compile server.py models/schemas.py
python -m pytest -q tests
```

| Backend test file | Coverage area |
| --- | --- |
| `tests/test_authorization.py` | Authorization, roles, MFA, OTP, audit, and sharing. |
| `tests/test_document_deletion.py` | Soft deletion, dependent access revocation, and retained audit history. |
| `tests/test_codebase_fixes.py` | Regression fixes. |
| `tests/test_schema_migrations.py` | Schema compatibility and upgrades. |
| `tests/test_secret_config.py` | Secret configuration behavior. |
| `tests/test_database_config.py` | Required PostgreSQL configuration. |

Never run data-cleanup or destructive tests against production.

## Deployment checklist

| Step | Check |
| --- | --- |
| 1 | Build and lint the frontend; configure production `VITE_` build values without embedding secrets. |
| 2 | Deploy the backend separately, inject secrets from a protected source, and keep the API behind a TLS reverse proxy. |
| 3 | Keep PostgreSQL, S3 buckets, ClamAV, and audit archive access private and least-privileged. |
| 4 | Verify `/health` and `/ready`, TLS, CORS, CSP, SES, S3, PostgreSQL, ClamAV, and Object Lock configuration. |
| 5 | Use a dedicated test tenant/account to verify invitation, upload, permission denial, download, revocation, and audit verification. |
| 6 | Confirm that a test audit event can be verified against the immutable archive before relying on the archive in production. |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Frontend cannot reach API | Confirm API is on port 8000, set local `VITE_API_URL`, and allow `http://localhost:5173` in backend CORS. |
| Login fails after refresh | Check the API proxy/redirect rules and browser cookie settings; API requests must return JSON, not the SPA HTML page. |
| Readiness is unavailable | Check PostgreSQL connectivity and required storage configuration. |
| Upload fails | Check allowed PDF/PNG/JPEG type, 10 MiB frontend and backend size limits, presigned request, bucket CORS, storage permissions, and ClamAV health. |
| Invitation or OTP email fails | Check verified SES sender, SES region/account permissions, recipient restrictions, and backend logs without exposing tokens or codes. |
| Admin cannot access a document | Admin role does not imply file-byte access. Assign an explicit document permission or use the owner account. |
| Audit archive check fails | Verify Object Lock, versioning, retention, IAM permissions, and archive availability; do not bypass fail-closed behavior. |

## Security and privacy

| Practice | Requirement |
| --- | --- |
| Credentials | Keep database passwords, `SECRET_KEY`, AWS credentials, and test passwords outside Git. |
| Authorization | Enforce document access in the backend, never only in the UI. |
| Storage | Keep document storage private and use least-privilege access. |
| Malware | Do not disable production scanning to make an upload succeed. |
| Audit | Preserve audit history; do not delete evidence to work around data-retention issues. |
| Test data | Use harmless documents, isolated tenants, test-only identities, and non-production services. |
| Known gaps | Review [THREATS.md](THREATS.md); this documentation is not a penetration test or security certification. |
