# TrustVault AI work log

Short summary of retained work. This is not a verbatim transcript. No source
commits were created for these entries; infrastructure updates were made by an
operator and have no source commit links.

| Date | Work | Outcome | Review note |
| --- | --- | --- | --- |
| 2026-10-25 | PostgreSQL configuration and cleanup | Required PostgreSQL settings, migrations, and configuration checks were added or verified. | Confirm the live schema and data separately; code changes alone do not prove live cleanup. |
| 2026-10-25 | Tenant authorization and failed-upload cleanup | Failed uploads use soft deletion, revoke dependent access, and retain audit history. | Never delete audit evidence to work around foreign-key constraints. |
| 2026-10-25 | Immutable audit archive | Diagnosed missing S3 bucket-list permission; operator applied a narrowly scoped permission. Archive errors remain fail-closed. | Do not treat every AccessDenied response as a missing object. |
| 2026-10-25 | Live upload validation | Kept the bucket private and corrected its CORS origin for browser uploads. | Do not make storage public or disable scanning to fix upload problems. |
| 2026-10-25 | Download filename preservation | Downloads retain the uploaded filename and extension. | Do not replace the source filename with one inferred from MIME type. |
| 2026-10-25 | Project and workflow documentation | Added project, threat, prompt, and user-workflow documentation. | OTP email and share-link behavior must be described accurately. |
| 2026-10-25 | Refresh and share failures | Added same-origin API rewrites, stricter response checks, clearer errors, and OTP share-link email behavior. | Local checks passed; deployment of the updated frontend artifact was still required. |
| 2026-10-25 | OTP share 401 follow-up | Added rate-limited OTP resend and clearer expired-session guidance. | A 401 can mean an expired share session; the OTP may also expire before the recipient opens the link. |
| 2026-10-25 | Final project documentation | Expanded the README, clarified admin and dummy-account placeholders, and aligned the architecture and user-workflow guides with the threat model. | Account values are unprovisioned placeholders. No credentials or commit IDs are included. |

## Project context

| Area | Summary |
| --- | --- |
| Frontend | React and Vite. |
| Backend | FastAPI, SQLModel, and PostgreSQL in a sibling source tree. |
| Authorization | The backend enforces per-document access; frontend controls are not security boundaries. |
| Audit | Preserve audit history. Do not remove evidence to simplify deletion. |
| Upload safety | Keep malware scanning enabled and object storage private. |
| Sensitive data | Never place credentials, tokens, MFA secrets, recovery codes, or OTPs in prompts or logs. |
| Commit history | Add a real commit link only after the relevant change is committed. |
| Documentation | Use the README as the setup reference; HTML pages explain architecture and user flows; threat gaps must remain explicit. |
