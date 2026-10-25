"""TrustVault API.

All access to tenant-owned resources is scoped through the authenticated user's
company_id.  Secrets and bearer/share tokens are only accepted transiently and
are stored as hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import base64
import binascii
import os
import re
import secrets
import struct
import socket
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import EmailStr, Field as PydanticField
from sqlmodel import Field, Session, SQLModel, select
from sqlalchemy import case, inspect, text, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from starlette.middleware.trustedhost import TrustedHostMiddleware

from db import engine, get_db, init_db
from email_service import EmailDeliveryError, send_guest_invitation, send_share_link, send_share_otp
from models import (
    AccountType, AccessSuggestion, AuditAction, AuditEvent, Company, CompanyUser, Document,
    DocumentPermission, DocumentShareLink, PermissionLevel, ShareLinkStatus,
    RateLimitBucket, UserRole, UserStatus, UserNotification, normalize_email,
)

load_dotenv()
app = FastAPI(title="TrustVault API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
hosts = [x.strip() for x in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
                   expose_headers=["Content-Disposition"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
AUTH_COOKIE = "trustvault_auth"


def now() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


ALLOWED_DOCUMENT_TYPES = {"application/pdf", "image/png", "image/jpeg"}
SHARE_SESSION_COOKIE = "trustvault_share_session"


def validate_content_type(content_type: str) -> str:
    normalized = content_type.split(";", 1)[0].strip().lower()
    if normalized not in ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(415, "Only PDF, PNG, and JPEG documents are supported")
    return normalized


def max_document_size_bytes() -> int:
    try:
        maximum = int(os.getenv("MAX_DOCUMENT_SIZE_BYTES", str(25 * 1024 * 1024)))
    except ValueError as exc:
        raise RuntimeError("MAX_DOCUMENT_SIZE_BYTES must be a positive integer") from exc
    if maximum <= 0:
        raise RuntimeError("MAX_DOCUMENT_SIZE_BYTES must be a positive integer")
    return maximum


def detect_document_type(prefix: bytes) -> str | None:
    if prefix.startswith(b"%PDF-"):
        return "application/pdf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    return None


def start_malware_scan() -> socket.socket | None:
    host = os.getenv("CLAMAV_HOST")
    if not host:
        if os.getenv("ENVIRONMENT", "development") == "production":
            raise HTTPException(503, "Malware scanner is not configured")
        return None
    try:
        port = int(os.getenv("CLAMAV_PORT", "3310"))
        timeout = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "15"))
        scanner = socket.create_connection((host, port), timeout=timeout)
        scanner.settimeout(timeout)
        scanner.sendall(b"zINSTREAM\0")
        return scanner
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "Malware scanner is unavailable") from exc


def scan_chunk(scanner: socket.socket | None, chunk: bytes) -> None:
    if scanner is None:
        return
    try:
        scanner.sendall(struct.pack(">I", len(chunk)) + chunk)
    except OSError as exc:
        scanner.close()
        raise HTTPException(503, "Malware scanner is unavailable") from exc


def finish_malware_scan(scanner: socket.socket | None) -> None:
    if scanner is None:
        return
    try:
        scanner.sendall(b"\0\0\0\0")
        result = bytearray()
        while not result.endswith((b"\0", b"\n")):
            chunk = scanner.recv(1024)
            if not chunk:
                raise OSError("Malware scanner closed the connection without a result")
            result.extend(chunk)
            if len(result) > 4096:
                raise HTTPException(503, "Malware scanner returned an invalid response")
        if b"FOUND" in result:
            raise HTTPException(422, "Malware was detected in the uploaded document")
        if b" OK" not in result:
            raise HTTPException(503, "Malware scanner returned an invalid response")
    except OSError as exc:
        raise HTTPException(503, "Malware scanner is unavailable") from exc
    finally:
        scanner.close()


def share_session_value(link: DocumentShareLink) -> str:
    expires = int(min(link.expires_at, now() + timedelta(minutes=10)).timestamp())
    payload = f"{link.id}:{expires}"
    signature = hmac.new(config_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def set_share_session_cookie(response: Response, link: DocumentShareLink) -> None:
    production = os.getenv("ENVIRONMENT", "development") == "production"
    response.set_cookie(
        SHARE_SESSION_COOKIE,
        share_session_value(link),
        max_age=600,
        httponly=True,
        secure=production,
        samesite="none" if production else "lax",
    )


def valid_share_session(request: Request, link: DocumentShareLink) -> bool:
    value = request.cookies.get(SHARE_SESSION_COOKIE, "")
    parts = value.split(":")
    if len(parts) != 3 or parts[0] != str(link.id):
        return False
    try:
        expires = int(parts[1])
    except ValueError:
        return False
    payload = f"{parts[0]}:{parts[1]}"
    expected = hmac.new(config_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return expires > int(now().timestamp()) and hmac.compare_digest(parts[2], expected)


def share_link_from_session(request: Request, db: Session) -> DocumentShareLink:
    value = request.cookies.get(SHARE_SESSION_COOKIE, "")
    parts = value.split(":")
    if len(parts) != 3:
        raise HTTPException(401, "Share session is missing or expired")
    try:
        link_id = UUID(parts[0])
        expires = int(parts[1])
    except ValueError:
        raise HTTPException(401, "Share session is missing or expired") from None
    payload = f"{parts[0]}:{parts[1]}"
    expected = hmac.new(config_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    if expires <= int(now().timestamp()) or not hmac.compare_digest(parts[2], expected):
        raise HTTPException(401, "Share session is missing or expired")
    link = db.get(DocumentShareLink, link_id)
    if (
        not link
        or link.status != ShareLinkStatus.ACTIVE
        or link.expires_at <= now()
        or expires > int(link.expires_at.timestamp())
    ):
        raise HTTPException(404, "Share link unavailable")
    return link


def safe_download_headers(name: str) -> dict[str, str]:
    safe_name = name.replace("\\", "/").rsplit("/", 1)[-1]
    safe_name = safe_name.replace('"', "").replace("\r", "").replace("\n", "") or "document"
    encoded_name = quote(safe_name, safe="")
    return {
        "Content-Disposition": f'attachment; filename="{safe_name}"; filename*=UTF-8\'\'{encoded_name}',
        "X-Content-Type-Options": "nosniff",
    }


def client_ip(request: Request) -> str | None:
    if os.getenv("TRUST_PROXY", "false").lower() == "true":
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt, expected = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def encrypt_mfa_secret(user_id: UUID, secret: str) -> str:
    key = hashlib.sha256(("trustvault-mfa:" + config_secret()).encode()).digest()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode(), str(user_id).encode())
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_mfa_secret(user_id: UUID, encrypted: str) -> str:
    try:
        value = base64.urlsafe_b64decode(encrypted.encode())
        key = hashlib.sha256(("trustvault-mfa:" + config_secret()).encode()).digest()
        return AESGCM(key).decrypt(value[:12], value[12:], str(user_id).encode()).decode()
    except (binascii.Error, InvalidTag, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise RuntimeError("Stored MFA secret could not be decrypted") from exc


def totp_code(secret: str, step: int) -> str:
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verified_totp_step(secret: str, code: str, last_step: int | None = None) -> int | None:
    if not re.fullmatch(r"\d{6}", code):
        return None
    current_step = int(now().timestamp()) // 30
    for step in range(current_step - 1, current_step + 2):
        if (last_step is None or step > last_step) and hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def consume_recovery_code(user: CompanyUser, code: str, db: Session) -> bool:
    recovery_hashes = json.loads(user.mfa_recovery_hashes or "[]")
    candidate = token_hash(code.strip().upper())
    matching = next((value for value in recovery_hashes if hmac.compare_digest(value, candidate)), None)
    if matching is None:
        return False
    remaining = json.dumps([value for value in recovery_hashes if value != matching])
    result = db.exec(update(CompanyUser).where(
        CompanyUser.id == user.id,
        CompanyUser.mfa_recovery_hashes == user.mfa_recovery_hashes,
    ).values(mfa_recovery_hashes=remaining))
    return result.rowcount == 1


def config_secret() -> str:
    secret = (os.getenv("SECRET_KEY") or "").strip()
    placeholders = {
        "",
        "change-me",
        "changeme",
        "development-only-change-me",
        "<paste the openssl output>",
    }
    invalid = len(secret) < 32 or secret.lower() in placeholders
    if invalid and os.getenv("ENVIRONMENT", "development").lower() == "production":
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters")
    return secret if not invalid else "development-only-insecure-secret-change-me"


def create_access_token(user: CompanyUser) -> str:
    jti = str(uuid4())
    expires = now() + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
    return jwt.encode({"sub": str(user.id), "company_id": str(user.company_id),
                       "session_version": user.session_version, "jti": jti, "exp": expires},
                      config_secret(), algorithm=os.getenv("ALGORITHM", "HS256"))


class RegisterRequest(SQLModel):
    full_name: str = PydanticField(min_length=1, max_length=255)
    email: EmailStr
    password: str = PydanticField(min_length=8, max_length=128)
    company_name: str | None = PydanticField(default=None, max_length=255)
    role: UserRole = UserRole.MEMBER


class MfaCodeRequest(SQLModel):
    code: str = PydanticField(min_length=6, max_length=32)


class MfaChallengeRequest(MfaCodeRequest):
    challenge_token: str = PydanticField(min_length=20, max_length=2048)


class UserResponse(SQLModel):
    id: UUID
    company_id: UUID
    company_name: str | None = None
    email: EmailStr
    full_name: str
    account_type: AccountType
    role: UserRole
    status: UserStatus


class MemberResponse(UserResponse):
    created_at: datetime


class MemberRoleUpdate(SQLModel):
    role: UserRole


class DocumentCreate(SQLModel):
    name: str = PydanticField(min_length=1, max_length=255)
    category: str = PydanticField(default="Other", min_length=1, max_length=100)
    content_sha256: str = PydanticField(min_length=64, max_length=64)
    content_type: str = PydanticField(default="application/octet-stream", max_length=255)
    file_size: int = PydanticField(gt=0)


class DocumentUpdate(SQLModel):
    name: str = PydanticField(min_length=1, max_length=255)
    category: str = PydanticField(default="Other", min_length=1, max_length=100)


class DocumentResponse(SQLModel):
    id: UUID
    owner_id: UUID
    name: str
    category: str
    content_sha256: str
    content_type: str
    created_at: datetime
    updated_at: datetime


class AuditEventResponse(SQLModel):
    id: UUID
    actor_user_id: UUID | None
    actor_email: EmailStr | None = None
    actor_name: str | None = None
    document_id: UUID | None
    document_name: str | None = None
    share_link_id: UUID | None
    action: AuditAction
    details: str | None
    request_id: str | None
    ip_address: str | None
    occurred_at: datetime


class NotificationResponse(SQLModel):
    id: UUID
    audit_event_id: UUID
    action: AuditAction
    details: str | None
    document_id: UUID | None = None
    document_name: str | None = None
    actor_name: str | None = None
    occurred_at: datetime
    read_at: datetime | None


class NotificationReadRequest(SQLModel):
    notification_ids: list[UUID] = PydanticField(min_length=1, max_length=200)


class UploadCompletionResponse(SQLModel):
    verified: bool
    content_sha256: str
    content_length: int | None = None


class PermissionRequest(SQLModel):
    user_id: UUID
    permission_level: PermissionLevel
    expires_at: datetime | None = None


class GuestInviteRequest(SQLModel):
    email: EmailStr
    expires_at: datetime | None = None
    document_id: UUID | None = None
    permission_level: PermissionLevel = PermissionLevel.READ


class GuestAcceptRequest(SQLModel):
    token: str = PydanticField(min_length=20, max_length=256)
    password: str = PydanticField(min_length=8, max_length=128)


class MemberInviteRequest(SQLModel):
    email: EmailStr
    expires_at: datetime | None = None


class ShareRequest(SQLModel):
    expires_at: datetime
    max_downloads: int = PydanticField(default=1, ge=1, le=1000)
    recipient_email: EmailStr | None = None
    passcode: str | None = PydanticField(default=None, min_length=6, max_length=128)
    require_otp: bool = False


class ShareResponse(SQLModel):
    id: UUID
    url: str
    expires_at: datetime
    max_downloads: int


class OtpVerificationRequest(SQLModel):
    otp: str = PydanticField(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ShareAccessRequest(SQLModel):
    passcode: str | None = PydanticField(default=None, min_length=6, max_length=128)


class ShareExchangeRequest(SQLModel):
    token: str = PydanticField(min_length=32, max_length=256)


class GuestResponse(SQLModel):
    id: UUID
    email: EmailStr
    role: UserRole
    status: UserStatus
    invitation_expires_at: datetime | None
    access_expires_at: datetime | None


class PermissionResponse(SQLModel):
    id: UUID
    user_id: UUID
    permission_level: PermissionLevel
    granted_by: UUID
    expires_at: datetime | None
    revoked_at: datetime | None


class ShareLinkResponse(SQLModel):
    id: UUID
    document_id: UUID
    recipient_email: EmailStr
    status: ShareLinkStatus
    max_downloads: int
    download_count: int
    expires_at: datetime
    created_at: datetime


class AccessSuggestionRequest(SQLModel):
    document_id: UUID
    user_id: UUID | None = None


class AccessSuggestionResponse(SQLModel):
    id: UUID
    document_id: UUID
    suggested_user_id: UUID
    suggested_email: EmailStr
    permission_level: PermissionLevel
    rationale: str
    status: str
    created_at: datetime


class AccessDecisionRequest(SQLModel):
    approve: bool
    permission_level: PermissionLevel | None = None


def rate_limit(
    request: Request,
    key: str,
    db: Session,
    limit: int = 10,
    window: int = 60,
) -> None:
    key_hashes = {
        token_hash(f"{client_ip(request) or 'unknown'}:{key}"),
        token_hash(f"global:{key}"),
    }
    current_time = now()
    cutoff = current_time - timedelta(seconds=window)
    if secrets.randbelow(100) == 0:
        db.exec(
            text("DELETE FROM rate_limit_buckets WHERE window_started_at < :cutoff"),
            params={"cutoff": current_time - timedelta(days=1)},
        )
    if engine.dialect.name == "postgresql":
        insert_bucket = postgresql_insert
    elif engine.dialect.name == "sqlite":
        insert_bucket = sqlite_insert
    else:
        raise RuntimeError("Database rate limiting supports PostgreSQL and test SQLite")
    attempt_counts = []
    for key_hash in sorted(key_hashes):
        statement = insert_bucket(RateLimitBucket).values(
            key_hash=key_hash,
            window_started_at=current_time,
            attempt_count=1,
        )
        statement = statement.on_conflict_do_update(
            index_elements=[RateLimitBucket.key_hash],
            set_={
                "window_started_at": case(
                    (RateLimitBucket.window_started_at <= cutoff, current_time),
                    else_=RateLimitBucket.window_started_at,
                ),
                "attempt_count": case(
                    (RateLimitBucket.window_started_at <= cutoff, 1),
                    else_=RateLimitBucket.attempt_count + 1,
                ),
            },
        ).returning(RateLimitBucket.attempt_count)
        attempt_counts.append(db.exec(statement).one()[0])
    db.commit()
    if max(attempt_counts) > limit:
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(window)})


def current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> CompanyUser:
    unauthorized = HTTPException(401, "Could not validate credentials", {"WWW-Authenticate": "Bearer"})
    token = token or request.cookies.get(AUTH_COOKIE)
    if not token:
        raise unauthorized
    try:
        payload = jwt.decode(token, config_secret(), algorithms=[os.getenv("ALGORITHM", "HS256")])
        user_id = UUID(payload["sub"])
        if db.exec(select(TokenRevocation).where(TokenRevocation.jti == payload.get("jti"))).first():
            raise unauthorized
    except (JWTError, KeyError, ValueError):
        raise unauthorized from None
    user = db.get(CompanyUser, user_id)
    if (
        not user
        or user.status != UserStatus.ACTIVE
        or payload.get("session_version") != user.session_version
        or payload.get("company_id") != str(user.company_id)
        or (
            user.access_expires_at is not None
            and user.access_expires_at <= now()
        )
    ):
        raise unauthorized
    if (
        user.role == UserRole.ADMIN
        and not user.mfa_enabled
        and request.url.path not in {
            "/api/auth/mfa/setup",
            "/api/auth/mfa/confirm",
            "/api/auth/logout",
        }
    ):
        raise HTTPException(403, "Administrator MFA enrollment is required")
    return user


def require_roles(*roles: UserRole):
    def dependency(user: CompanyUser = Depends(current_user)) -> CompanyUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return user
    return dependency


@app.post("/api/company/invitations", status_code=201)
def invite_company_member(
    data: MemberInviteRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> dict[str, Any]:
    rate_limit(request, f"member-invite:{user.company_id}:{user.id}", db, limit=10, window=3600)
    email = normalize_email(str(data.email))
    if db.exec(select(CompanyUser.id).where(CompanyUser.email == email)).first():
        raise HTTPException(409, "Email is already registered")
    expires_at = data.expires_at or (now() + timedelta(days=7))
    if expires_at <= now():
        raise HTTPException(400, "Invitation expiry must be in the future")
    raw = secrets.token_urlsafe(32)
    member = CompanyUser(
        company_id=user.company_id,
        email=email,
        password_hash=hash_password(secrets.token_urlsafe(24)),
        account_type=AccountType.CORPORATE,
        role=UserRole.MEMBER,
        status=UserStatus.INVITED,
        invitation_token_hash=token_hash(raw),
        invitation_expires_at=expires_at,
        invited_by=user.id,
    )
    db.add(member)
    db.flush()
    try:
        send_guest_invitation(email, raw, expires_at)
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(503, "Invitation email could not be sent") from exc
    audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
          details="member_invitation")
    audit(db, request, user, AuditAction.GUEST_INVITED, user.company_id,
          details=f"member_invitation member={member.id} expires_at={expires_at.isoformat()}")
    db.commit()
    return {"id": str(member.id), "expires_at": expires_at, "delivery": "sent"}


def tenant_document(
db: Session,
user: CompanyUser,
document_id: UUID,
required_permission: PermissionLevel = PermissionLevel.READ,
) -> Document:
    document = db.get(Document, document_id)
    if not document or document.company_id != user.company_id or document.deleted_at:
        raise HTTPException(404, "Document not found")
    permission = db.exec(select(DocumentPermission).where(
        DocumentPermission.document_id == document.id,
        DocumentPermission.user_id == user.id,
        DocumentPermission.revoked_at.is_(None),
        (DocumentPermission.expires_at.is_(None) | (DocumentPermission.expires_at > now())),
    )).first()
    levels = {PermissionLevel.READ: 1, PermissionLevel.WRITE: 2}
    if document.owner_id != user.id:
        if not permission or levels[permission.permission_level] < levels[required_permission]:
            raise HTTPException(403, "Document access denied")
    return document


def tenant_admin_document(db: Session, user: CompanyUser, document_id: UUID) -> Document:
    document = db.get(Document, document_id)
    if not document or document.company_id != user.company_id or document.deleted_at:
        raise HTTPException(404, "Document not found")
    if user.role != UserRole.ADMIN and document.owner_id != user.id:
        raise HTTPException(403, "Owner access required")
    return document


def audit(db: Session, request: Request, user: CompanyUser | None, action: AuditAction,
          company_id: UUID, document_id: UUID | None = None, share_link_id: UUID | None = None,
          details: str | None = None) -> AuditEvent:
    db.exec(select(Company.id).where(Company.id == company_id).with_for_update()).first()
    previous = db.exec(select(AuditEvent).where(AuditEvent.company_id == company_id)
                       .order_by(AuditEvent.sequence_number.desc())).first()
    sequence = (previous.sequence_number + 1) if previous else 1
    previous_hash = previous.event_hash if previous else None
    occurred_at = now()
    body = json.dumps({
        "company_id": str(company_id),
        "sequence": sequence,
        "occurred_at": occurred_at.isoformat(),
        "action": action.value,
        "actor_user_id": str(user.id) if user else None,
        "document_id": str(document_id) if document_id else None,
        "share_link_id": str(share_link_id) if share_link_id else None,
        "details": details,
        "ip_address": client_ip(request),
        "request_id": getattr(request.state, "request_id", None),
        "user_agent": request.headers.get("user-agent"),
        "previous_hash": previous_hash,
    }, sort_keys=True, separators=(",", ":"))
    event_hash = hashlib.sha256(body.encode()).hexdigest()
    event = AuditEvent(company_id=company_id, actor_user_id=user.id if user else None,
                       action=action, document_id=document_id, share_link_id=share_link_id,
                       details=details,
                       ip_address=client_ip(request),
                       request_id=getattr(request.state, "request_id", None),
                       user_agent=request.headers.get("user-agent"),
                       occurred_at=occurred_at,
                       sequence_number=sequence, previous_event_hash=previous_hash, event_hash=event_hash)
    db.add(event)
    if action in {AuditAction.USER_LOGIN_FAILED, AuditAction.EMAIL_FAILED, AuditAction.ACCESS_DENIED}:
        db.flush()
        admins = db.exec(select(CompanyUser).where(
            CompanyUser.company_id == company_id,
            CompanyUser.role == UserRole.ADMIN,
            CompanyUser.status == UserStatus.ACTIVE,
        ))
        for admin in admins:
            db.add(UserNotification(user_id=admin.id, audit_event_id=event.id))
    if os.getenv("AUDIT_ARCHIVE_BUCKET"):
        db.flush()
        archive_audit_event(event)
    return event


def audit_payload(event: AuditEvent) -> str:
    occurred_at = event.occurred_at
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=timezone.utc)
    else:
        occurred_at = occurred_at.astimezone(timezone.utc)
    return json.dumps({
        "company_id": str(event.company_id),
        "sequence": event.sequence_number,
        "occurred_at": occurred_at.isoformat(),
        "action": event.action.value,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "document_id": str(event.document_id) if event.document_id else None,
        "share_link_id": str(event.share_link_id) if event.share_link_id else None,
        "details": event.details,
        "ip_address": event.ip_address,
        "request_id": event.request_id,
        "user_agent": event.user_agent,
        "previous_hash": event.previous_event_hash,
    }, sort_keys=True, separators=(",", ":"))


def previous_audit_payload(event: AuditEvent) -> str:
    return json.dumps({
        "company_id": str(event.company_id),
        "sequence": event.sequence_number,
        "action": event.action.value,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "document_id": str(event.document_id) if event.document_id else None,
        "share_link_id": str(event.share_link_id) if event.share_link_id else None,
        "details": event.details,
        "ip_address": event.ip_address,
        "request_id": event.request_id,
        "user_agent": event.user_agent,
        "previous_hash": event.previous_event_hash,
    }, sort_keys=True, separators=(",", ":"))


def legacy_audit_payload(event: AuditEvent) -> str:
    return json.dumps({
        "company_id": str(event.company_id),
        "sequence": event.sequence_number,
        "action": event.action.value,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "document_id": str(event.document_id) if event.document_id else None,
        "share_link_id": str(event.share_link_id) if event.share_link_id else None,
        "details": event.details,
        "request_id": event.request_id,
        "previous_hash": event.previous_event_hash,
    }, sort_keys=True, separators=(",", ":"))


def audit_payload_candidates(event: AuditEvent) -> tuple[str, ...]:
    return (
        audit_payload(event),
        previous_audit_payload(event),
        legacy_audit_payload(event),
    )


def audit_archive_key(event: AuditEvent) -> str:
    return (
        f"audit/{event.company_id}/{event.sequence_number:020d}-"
        f"{event.event_hash}.json"
    )


def audit_archive_body(event: AuditEvent) -> bytes:
    for payload in audit_payload_candidates(event):
        if hmac.compare_digest(
            hashlib.sha256(payload.encode()).hexdigest(), event.event_hash
        ):
            return json.dumps({
                "event_hash": event.event_hash,
                "payload": json.loads(payload),
            }, sort_keys=True, separators=(",", ":")).encode()
    raise HTTPException(409, "Audit event hash does not match its contents")


def archive_audit_event(event: AuditEvent) -> None:
    bucket = os.getenv("AUDIT_ARCHIVE_BUCKET")
    if not bucket:
        return
    key = audit_archive_key(event)
    body = audit_archive_body(event)
    client = s3_client()
    create_object = False
    try:
        client.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in {"404", "NoSuchKey", "NotFound"}:
            raise HTTPException(503, "Immutable audit storage is unavailable") from exc
        create_object = True
    except BotoCoreError as exc:
        raise HTTPException(503, "Immutable audit storage is unavailable") from exc
    if create_object:
        try:
            retention_days = int(os.getenv("AUDIT_RETENTION_DAYS", "2555"))
            if retention_days < 1:
                raise ValueError("AUDIT_RETENTION_DAYS must be positive")
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=now() + timedelta(days=retention_days),
            )
        except (BotoCoreError, ClientError, ValueError) as write_error:
            raise HTTPException(503, "Immutable audit event could not be archived") from write_error
    try:
        response = client.get_object(Bucket=bucket, Key=key)
        archived = response["Body"].read()
        response["Body"].close()
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(503, "Immutable audit event could not be verified") from exc
    if not hmac.compare_digest(archived, body):
        raise HTTPException(409, "Audit archive sequence already contains different content")


class TokenRevocation(SQLModel, table=True):
    __tablename__ = "token_revocations"
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    jti: str = Field(max_length=64, unique=True, index=True)
    revoked_at: datetime = Field(default_factory=now)


def ensure_postgres_enum_values(db: Session) -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Schema migrations require PostgreSQL")
    db.exec(text("ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'EXTERNAL_CLIENT'"))
    db.exec(text("ALTER TYPE permissionlevel ADD VALUE IF NOT EXISTS 'READ'"))
    db.exec(text("ALTER TYPE permissionlevel ADD VALUE IF NOT EXISTS 'WRITE'"))
    for action in AuditAction:
        db.exec(text(
            f"ALTER TYPE auditaction ADD VALUE IF NOT EXISTS '{action.value}'"
        ))
    db.commit()


def ensure_audit_event_columns(db: Session) -> None:
    columns = {
        column["name"] for column in inspect(engine).get_columns("audit_events")
    }
    if "request_id" not in columns:
        db.exec(text("ALTER TABLE audit_events ADD COLUMN request_id VARCHAR(100)"))
    if "user_agent" not in columns:
        db.exec(text("ALTER TABLE audit_events ADD COLUMN user_agent VARCHAR(512)"))
    db.exec(text(
        "CREATE INDEX IF NOT EXISTS ix_audit_events_request_id "
        "ON audit_events (request_id)"
    ))
    db.commit()


def ensure_document_schema(db: Session) -> None:
    columns = {
        column["name"] for column in inspect(engine).get_columns("documents")
    }
    if "content_type" not in columns:
        db.exec(text(
            "ALTER TABLE documents ADD COLUMN content_type VARCHAR(255) "
            "NOT NULL DEFAULT 'application/octet-stream'"
        ))
    if "deleted_at" not in columns:
        db.exec(text("ALTER TABLE documents ADD COLUMN deleted_at TIMESTAMP NULL"))
    if engine.dialect.name == "postgresql":
        for constraint in inspect(engine).get_unique_constraints("documents"):
            if set(constraint.get("column_names") or ()) == {
                "company_id",
                "content_sha256",
            }:
                name = engine.dialect.identifier_preparer.quote(constraint["name"])
                db.exec(text(f"ALTER TABLE documents DROP CONSTRAINT {name}"))
    db.exec(text(
        "CREATE INDEX IF NOT EXISTS ix_documents_category "
        "ON documents (category)"
    ))
    db.exec(text(
        "CREATE INDEX IF NOT EXISTS ix_documents_upload_verified_at "
        "ON documents (upload_verified_at)"
    ))
    db.exec(text(
        "CREATE INDEX IF NOT EXISTS ix_documents_deleted_at "
        "ON documents (deleted_at)"
    ))
    db.exec(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_documents_company_checksum_active "
        "ON documents (company_id, content_sha256) WHERE deleted_at IS NULL"
    ))
    db.commit()


def ensure_password_hash_column_width(db: Session) -> None:
    column = next(
        column
        for column in inspect(engine).get_columns("company_users")
        if column["name"] == "password_hash"
    )
    current_length = getattr(column["type"], "length", None)
    required_length = CompanyUser.__table__.c.password_hash.type.length
    if current_length is not None and current_length < required_length:
        db.exec(text(
            f"ALTER TABLE company_users ALTER COLUMN password_hash "
            f"TYPE VARCHAR({required_length})"
        ))
        db.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()
    if os.getenv("ENVIRONMENT", "development") == "production":
        if not os.getenv("CLAMAV_HOST") or not os.getenv("AUDIT_ARCHIVE_BUCKET"):
            raise RuntimeError("Production requires CLAMAV_HOST and AUDIT_ARCHIVE_BUCKET")
        frontend_url = os.getenv("FRONTEND_URL", "").rstrip("/")
        parsed_frontend_url = urlsplit(frontend_url)
        if (
            parsed_frontend_url.scheme != "https"
            or not parsed_frontend_url.netloc
            or parsed_frontend_url.path
            or parsed_frontend_url.query
            or parsed_frontend_url.fragment
            or frontend_url not in origins
        ):
            raise RuntimeError(
                "Production FRONTEND_URL must be an HTTPS origin included in CORS_ORIGINS"
            )
        config_secret()
        max_document_size_bytes()
        try:
            scanner_port = int(os.getenv("CLAMAV_PORT", "3310"))
            scanner_timeout = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "15"))
            retention_days = int(os.getenv("AUDIT_RETENTION_DAYS", "2555"))
            access_token_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        except ValueError as exc:
            raise RuntimeError("Production security limits must use valid numeric values") from exc
        if not 1 <= scanner_port <= 65535 or not 0 < scanner_timeout < 3600:
            raise RuntimeError("CLAMAV_PORT and CLAMAV_TIMEOUT_SECONDS are invalid")
        if retention_days < 1 or access_token_minutes < 1:
            raise RuntimeError("Audit retention and access-token lifetime must be positive")
        archive_bucket = os.environ["AUDIT_ARCHIVE_BUCKET"]
        try:
            storage = s3_client()
            versioning = storage.get_bucket_versioning(Bucket=archive_bucket)
            lock = storage.get_object_lock_configuration(Bucket=archive_bucket)
        except (BotoCoreError, ClientError) as exc:
            raise RuntimeError("Immutable audit bucket configuration could not be verified") from exc
        if versioning.get("Status") != "Enabled" or lock.get(
            "ObjectLockConfiguration", {}
        ).get("ObjectLockEnabled") != "Enabled":
            raise RuntimeError("Audit archive bucket must have versioning and Object Lock enabled")
    with Session(engine) as db:
        if engine.dialect.name == "postgresql":
            ensure_postgres_enum_values(db)
        ensure_audit_event_columns(db)
        ensure_document_schema(db)
        ensure_password_hash_column_width(db)
        columns = {column["name"] for column in inspect(engine).get_columns("company_users")}
        if "full_name" not in columns:
            db.exec(text("ALTER TABLE company_users ADD COLUMN full_name VARCHAR(255) NOT NULL DEFAULT ''"))
        if "session_version" not in columns:
            db.exec(text("ALTER TABLE company_users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0"))
        mfa_columns = {
            "mfa_enabled": "BOOLEAN NOT NULL DEFAULT FALSE",
            "mfa_secret_encrypted": "VARCHAR(512) NULL",
            "mfa_pending_secret_encrypted": "VARCHAR(512) NULL",
            "mfa_recovery_hashes": "TEXT NULL",
            "mfa_last_verified_step": "INTEGER NULL",
        }
        for column, definition in mfa_columns.items():
            if column not in columns:
                db.exec(text(f"ALTER TABLE company_users ADD COLUMN {column} {definition}"))
        document_columns = {column["name"] for column in inspect(engine).get_columns("documents")}
        if "category" not in document_columns:
            db.exec(text("ALTER TABLE documents ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT 'Other'"))
        if "upload_verified_at" not in document_columns:
            db.exec(text("ALTER TABLE documents ADD COLUMN upload_verified_at TIMESTAMP NULL"))
        if "expected_size" not in document_columns:
            db.exec(text("ALTER TABLE documents ADD COLUMN expected_size INTEGER NULL"))
        share_columns = {column["name"] for column in inspect(engine).get_columns("document_share_links")}
        if "otp_attempts" not in share_columns:
            db.exec(text("ALTER TABLE document_share_links ADD COLUMN otp_attempts INTEGER NOT NULL DEFAULT 0"))
        if "otp_locked_until" not in share_columns:
            db.exec(text("ALTER TABLE document_share_links ADD COLUMN otp_locked_until TIMESTAMP NULL"))
        audit_constraints = inspect(engine).get_unique_constraints("audit_events")
        if not any(
            set(constraint["column_names"]) == {"company_id", "sequence_number"}
            for constraint in audit_constraints
        ):
            db.exec(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_events_company_sequence "
                "ON audit_events (company_id, sequence_number)"
            ))
        db.exec(text("UPDATE company_users SET role = 'ADMIN' WHERE role = 'OWNER'"))
        db.exec(text("UPDATE company_users SET role = 'EXTERNAL_CLIENT' WHERE role = 'EXTERNAL_VIEWER'"))
        db.exec(text("UPDATE document_permissions SET permission_level = 'WRITE' WHERE permission_level = 'EDIT'"))
        db.exec(text("UPDATE document_permissions SET permission_level = 'READ' WHERE permission_level = 'DOWNLOAD'"))
        db.commit()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    if len(request_id) > 100:
        request_id = str(uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers.update({
        "X-Request-ID": request_id,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    })
    if os.getenv("ENVIRONMENT", "development") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def protect_cookie_authenticated_requests(request: Request, call_next):
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and (
            request.cookies.get(AUTH_COOKIE)
            or request.cookies.get(SHARE_SESSION_COOKIE)
        )
        and not request.headers.get("Authorization")
    ):
        origin = request.headers.get("Origin")
        if not origin or origin not in origins:
            return Response("Untrusted request origin", status_code=403)
    return await call_next(request)


@app.middleware("http")
async def audit_denied_requests(request: Request, call_next):
    response = await call_next(request)
    if response.status_code < 400 or not request.url.path.startswith("/api/"):
        return response
    token = request.headers.get("Authorization", "")
    user = None
    if token.lower().startswith("bearer "):
        try:
            payload = jwt.decode(
                token[7:],
                config_secret(),
                algorithms=[os.getenv("ALGORITHM", "HS256")],
            )
            with Session(engine) as db:
                user_id = UUID(payload["sub"])
                user = db.get(CompanyUser, user_id)
                if user:
                    audit(
                        db,
                        request,
                        user,
                        AuditAction.ACCESS_DENIED,
                        user.company_id,
                        details=json.dumps({
                            "type": "access_denied",
                            "status": response.status_code,
                        }),
                    )
                    db.commit()
        except (JWTError, KeyError, ValueError):
            pass
    return response


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.exec(select(Company).limit(1)).first()
    except Exception as exc:
        raise HTTPException(503, "Database unavailable") from exc
    return {"status": "ok"}


@app.get("/ready")
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    health(db)
    if not os.getenv("S3_BUCKET"):
        raise HTTPException(503, "Object storage is not configured")
    return {"status": "ready"}


@app.post("/api/auth/register", response_model=UserResponse, status_code=201)
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> CompanyUser:
    email = normalize_email(str(data.email))
    rate_limit(request, email, db, 5)
    company = Company.for_email(email, data.company_name)
    if company.account_type != AccountType.PERSONAL:
        raise HTTPException(403, "Corporate accounts require an administrator invitation")
    if db.exec(select(CompanyUser).where(CompanyUser.email == email)).first():
        raise HTTPException(409, "Email is already registered")
    existing = db.get(Company, company.id)
    if existing:
        company = existing
    else:
        db.add(company)
    user = CompanyUser.for_email(email, full_name=data.full_name.strip(),
                                 password_hash=hash_password(data.password),
                                 role=UserRole.ADMIN,
                                 status=UserStatus.ACTIVE)
    db.add(user)
    audit(db, request, user, AuditAction.USER_REGISTERED, user.company_id)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), request: Request = None,
          db: Session = Depends(get_db)) -> dict[str, str]:
    if request is None: raise HTTPException(500, "Request context unavailable")
    email = normalize_email(form.username); rate_limit(request, email, db, 5)
    user = db.exec(select(CompanyUser).where(CompanyUser.email == email)).first()
    if not user or user.status != UserStatus.ACTIVE or not verify_password(form.password, user.password_hash):
        if user:
            audit(db, request, user, AuditAction.USER_LOGIN_FAILED, user.company_id)
            db.commit()
        raise HTTPException(401, "Incorrect email or password", {"WWW-Authenticate": "Bearer"})
    if user.mfa_enabled:
        challenge = jwt.encode(
            {
                "sub": str(user.id),
                "company_id": str(user.company_id),
                "session_version": user.session_version,
                "mfa_challenge": True,
                "exp": now() + timedelta(minutes=5),
            },
            config_secret(),
            algorithm=os.getenv("ALGORITHM", "HS256"),
        )
        challenge_response = Response(
            content=json.dumps({"mfa_required": True, "challenge_token": challenge}),
            media_type="application/json",
        )
        challenge_response.delete_cookie(AUTH_COOKIE)
        return challenge_response
    access_token = create_access_token(user)
    audit(db, request, user, AuditAction.USER_LOGIN_SUCCESS, user.company_id)
    db.commit()
    response = Response(
        content=json.dumps({
            "access_token": access_token,
            "token_type": "bearer",
            "mfa_setup_required": user.role == UserRole.ADMIN,
        }),
        media_type="application/json",
    )
    response.set_cookie(
        AUTH_COOKIE,
        access_token,
        max_age=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")) * 60,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development") == "production",
        samesite="lax",
    )
    return response


@app.post("/api/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> None:
    token = token or request.cookies.get(AUTH_COOKIE)
    try:
        payload = jwt.decode(token, config_secret(), algorithms=[os.getenv("ALGORITHM", "HS256")])
        if payload.get("jti"):
            user = db.get(CompanyUser, UUID(payload["sub"]))
            db.add(TokenRevocation(jti=payload["jti"]))
            if user:
                audit(db, request, user, AuditAction.USER_LOGOUT, user.company_id)
            db.commit()
    except (JWTError, KeyError, ValueError):
        pass
    response.delete_cookie(AUTH_COOKIE)


@app.get("/api/auth/me", response_model=UserResponse)
@app.get("/users/me", response_model=UserResponse)
def me(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> dict[str, Any]:
    company = db.get(Company, user.company_id)
    if not company:
        raise HTTPException(500, "User tenant is unavailable")
    return {**user.model_dump(), "company_name": company.name}


@app.post("/api/auth/mfa/setup")
def setup_mfa(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> dict[str, str]:
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already enabled")
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    user.mfa_pending_secret_encrypted = encrypt_mfa_secret(user.id, secret)
    db.add(user)
    db.commit()
    label = quote(user.email, safe="")
    issuer = quote("TrustVault", safe="")
    return {
        "secret": secret,
        "otpauth_url": f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
    }


@app.post("/api/auth/mfa/confirm")
def confirm_mfa(
    data: MfaCodeRequest,
    response: Response,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> dict[str, Any]:
    if user.mfa_enabled or not user.mfa_pending_secret_encrypted:
        raise HTTPException(409, "MFA setup has not been started")
    secret = decrypt_mfa_secret(user.id, user.mfa_pending_secret_encrypted)
    verified_step = verified_totp_step(secret, data.code)
    if verified_step is None:
        raise HTTPException(401, "Invalid authenticator code")
    recovery_codes = [secrets.token_hex(16).upper() for _ in range(10)]
    user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
    user.mfa_pending_secret_encrypted = None
    user.mfa_recovery_hashes = json.dumps([token_hash(code) for code in recovery_codes])
    user.mfa_last_verified_step = verified_step
    user.mfa_enabled = True
    user.session_version += 1
    db.add(user)
    db.commit()
    access_token = create_access_token(user)
    response.set_cookie(
        AUTH_COOKIE,
        access_token,
        max_age=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")) * 60,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development") == "production",
        samesite="lax",
    )
    return {"access_token": access_token, "recovery_codes": recovery_codes}


@app.post("/api/auth/mfa/verify")
def verify_mfa_challenge(
    data: MfaChallengeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    unauthorized = HTTPException(401, "MFA challenge is invalid or expired")
    try:
        payload = jwt.decode(
            data.challenge_token,
            config_secret(),
            algorithms=[os.getenv("ALGORITHM", "HS256")],
        )
        if payload.get("mfa_challenge") is not True:
            raise unauthorized
        user_id = UUID(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise unauthorized from None
    user = db.get(CompanyUser, user_id)
    if (
        not user
        or user.status != UserStatus.ACTIVE
        or not user.mfa_enabled
        or payload.get("session_version") != user.session_version
        or payload.get("company_id") != str(user.company_id)
    ):
        raise unauthorized
    rate_limit(request, f"mfa:{user.id}", db, limit=5, window=300)
    step = verified_totp_step(
        decrypt_mfa_secret(user.id, user.mfa_secret_encrypted),
        data.code,
        user.mfa_last_verified_step,
    )
    if step is not None:
        result = db.exec(update(CompanyUser).where(
            CompanyUser.id == user.id,
            (CompanyUser.mfa_last_verified_step.is_(None)
             | (CompanyUser.mfa_last_verified_step < step)),
        ).values(mfa_last_verified_step=step))
        if result.rowcount != 1:
            raise HTTPException(401, "Authenticator code has already been used")
    elif not consume_recovery_code(user, data.code, db):
        db.rollback()
        raise HTTPException(401, "Invalid authenticator or recovery code")
    db.add(user)
    audit(db, request, user, AuditAction.USER_LOGIN_SUCCESS, user.company_id)
    db.commit()
    access_token = create_access_token(user)
    response.set_cookie(
        AUTH_COOKIE,
        access_token,
        max_age=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")) * 60,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development") == "production",
        samesite="lax",
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/guests/invite")
def invite_guest(data: GuestInviteRequest, request: Request, db: Session = Depends(get_db),
                 user: CompanyUser = Depends(current_user)) -> dict[str, Any]:
    email = normalize_email(str(data.email))
    guest = db.exec(select(CompanyUser).where(CompanyUser.email == email,
                                              CompanyUser.company_id == user.company_id)).first()
    if guest and guest.status == UserStatus.ACTIVE:
        raise HTTPException(409, "A user with this email already exists in the tenant")

    raw = secrets.token_urlsafe(32)
    expires_at = data.expires_at or (now() + timedelta(days=7))
    if expires_at <= now():
        raise HTTPException(400, "Invitation expiry must be in the future")
    document = None
    if data.document_id:
        document = tenant_document(db, user, data.document_id)
        if document.owner_id != user.id and user.role != UserRole.ADMIN:
            raise HTTPException(403, "Owner access required")
        if data.permission_level == PermissionLevel.WRITE:
            raise HTTPException(400, "External clients can only receive read access")
    if guest:
        guest.password_hash = hash_password(secrets.token_urlsafe(24))
        guest.status = UserStatus.INVITED
        guest.invitation_token_hash = token_hash(raw)
        guest.invitation_expires_at = expires_at
        guest.invited_by = user.id
    else:
        guest = CompanyUser(
            company_id=user.company_id,
            email=email,
            password_hash=hash_password(secrets.token_urlsafe(24)),
            role=UserRole.EXTERNAL_CLIENT,
            status=UserStatus.INVITED,
            invitation_token_hash=token_hash(raw),
            invitation_expires_at=expires_at,
            invited_by=user.id,
        )
        db.add(guest)
    db.flush()
    if document:
        permission = db.exec(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document.id,
                DocumentPermission.user_id == guest.id,
            )
        ).first()
        if permission:
            permission.permission_level = data.permission_level
            permission.revoked_at = None
            permission.expires_at = expires_at
        else:
            permission = DocumentPermission(
                document_id=document.id,
                user_id=guest.id,
                permission_level=data.permission_level,
                granted_by=user.id,
                expires_at=expires_at,
            )
        db.add(permission)
    try:
        send_guest_invitation(email, raw, expires_at)
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(503, "Invitation email could not be sent") from exc
    audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
          details="guest_invitation")
    invitation_event = audit(
        db,
        request,
        user,
        AuditAction.GUEST_INVITED,
        user.company_id,
        document.id if document else None,
        details=f"guest_invitation expires_at={expires_at.isoformat()}",
    )
    if document:
        db.flush()
        db.add(UserNotification(user_id=guest.id, audit_event_id=invitation_event.id))
    db.commit()
    db.refresh(guest)
    return {"id": str(guest.id), "expires_at": expires_at, "delivery": "sent"}


@app.post("/api/guests/accept")
def accept_guest(data: GuestAcceptRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    guest = db.exec(select(CompanyUser).where(CompanyUser.invitation_token_hash == token_hash(data.token))).first()
    if not guest or guest.status != UserStatus.INVITED or not guest.invitation_expires_at or guest.invitation_expires_at <= now():
        raise HTTPException(400, "Invalid or expired invitation")
    guest.password_hash = hash_password(data.password); guest.status = UserStatus.ACTIVE
    guest.invitation_token_hash = None; guest.invitation_accepted_at = now()
    db.add(guest)
    audit(db, request, guest, AuditAction.GUEST_ACTIVATED, guest.company_id)
    db.commit()
    return {"status": "accepted"}


@app.post("/api/guests/{guest_id}/revoke", status_code=204)
def revoke_guest(guest_id: UUID, request: Request, db: Session = Depends(get_db),
                 user: CompanyUser = Depends(require_roles(UserRole.ADMIN))) -> None:
    guest = db.get(CompanyUser, guest_id)
    if not guest or guest.company_id != user.company_id: raise HTTPException(404, "Guest not found")
    guest.status = UserStatus.REVOKED
    guest.session_version += 1
    db.add(guest)
    audit(db, request, user, AuditAction.ROLE_CHANGED, user.company_id,
          details=f"guest_revoked member={guest.id}")
    db.commit()


@app.get("/api/guests", response_model=list[GuestResponse])
def list_guests(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[CompanyUser]:
    return list(
        db.exec(
            select(CompanyUser).where(
                CompanyUser.company_id == user.company_id,
                CompanyUser.role == UserRole.EXTERNAL_CLIENT,
            )
        )
    )


@app.get("/api/company/members", response_model=list[MemberResponse])
def list_company_members(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> list[CompanyUser]:
    return list(
        db.exec(
            select(CompanyUser)
            .where(CompanyUser.company_id == user.company_id)
            .order_by(CompanyUser.created_at)
        )
    )


@app.patch("/api/company/members/{member_id}", response_model=MemberResponse)
def update_company_member(
    member_id: UUID,
    data: MemberRoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> CompanyUser:
    member = db.get(CompanyUser, member_id)
    if not member or member.company_id != user.company_id:
        raise HTTPException(404, "Member not found")
    if member.id == user.id and data.role != UserRole.ADMIN:
        raise HTTPException(400, "The workspace administrator cannot remove their own admin role")
    member.role = data.role
    member.session_version += 1
    member.updated_at = now()
    db.add(member)
    audit(
        db,
        request,
        user,
        AuditAction.ROLE_CHANGED,
        user.company_id,
        details=f"member={member.id} role={data.role.value}",
    )
    db.commit()
    db.refresh(member)
    return member


@app.post("/api/documents", response_model=DocumentResponse, status_code=201)
def create_document(data: DocumentCreate, request: Request, db: Session = Depends(get_db),
                    user: CompanyUser = Depends(current_user)) -> Document:
    content_type = validate_content_type(data.content_type)
    if data.file_size > max_document_size_bytes():
        raise HTTPException(413, "Document exceeds the permitted size")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", data.content_sha256):
        raise HTTPException(422, "A valid SHA-256 checksum is required")
    content_sha256 = data.content_sha256.lower()
    duplicate = db.exec(select(Document).where(
        Document.company_id == user.company_id,
        Document.content_sha256 == content_sha256,
        Document.deleted_at.is_(None),
    )).first()
    if duplicate:
        if (
            duplicate.owner_id == user.id
            and duplicate.upload_verified_at is None
            and duplicate.expected_size == data.file_size
        ):
            duplicate.name = data.name
            duplicate.category = data.category
            duplicate.content_type = content_type
            duplicate.updated_at = now()
            db.add(duplicate)
            db.commit()
            db.refresh(duplicate)
            return duplicate
        raise HTTPException(409, "A document with identical contents already exists in this company workspace")
    key = f"{user.company_id}/{uuid4()}/{data.name}"
    document = Document(
        company_id=user.company_id,
        owner_id=user.id,
        name=data.name,
        category=data.category,
        storage_key=key,
        content_sha256=content_sha256,
        content_type=content_type,
        expected_size=data.file_size,
    )
    db.add(document); audit(db, request, user, AuditAction.DOCUMENT_CREATED, user.company_id, document.id)
    db.commit(); db.refresh(document)
    return document


@app.get("/api/documents", response_model=list[DocumentResponse])
def list_documents(db: Session = Depends(get_db), user: CompanyUser = Depends(current_user)) -> list[Document]:
    if user.role == UserRole.ADMIN:
        return list(db.exec(select(Document).where(
            Document.company_id == user.company_id,
            Document.deleted_at.is_(None),
            (Document.upload_verified_at.is_not(None) | Document.expected_size.is_(None)),
        )))
    permitted = select(DocumentPermission.document_id).where(
        DocumentPermission.user_id == user.id,
        DocumentPermission.revoked_at.is_(None),
        (DocumentPermission.expires_at.is_(None) | (DocumentPermission.expires_at > now())),
    )
    return list(db.exec(select(Document).where(
        Document.company_id == user.company_id,
        Document.deleted_at.is_(None),
        (Document.upload_verified_at.is_not(None) | Document.expected_size.is_(None)),
        (Document.owner_id == user.id) | Document.id.in_(permitted),
    )))


@app.get("/api/documents/shared-with-me", response_model=list[DocumentResponse])
def list_shared_documents(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> list[Document]:
    permitted = select(DocumentPermission.document_id).where(
        DocumentPermission.user_id == user.id,
        DocumentPermission.revoked_at.is_(None),
        (DocumentPermission.expires_at.is_(None) | (DocumentPermission.expires_at > now())),
    )
    return list(db.exec(select(Document).where(
        Document.company_id == user.company_id,
        Document.deleted_at.is_(None),
        (Document.upload_verified_at.is_not(None) | Document.expected_size.is_(None)),
        Document.owner_id != user.id,
        Document.id.in_(permitted),
    )))


@app.get("/api/documents/{document_id}", response_model=DocumentResponse)
def get_document(document_id: UUID, db: Session = Depends(get_db), user: CompanyUser = Depends(current_user)) -> Document:
    if user.role == UserRole.ADMIN:
        return tenant_admin_document(db, user, document_id)
    return tenant_document(db, user, document_id)


@app.patch("/api/documents/{document_id}", response_model=DocumentResponse)
def update_document(document_id: UUID, data: DocumentUpdate, db: Session = Depends(get_db),
                    request: Request = None,
                    user: CompanyUser = Depends(current_user)) -> Document:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    document.name = data.name
    document.category = data.category
    document.updated_at = now()
    db.add(document)
    audit(db, request, user, AuditAction.DOCUMENT_UPDATED, user.company_id, document.id)
    db.commit()
    db.refresh(document)
    return document


@app.delete("/api/documents/{document_id}", status_code=204)
def delete_document(document_id: UUID, db: Session = Depends(get_db),
                    request: Request = None,
                    user: CompanyUser = Depends(current_user)) -> None:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    try:
        s3_client().delete_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(503, "Object storage unavailable") from exc
    deleted_at = now()
    document.deleted_at = deleted_at
    document.updated_at = deleted_at
    db.add(document)
    db.exec(update(DocumentPermission).where(
        DocumentPermission.document_id == document.id,
        DocumentPermission.revoked_at.is_(None),
    ).values(revoked_at=deleted_at))
    db.exec(update(AccessSuggestion).where(
        AccessSuggestion.document_id == document.id,
        AccessSuggestion.status == "PENDING",
    ).values(status="REJECTED", decided_at=deleted_at))
    db.exec(update(DocumentShareLink).where(
        DocumentShareLink.document_id == document.id,
        DocumentShareLink.status == ShareLinkStatus.ACTIVE,
    ).values(status=ShareLinkStatus.REVOKED, revoked_at=deleted_at))
    audit(db, request, user, AuditAction.DOCUMENT_DELETED,
          user.company_id, document.id,
          details=f"document_deleted document_id={document.id}")
    db.commit()


def s3_client():
    return boto3.client(
        "s3",
        region_name=os.getenv("AWS_REGION") or os.getenv("REGION"),
        endpoint_url=os.getenv("S3_ENDPOINT_URL") or None,
        config=Config(signature_version="s3v4"),
    )


def verify_document_upload(document: Document, db: Session) -> tuple[str, int, bytes]:
    try:
        metadata = s3_client().head_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(404, "Uploaded object not found") from exc
    content_length = metadata.get("ContentLength")
    maximum_size = max_document_size_bytes()
    if not isinstance(content_length, int) or content_length <= 0 or content_length > maximum_size:
        raise HTTPException(413, "Uploaded document exceeds the permitted size")
    try:
        object_response = s3_client().get_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
        body = object_response["Body"]
        digest = hashlib.sha256()
        prefix = b""
        content = bytearray()
        bytes_read = 0
        scanner = None
        try:
            scanner = start_malware_scan()
            while True:
                chunk = body.read(min(1024 * 1024, maximum_size + 1 - bytes_read))
                if not chunk:
                    break
                if not prefix:
                    prefix = chunk[:16]
                bytes_read += len(chunk)
                if bytes_read > maximum_size:
                    raise HTTPException(413, "Uploaded document exceeds the permitted size")
                digest.update(chunk)
                scan_chunk(scanner, chunk)
                content.extend(chunk)
            finish_malware_scan(scanner)
        finally:
            body.close()
            if scanner is not None:
                scanner.close()
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(404, "Uploaded object could not be verified") from exc
    uploaded_hash = digest.hexdigest()
    detected_type = detect_document_type(prefix)
    if bytes_read != content_length or (
        document.expected_size is not None and content_length != document.expected_size
    ):
        raise HTTPException(422, "Uploaded object size does not match storage metadata")
    if not hmac.compare_digest(uploaded_hash, document.content_sha256.lower()):
        raise HTTPException(422, "Uploaded object checksum does not match")
    if detected_type != document.content_type:
        raise HTTPException(415, "Uploaded file content does not match its declared type")
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    db.refresh(document)
    return uploaded_hash, content_length, bytes(content)


@app.post("/api/documents/{document_id}/upload-url")
def upload_url(
    document_id: UUID,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> dict[str, Any]:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    try:
        upload = s3_client().generate_presigned_post(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
            Fields={
                "Content-Type": document.content_type,
                "x-amz-meta-content-sha256": document.content_sha256,
            },
            Conditions=[
                {"Content-Type": document.content_type},
                {"x-amz-meta-content-sha256": document.content_sha256},
                ["content-length-range", 1, max_document_size_bytes()],
            ],
            ExpiresIn=900,
        )
    except (KeyError, BotoCoreError, ClientError) as exc: raise HTTPException(503, "Object storage unavailable") from exc
    return {
        "url": upload["url"],
        "fields": upload["fields"],
        "content_type": document.content_type,
        "content_sha256": document.content_sha256,
        "file_size": document.expected_size,
    }


@app.post(
    "/api/documents/{document_id}/complete-upload",
    response_model=UploadCompletionResponse,
)
def complete_upload(
    document_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> UploadCompletionResponse:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    if document.expected_size is None:
        raise HTTPException(409, "Upload size is not registered for this document")
    uploaded_hash, content_length, _ = verify_document_upload(document, db)
    audit(
        db,
        request,
        user,
        AuditAction.DOCUMENT_PREVIEW,
        user.company_id,
        document.id,
        details="upload_verified",
    )
    db.commit()
    return UploadCompletionResponse(
        verified=True,
        content_sha256=uploaded_hash,
        content_length=content_length,
    )


@app.get("/api/documents/{document_id}/download-url")
def download_url(
    document_id: UUID,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> dict[str, str]:
    document = tenant_document(db, user, document_id, PermissionLevel.READ)
    return {"url": f"/api/documents/{document.id}/content"}


@app.get("/api/documents/{document_id}/content")
def document_content(
    document_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> Response:
    document = tenant_document(db, user, document_id, PermissionLevel.READ)
    _, _, content = verify_document_upload(document, db)
    audit(db, request, user, AuditAction.DOCUMENT_DOWNLOAD, user.company_id, document.id)
    db.commit()
    return Response(
        content=content,
        media_type=document.content_type,
        headers=safe_download_headers(document.name),
    )


@app.delete("/api/documents/{document_id}/object", status_code=204)
def delete_object(document_id: UUID, request: Request, db: Session = Depends(get_db),
                  user: CompanyUser = Depends(current_user)) -> None:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    try: s3_client().delete_object(Bucket=os.environ["S3_BUCKET"], Key=document.storage_key)
    except (KeyError, BotoCoreError, ClientError) as exc: raise HTTPException(503, "Object storage unavailable") from exc
    audit(db, request, user, AuditAction.DOCUMENT_DELETED, user.company_id, document.id,
          details="object_deleted")
    db.commit()


@app.post("/api/documents/{document_id}/permissions", status_code=201)
def grant_permission(document_id: UUID, data: PermissionRequest, request: Request, db: Session = Depends(get_db),
                     user: CompanyUser = Depends(current_user)) -> dict[str, str]:
    document = tenant_admin_document(db, user, document_id)
    target = db.get(CompanyUser, data.user_id)
    if not target or target.company_id != user.company_id: raise HTTPException(404, "User not found")
    if target.role == UserRole.EXTERNAL_CLIENT and data.permission_level == PermissionLevel.WRITE:
        raise HTTPException(400, "External clients can only receive read access")
    existing = db.exec(select(DocumentPermission).where(
        DocumentPermission.document_id == document.id,
        DocumentPermission.user_id == target.id,
    )).first()
    if existing and existing.revoked_at is None:
        raise HTTPException(409, "Permission already exists")
    if existing:
        existing.permission_level = data.permission_level
        existing.granted_by = user.id
        existing.expires_at = data.expires_at
        existing.revoked_at = None
        permission = existing
    else:
        permission = DocumentPermission(document_id=document.id, user_id=target.id,
                                        permission_level=data.permission_level,
                                        granted_by=user.id, expires_at=data.expires_at)
    db.add(permission)
    event = audit(
        db,
        request,
        user,
        AuditAction.PERMISSION_GRANTED,
        user.company_id,
        document.id,
        details=f"granted_to={target.email};permission={data.permission_level.value}",
    )
    db.flush()
    db.add(UserNotification(user_id=target.id, audit_event_id=event.id))
    db.commit()
    return {"id": str(permission.id)}


@app.get(
    "/api/documents/{document_id}/permissions",
    response_model=list[PermissionResponse],
)
def list_permissions(
    document_id: UUID,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> list[DocumentPermission]:
    document = tenant_admin_document(db, user, document_id)
    return list(db.exec(select(DocumentPermission).where(
        DocumentPermission.document_id == document.id,
    )))


@app.post("/api/ai/access-suggestions", response_model=list[AccessSuggestionResponse])
def suggest_access(
    data: AccessSuggestionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[AccessSuggestionResponse]:
    document = tenant_admin_document(db, user, data.document_id)
    candidates = db.exec(select(CompanyUser).where(
        CompanyUser.company_id == user.company_id,
        CompanyUser.status == UserStatus.ACTIVE,
        CompanyUser.id != document.owner_id,
        CompanyUser.role != UserRole.EXTERNAL_CLIENT,
    )).all()
    if data.user_id:
        candidates = [candidate for candidate in candidates if candidate.id == data.user_id]
    existing_user_ids = {
        permission.user_id for permission in db.exec(select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
        ))
    }
    results = []
    for candidate in candidates:
        if candidate.id in existing_user_ids:
            continue
        suggestion = AccessSuggestion(
            company_id=user.company_id, document_id=document.id,
            suggested_user_id=candidate.id, permission_level=PermissionLevel.READ,
            rationale="Least-privilege READ recommendation; owner confirmation is required.",
            created_by=user.id,
        )
        db.add(suggestion)
        db.flush()
        audit(db, request, user, AuditAction.AI_ACCESS_SUGGESTED, user.company_id,
              document.id, details=f"suggestion_id={suggestion.id};user_id={candidate.id}")
        results.append(AccessSuggestionResponse(
            id=suggestion.id, document_id=document.id, suggested_user_id=candidate.id,
            suggested_email=candidate.email, permission_level=suggestion.permission_level,
            rationale=suggestion.rationale, status=suggestion.status,
            created_at=suggestion.created_at,
        ))
    db.commit()
    return results


@app.post("/api/ai/access-suggestions/{suggestion_id}/decision",
          response_model=AccessSuggestionResponse)
def decide_access_suggestion(
    suggestion_id: UUID,
    data: AccessDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> AccessSuggestionResponse:
    suggestion = db.get(AccessSuggestion, suggestion_id)
    if not suggestion or suggestion.company_id != user.company_id:
        raise HTTPException(404, "Access suggestion not found")
    if suggestion.status != "PENDING":
        raise HTTPException(409, "Access suggestion has already been decided")
    target = db.get(CompanyUser, suggestion.suggested_user_id)
    document = db.get(Document, suggestion.document_id)
    if not target or target.company_id != user.company_id or target.status != UserStatus.ACTIVE:
        raise HTTPException(404, "Suggested user not found")
    if not document or document.company_id != user.company_id or document.deleted_at:
        raise HTTPException(404, "Document not found")
    if document.owner_id != user.id:
        raise HTTPException(403, "Only the document owner can approve access")
    if data.approve:
        permission_level = data.permission_level or suggestion.permission_level
        if permission_level != PermissionLevel.READ:
            raise HTTPException(400, "Access suggestions can grant READ access only")
        existing = db.exec(select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == target.id,
        )).first()
        if existing and existing.revoked_at is None:
            raise HTTPException(409, "User already has document access")
        db.add(DocumentPermission(
            document_id=suggestion.document_id, user_id=target.id,
            permission_level=permission_level, granted_by=user.id,
        ))
        suggestion.permission_level = permission_level
        suggestion.status = "APPROVED"
        action = AuditAction.AI_ACCESS_CONFIRMED
    else:
        suggestion.status = "REJECTED"
        action = AuditAction.AI_ACCESS_REJECTED
    suggestion.decided_at = now()
    db.add(suggestion)
    event = audit(db, request, user, action, user.company_id, suggestion.document_id,
                  details=(
                      f"suggestion_id={suggestion.id};approved={data.approve};"
                      f"granted_to={target.email if data.approve else ''}"
                  ))
    if data.approve:
        db.flush()
        db.add(UserNotification(user_id=target.id, audit_event_id=event.id))
    db.commit()
    db.refresh(suggestion)
    return AccessSuggestionResponse(
        id=suggestion.id, document_id=suggestion.document_id,
        suggested_user_id=target.id, suggested_email=target.email,
        permission_level=suggestion.permission_level, rationale=suggestion.rationale,
        status=suggestion.status, created_at=suggestion.created_at,
    )


@app.delete("/api/documents/{document_id}/permissions/{permission_id}", status_code=204)
def revoke_permission(document_id: UUID, permission_id: UUID, request: Request,
                      db: Session = Depends(get_db),
                      user: CompanyUser = Depends(current_user)) -> None:
    document = tenant_admin_document(db, user, document_id)
    permission = db.get(DocumentPermission, permission_id)
    if not permission or permission.document_id != document.id: raise HTTPException(404, "Permission not found")
    permission.revoked_at = now()
    db.add(permission)
    audit(db, request, user, AuditAction.PERMISSION_REVOKED, user.company_id, document.id,
          details=f"permission={permission.id} user={permission.user_id}")
    db.commit()


@app.post("/api/documents/{document_id}/shares", response_model=ShareResponse, status_code=201)
def create_share(document_id: UUID, data: ShareRequest, request: Request, db: Session = Depends(get_db),
                 user: CompanyUser = Depends(current_user)) -> ShareResponse:
    rate_limit(request, f"share-create:{user.company_id}:{user.id}", db, limit=20, window=3600)
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    if document.owner_id != user.id:
        raise HTTPException(403, "Only the document owner can create a share")
    if data.require_otp and not data.recipient_email:
        raise HTTPException(422, "A recipient email is required when email OTP is enabled")
    if data.expires_at <= now(): raise HTTPException(400, "Expiry must be in the future")
    verify_document_upload(document, db)
    raw = secrets.token_urlsafe(32)
    otp = f"{secrets.randbelow(1_000_000):06d}" if data.require_otp else None
    link = DocumentShareLink(document_id=document.id, company_id=user.company_id, token_hash=token_hash(raw),
                             passcode_hash=hash_password(data.passcode) if data.passcode else None,
                             otp_code_hash=hash_password(otp) if otp else None,
                             otp_expires_at=(now() + timedelta(minutes=10)) if otp else None,
                             recipient_email=normalize_email(str(data.recipient_email)) if data.recipient_email else "link-only@trustvault.local",
                             max_downloads=data.max_downloads,
                             expires_at=data.expires_at, created_by=user.id)
    db.add(link)
    db.flush()
    if otp:
        try:
            send_share_otp(link.recipient_email, otp, link.otp_expires_at)
        except EmailDeliveryError as exc:
            db.rollback()
            raise HTTPException(503, "Share verification email could not be sent") from exc
        audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
              document.id, link.id, details="share_otp")
    if data.recipient_email:
        try:
            send_share_link(
                link.recipient_email,
                f"{os.getenv('FRONTEND_URL', 'http://localhost:5173').rstrip('/')}/share#token={raw}",
                link.expires_at,
                otp_required=bool(otp),
            )
        except EmailDeliveryError as exc:
            db.rollback()
            raise HTTPException(503, "Share email could not be sent") from exc
        audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
              document.id, link.id, details="share_link")
    audit(db, request, user, AuditAction.SHARE_LINK_CREATED, user.company_id,
          document.id, link.id, details="share_link_created")
    db.commit()
    db.refresh(link)
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    return ShareResponse(id=link.id, url=f"{frontend_url}/share#token={raw}", expires_at=link.expires_at,
                         max_downloads=link.max_downloads)


def verify_share_otp_for_link(
    data: OtpVerificationRequest,
    response: Response,
    db: Session,
    link: DocumentShareLink | None,
) -> dict[str, str]:
    if not link or link.status != ShareLinkStatus.ACTIVE or not link.otp_code_hash:
        raise HTTPException(404, "OTP verification unavailable")
    current_time = now()
    if link.otp_locked_until and link.otp_locked_until > current_time:
        raise HTTPException(429, "OTP verification is temporarily locked")
    if not link.otp_expires_at or link.otp_expires_at <= current_time:
        raise HTTPException(401, "Invalid or expired OTP")
    verified = verify_password(data.otp, link.otp_code_hash)
    if not verified:
        db.exec(update(DocumentShareLink).where(
            DocumentShareLink.id == link.id,
            DocumentShareLink.otp_verified_at.is_(None),
            DocumentShareLink.otp_expires_at > current_time,
            (DocumentShareLink.otp_locked_until.is_(None)
             | (DocumentShareLink.otp_locked_until <= current_time)),
        ).values(
            otp_attempts=DocumentShareLink.otp_attempts + 1,
            otp_locked_until=case(
                (DocumentShareLink.otp_attempts + 1 >= 5, current_time + timedelta(minutes=15)),
                else_=DocumentShareLink.otp_locked_until,
            ),
        ))
        db.commit()
        raise HTTPException(401, "Invalid or expired OTP")
    result = db.exec(update(DocumentShareLink).where(
        DocumentShareLink.id == link.id,
        DocumentShareLink.otp_code_hash == link.otp_code_hash,
        DocumentShareLink.otp_verified_at.is_(None),
        DocumentShareLink.otp_expires_at > current_time,
        (DocumentShareLink.otp_locked_until.is_(None)
         | (DocumentShareLink.otp_locked_until <= current_time)),
    ).values(otp_verified_at=current_time, otp_code_hash=None))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "OTP verification has already been used")
    db.commit()
    db.refresh(link)
    set_share_session_cookie(response, link)
    return {"status": "verified"}


@app.post("/api/shares/exchange")
def exchange_share_token(
    data: ShareExchangeRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    link = db.exec(select(DocumentShareLink).where(
        DocumentShareLink.token_hash == token_hash(data.token)
    )).first()
    if not link or link.status != ShareLinkStatus.ACTIVE or link.expires_at <= now():
        raise HTTPException(404, "Share link unavailable")
    set_share_session_cookie(response, link)
    return {"requires_otp": link.otp_expires_at is not None}


@app.post("/api/shares/current/verify-otp")
def verify_current_share_otp(
    data: OtpVerificationRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    link = share_link_from_session(request, db)
    rate_limit(request, str(link.id), db, 5)
    return verify_share_otp_for_link(data, response, db, link)


@app.post("/api/shares/current/resend-otp")
def resend_current_share_otp(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    link = share_link_from_session(request, db)
    if not link.otp_expires_at or link.otp_verified_at:
        raise HTTPException(404, "OTP resend unavailable")
    if link.otp_locked_until and link.otp_locked_until > now():
        raise HTTPException(429, "OTP verification is temporarily locked")
    rate_limit(request, f"share-otp-resend:{link.id}", db, limit=3, window=600)
    otp = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = now() + timedelta(minutes=10)
    link.otp_code_hash = hash_password(otp)
    link.otp_expires_at = expires_at
    link.otp_attempts = 0
    link.otp_locked_until = None
    try:
        send_share_otp(link.recipient_email, otp, expires_at)
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(503, "Share verification email could not be sent") from exc
    db.add(link)
    audit(
        db,
        request,
        None,
        AuditAction.EMAIL_SENT,
        link.company_id,
        link.document_id,
        link.id,
        details="share_otp_resent",
    )
    db.commit()
    return {"status": "sent"}


@app.post("/api/shares/current/download")
def share_current_content(
    request: Request,
    data: ShareAccessRequest | None = None,
    db: Session = Depends(get_db),
) -> Response:
    link = share_link_from_session(request, db)
    return share_content_for_link(link, request, data, db)

def share_content_for_link(
    link: DocumentShareLink | None,
    request: Request,
    data: ShareAccessRequest | None,
    db: Session,
) -> Response:
    if not link or link.status != ShareLinkStatus.ACTIVE or link.expires_at <= now():
        raise HTTPException(404, "Share link unavailable")
    rate_limit(request, f"share-download:{link.id}", db, limit=30, window=60)
    passcode = data.passcode if data else None
    if link.passcode_hash and (not passcode or not verify_password(passcode, link.passcode_hash)):
        raise HTTPException(401, "Passcode required")
    if link.otp_expires_at and (not link.otp_verified_at or not valid_share_session(request, link)):
        raise HTTPException(401, "OTP verification required")
    document = db.get(Document, link.document_id)
    if not document or document.deleted_at:
        raise HTTPException(404, "Document not found")
    current_time = now()
    result = db.exec(update(DocumentShareLink).where(
        DocumentShareLink.id == link.id,
        DocumentShareLink.status == ShareLinkStatus.ACTIVE,
        DocumentShareLink.download_count < DocumentShareLink.max_downloads,
        DocumentShareLink.expires_at > current_time,
    ).values(
        download_count=DocumentShareLink.download_count + 1,
        status=case(
            (DocumentShareLink.download_count + 1 >= DocumentShareLink.max_downloads,
             ShareLinkStatus.EXHAUSTED),
            else_=DocumentShareLink.status,
        ),
    ))
    if result.rowcount != 1:
        raise HTTPException(410, "Download quota exhausted")
    db.commit()
    try:
        _, _, content = verify_document_upload(document, db)
    except HTTPException:
        db.exec(update(DocumentShareLink).where(
            DocumentShareLink.id == link.id,
            DocumentShareLink.download_count > 0,
            DocumentShareLink.status.in_([ShareLinkStatus.ACTIVE, ShareLinkStatus.EXHAUSTED]),
            DocumentShareLink.expires_at > now(),
        ).values(
            download_count=DocumentShareLink.download_count - 1,
            status=ShareLinkStatus.ACTIVE,
        ))
        db.commit()
        raise
    db.refresh(link)
    audit(
        db,
        request,
        None,
        AuditAction.DOCUMENT_DOWNLOAD,
        link.company_id,
        document.id,
        link.id,
        details="shared_document_download",
    )
    db.add(link)
    db.commit()
    return Response(
        content=content,
        media_type=document.content_type,
        headers=safe_download_headers(document.name),
    )


@app.post("/api/shares/{share_id}/revoke", status_code=204)
def revoke_share(share_id: UUID, db: Session = Depends(get_db),
                 request: Request = None,
                 user: CompanyUser = Depends(current_user)) -> None:
    link = db.get(DocumentShareLink, share_id)
    if not link or link.company_id != user.company_id: raise HTTPException(404, "Share link not found")
    document = db.get(Document, link.document_id)
    if link.created_by != user.id and (not document or document.owner_id != user.id) and user.role != UserRole.ADMIN:
        raise HTTPException(404, "Share link not found")
    link.status = ShareLinkStatus.REVOKED
    link.revoked_at = now()
    db.add(link)
    audit(db, request, user, AuditAction.SHARE_LINK_REVOKED,
          user.company_id, link.document_id, link.id)
    db.commit()


@app.get("/api/shares", response_model=list[ShareLinkResponse])
def list_shares(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(
        require_roles(UserRole.ADMIN)
    ),
) -> list[DocumentShareLink]:
    return list(
        db.exec(
            select(DocumentShareLink).where(
                DocumentShareLink.company_id == user.company_id,
            )
        )
    )


@app.get("/api/audit", response_model=list[AuditEventResponse])
def list_audit_events(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(
        require_roles(UserRole.ADMIN)
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditEventResponse]:
    events = list(db.exec(
        select(AuditEvent)
        .where(AuditEvent.company_id == user.company_id)
        .order_by(AuditEvent.occurred_at.desc())
        .offset(offset)
        .limit(limit)
    ))
    responses = []
    for event in events:
        actor = db.get(CompanyUser, event.actor_user_id) if event.actor_user_id else None
        document = db.get(Document, event.document_id) if event.document_id else None
        responses.append(AuditEventResponse(
            id=event.id,
            actor_user_id=event.actor_user_id,
            actor_email=actor.email if actor else None,
            actor_name=actor.full_name if actor else None,
            document_id=event.document_id,
            document_name=document.name if document else None,
            share_link_id=event.share_link_id,
            action=event.action,
            details=event.details,
            request_id=event.request_id,
            ip_address=event.ip_address,
            occurred_at=event.occurred_at,
        ))
    return responses


@app.get("/api/notifications", response_model=list[NotificationResponse])
def list_notifications(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[NotificationResponse]:
    rows = list(db.exec(
        select(UserNotification, AuditEvent)
        .join(AuditEvent, AuditEvent.id == UserNotification.audit_event_id)
        .where(UserNotification.user_id == user.id)
        .order_by(UserNotification.created_at.desc())
        .limit(limit)
    ))
    responses = []
    for notification, event in rows:
        document = db.get(Document, event.document_id) if event.document_id else None
        actor = db.get(CompanyUser, event.actor_user_id) if event.actor_user_id else None
        responses.append(NotificationResponse(
            id=notification.id,
            audit_event_id=event.id,
            action=event.action,
            details=event.details,
            document_id=event.document_id,
            document_name=document.name if document else None,
            actor_name=actor.full_name if actor else None,
            occurred_at=event.occurred_at,
            read_at=notification.read_at,
        ))
    return responses


@app.post("/api/notifications/read", status_code=204)
def mark_notifications_read(
    data: NotificationReadRequest,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(current_user),
) -> None:
    notifications = list(db.exec(select(UserNotification).where(
        UserNotification.user_id == user.id,
        UserNotification.id.in_(data.notification_ids),
    )))
    for notification in notifications:
        notification.read_at = now()
        db.add(notification)
    db.commit()


@app.get("/api/admin/analytics")
def admin_analytics(
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> dict[str, Any]:
    documents = list(db.exec(select(Document).where(
        Document.company_id == user.company_id,
        Document.deleted_at.is_(None),
    )))
    members = list(db.exec(select(CompanyUser).where(CompanyUser.company_id == user.company_id)))
    events = list(db.exec(
        select(AuditEvent)
        .where(AuditEvent.company_id == user.company_id)
        .order_by(AuditEvent.occurred_at)
    ))
    period_start = now() - timedelta(days=29)
    recent_events = []
    for event in events:
        occurred_at = event.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        if occurred_at >= period_start:
            recent_events.append(event)
    breakdown: dict[str, int] = {}
    activity_by_date: dict[str, int] = {}
    for event in recent_events:
        breakdown[event.action.value] = breakdown.get(event.action.value, 0) + 1
        occurred_at = event.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        day = occurred_at.date().isoformat()
        activity_by_date[day] = activity_by_date.get(day, 0) + 1
    today = now().date()
    activity_by_day = [
        {
            "date": (today - timedelta(days=offset)).isoformat(),
            "count": activity_by_date.get(
                (today - timedelta(days=offset)).isoformat(), 0
            ),
        }
        for offset in range(29, -1, -1)
    ]
    documents_by_category: dict[str, int] = {}
    for document in documents:
        category = document.category or "Uncategorized"
        documents_by_category[category] = documents_by_category.get(category, 0) + 1
    alert_actions = {
        AuditAction.USER_LOGIN_FAILED,
        AuditAction.EMAIL_FAILED,
        AuditAction.ACCESS_DENIED,
    }
    unread_alerts = db.exec(
        select(UserNotification.id)
        .join(AuditEvent, AuditEvent.id == UserNotification.audit_event_id)
        .where(
            UserNotification.user_id == user.id,
            UserNotification.read_at.is_(None),
            AuditEvent.action.in_(alert_actions),
        )
    ).all()
    recent_alerts = []
    for event in reversed(recent_events):
        if event.action not in alert_actions:
            continue
        actor = db.get(CompanyUser, event.actor_user_id) if event.actor_user_id else None
        document = db.get(Document, event.document_id) if event.document_id else None
        recent_alerts.append({
            "id": event.id,
            "action": event.action.value,
            "details": event.details,
            "occurred_at": event.occurred_at,
            "actor_name": actor.full_name if actor else None,
            "actor_email": actor.email if actor else None,
            "document_name": document.name if document else None,
        })
        if len(recent_alerts) == 6:
            break
    return {
        "documents": len(documents),
        "members": len(members),
        "active_members": sum(member.status == UserStatus.ACTIVE for member in members),
        "audit_events": len(events),
        "event_breakdown": breakdown,
        "activity_by_day": activity_by_day,
        "documents_by_category": documents_by_category,
        "events_30d": len(recent_events),
        "alerts_30d": sum(event.action in alert_actions for event in recent_events),
        "unread_alerts": len(unread_alerts),
        "recent_alerts": recent_alerts,
    }


@app.get("/api/audit/verify")
def verify_audit_integrity(
    request: Request,
    db: Session = Depends(get_db),
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> dict[str, Any]:
    events = list(db.exec(
        select(AuditEvent)
        .where(AuditEvent.company_id == user.company_id)
        .order_by(AuditEvent.sequence_number)
    ))
    previous_hash = None
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence_number != expected_sequence:
            return {"valid": False, "checked": expected_sequence - 1, "reason": "sequence_gap"}
        if event.previous_event_hash != previous_hash:
            return {"valid": False, "checked": expected_sequence - 1, "reason": "chain_break"}
        if not any(
            hmac.compare_digest(
                hashlib.sha256(payload.encode()).hexdigest(), event.event_hash
            )
            for payload in audit_payload_candidates(event)
        ):
            return {"valid": False, "checked": expected_sequence - 1, "reason": "hash_mismatch"}
        previous_hash = event.event_hash
    archive_bucket = os.getenv("AUDIT_ARCHIVE_BUCKET")
    if archive_bucket:
        storage = s3_client()
        for checked, event in enumerate(events, start=1):
            try:
                response = storage.get_object(
                    Bucket=archive_bucket,
                    Key=audit_archive_key(event),
                )
                archived = response["Body"].read()
                response["Body"].close()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                    return {"valid": False, "checked": checked - 1, "reason": "anchor_missing"}
                raise HTTPException(503, "Immutable audit storage is unavailable") from exc
            except BotoCoreError as exc:
                raise HTTPException(503, "Immutable audit storage is unavailable") from exc
            expected_anchor = audit_archive_body(event)
            if not hmac.compare_digest(archived, expected_anchor):
                return {"valid": False, "checked": checked - 1, "reason": "anchor_mismatch"}
    audit(
        db,
        request,
        user,
        AuditAction.AUDIT_INTEGRITY_CHECK,
        user.company_id,
        details=f"checked={len(events)} valid=true anchored={bool(archive_bucket)}",
    )
    db.commit()
    return {"valid": True, "checked": len(events), "anchored": bool(archive_bucket)}
