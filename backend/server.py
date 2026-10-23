"""TrustVault API.

All access to tenant-owned resources is scoped through the authenticated user's
company_id.  Secrets and bearer/share tokens are only accepted transiently and
are stored as hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from botocore.config import Config
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, StreamingResponse
from jose import JWTError, jwt
from pydantic import EmailStr, Field as PydanticField
from sqlmodel import Field, Session, SQLModel, select
from sqlalchemy import inspect, text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from db import engine, get_db, init_db
from email_service import EmailDeliveryError, send_guest_invitation, send_share_link, send_share_otp
from models import (
    AccountType, AccessSuggestion, AuditAction, AuditEvent, Company, CompanyUser, Document,
    DocumentPermission, DocumentShareLink, PermissionLevel, ShareLinkStatus,
    UserRole, UserStatus, UserNotification, normalize_email,
)

load_dotenv()
app = FastAPI(title="TrustVault API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
hosts = [x.strip() for x in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type", "X-Request-ID"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
_attempts: dict[str, list[float]] = {}
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


def share_session_value(link: DocumentShareLink) -> str:
    expires = int(min(link.expires_at, now() + timedelta(minutes=10)).timestamp())
    payload = f"{link.id}:{expires}"
    signature = hmac.new(config_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


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


def safe_download_headers(name: str) -> dict[str, str]:
    safe_name = os.path.basename(name).replace('"', "").replace("\r", "").replace("\n", "")
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


def config_secret() -> str:
    secret = os.getenv("SECRET_KEY")
    if not secret and os.getenv("ENVIRONMENT", "development") != "production":
        secret = "development-only-change-me"
    if not secret or len(secret) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters")
    return secret


def create_access_token(user: CompanyUser) -> str:
    jti = str(uuid4())
    expires = now() + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
    return jwt.encode({"sub": str(user.id), "company_id": str(user.company_id), "jti": jti, "exp": expires},
                      config_secret(), algorithm=os.getenv("ALGORITHM", "HS256"))


class RegisterRequest(SQLModel):
    full_name: str = PydanticField(min_length=1, max_length=255)
    email: EmailStr
    password: str = PydanticField(min_length=8, max_length=128)
    company_name: str | None = PydanticField(default=None, max_length=255)
    role: UserRole = UserRole.MEMBER


class UserResponse(SQLModel):
    id: UUID
    company_id: UUID
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


class DocumentResponse(SQLModel):
    id: UUID
    owner_id: UUID
    name: str
    category: str
    storage_key: str
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


def rate_limit(request: Request, key: str, limit: int = 10, window: int = 60) -> None:
    identity = f"{request.client.host if request.client else 'unknown'}:{key}"
    current = time.monotonic()
    values = [v for v in _attempts.get(identity, []) if current - v < window]
    if len(values) >= limit:
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(window)})
    values.append(current)
    _attempts[identity] = values


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
        or (
            user.access_expires_at is not None
            and user.access_expires_at <= now()
        )
    ):
        raise unauthorized
    return user


def require_roles(*roles: UserRole):
    def dependency(user: CompanyUser = Depends(current_user)) -> CompanyUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return user
    return dependency


def tenant_document(
db: Session,
user: CompanyUser,
document_id: UUID,
required_permission: PermissionLevel = PermissionLevel.READ,
) -> Document:
    document = db.get(Document, document_id)
    if not document or document.company_id != user.company_id:
        raise HTTPException(404, "Document not found")
    permission = db.exec(select(DocumentPermission).where(
        DocumentPermission.document_id == document.id,
        DocumentPermission.user_id == user.id,
        DocumentPermission.revoked_at.is_(None),
        (DocumentPermission.expires_at.is_(None) | (DocumentPermission.expires_at > now())),
    )).first()
    levels = {PermissionLevel.READ: 1, PermissionLevel.WRITE: 2}
    if document.owner_id != user.id and user.role != UserRole.ADMIN:
        if not permission or levels[permission.permission_level] < levels[required_permission]:
            raise HTTPException(403, "Document access denied")
    return document


def audit(db: Session, request: Request, user: CompanyUser | None, action: AuditAction,
          company_id: UUID, document_id: UUID | None = None, share_link_id: UUID | None = None,
          details: str | None = None) -> None:
    previous = db.exec(select(AuditEvent).where(AuditEvent.company_id == company_id)
                       .order_by(AuditEvent.sequence_number.desc())).first()
    sequence = (previous.sequence_number + 1) if previous else 1
    previous_hash = previous.event_hash if previous else None
    body = json.dumps({
        "company_id": str(company_id),
        "sequence": sequence,
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


def audit_payload(event: AuditEvent) -> str:
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


class TokenRevocation(SQLModel, table=True):
    __tablename__ = "token_revocations"
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    jti: str = Field(max_length=64, unique=True, index=True)
    revoked_at: datetime = Field(default_factory=now)


@app.on_event("startup")
def startup() -> None:
    init_db()
    with Session(engine) as db:
        columns = {column["name"] for column in inspect(engine).get_columns("company_users")}
        if "full_name" not in columns:
            db.exec(text("ALTER TABLE company_users ADD COLUMN full_name VARCHAR(255) NOT NULL DEFAULT ''"))
        document_columns = {column["name"] for column in inspect(engine).get_columns("documents")}
        if "category" not in document_columns:
            db.exec(text("ALTER TABLE documents ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT 'Other'"))
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
    response.headers.update({"X-Request-ID": request_id, "X-Content-Type-Options": "nosniff",
                             "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                             "Cache-Control": "no-store"})
    return response


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
    rate_limit(request, email, 5)
    if db.exec(select(CompanyUser).where(CompanyUser.email == email)).first():
        raise HTTPException(409, "Email is already registered")
    company = Company.for_email(email, data.company_name)
    existing = db.get(Company, company.id)
    if existing:
        company = existing
    else:
        db.add(company)
    has_users = db.exec(select(CompanyUser.id).where(CompanyUser.company_id == company.id)).first()
    if has_users and data.role == UserRole.ADMIN:
        raise HTTPException(400, "Administrator access must be granted by an existing administrator")
    user = CompanyUser.for_email(email, full_name=data.full_name.strip(),
                                 password_hash=hash_password(data.password),
                                 role=UserRole.ADMIN if not has_users else data.role,
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
    email = normalize_email(form.username); rate_limit(request, email, 5)
    user = db.exec(select(CompanyUser).where(CompanyUser.email == email)).first()
    if not user or user.status != UserStatus.ACTIVE or not verify_password(form.password, user.password_hash):
        if user:
            audit(db, request, user, AuditAction.USER_LOGIN_FAILED, user.company_id)
            db.commit()
        raise HTTPException(401, "Incorrect email or password", {"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(user)
    audit(db, request, user, AuditAction.USER_LOGIN_SUCCESS, user.company_id)
    db.commit()
    response = Response(
        content=json.dumps({"access_token": access_token, "token_type": "bearer"}),
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
def me(user: CompanyUser = Depends(current_user)) -> CompanyUser:
    return user


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
        message_id = send_guest_invitation(email, raw, expires_at)
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(503, "Invitation email could not be sent") from exc
    audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
          details=f"guest_invitation recipient={email} message_id={message_id}")
    audit(db, request, user, AuditAction.GUEST_INVITED, user.company_id,
          details=f"recipient={email} expires_at={expires_at.isoformat()}")
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
    duplicate = db.exec(select(Document).where(
        Document.company_id == user.company_id,
        Document.content_sha256 == data.content_sha256,
    )).first()
    if duplicate:
        raise HTTPException(409, "Duplicate document upload detected")
    key = f"{user.company_id}/{uuid4()}/{data.name}"
    document = Document(
        company_id=user.company_id,
        owner_id=user.id,
        name=data.name,
        category=data.category,
        storage_key=key,
        content_sha256=data.content_sha256,
        content_type=content_type,
    )
    db.add(document); audit(db, request, user, AuditAction.DOCUMENT_CREATED, user.company_id, document.id)
    db.commit(); db.refresh(document)
    return document


@app.get("/api/documents", response_model=list[DocumentResponse])
def list_documents(db: Session = Depends(get_db), user: CompanyUser = Depends(current_user)) -> list[Document]:
    if user.role == UserRole.ADMIN:
        return list(db.exec(select(Document).where(Document.company_id == user.company_id)))
    permitted = select(DocumentPermission.document_id).where(
        DocumentPermission.user_id == user.id,
        DocumentPermission.revoked_at.is_(None),
        (DocumentPermission.expires_at.is_(None) | (DocumentPermission.expires_at > now())),
    )
    return list(db.exec(select(Document).where(
        Document.company_id == user.company_id,
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
        Document.owner_id != user.id,
        Document.id.in_(permitted),
    )))


@app.get("/api/documents/{document_id}", response_model=DocumentResponse)
def get_document(document_id: UUID, db: Session = Depends(get_db), user: CompanyUser = Depends(current_user)) -> Document:
    return tenant_document(db, user, document_id)


@app.patch("/api/documents/{document_id}", response_model=DocumentResponse)
def update_document(document_id: UUID, data: DocumentCreate, db: Session = Depends(get_db),
                    request: Request = None,
                    user: CompanyUser = Depends(current_user)) -> Document:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    document.name = data.name
    document.category = data.category
    document.content_sha256 = data.content_sha256
    document.content_type = validate_content_type(data.content_type)
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
    audit(db, request, user, AuditAction.DOCUMENT_DELETED,
          user.company_id, document.id, details="document_deleted")
    db.delete(document); db.commit()


def s3_client():
    return boto3.client(
        "s3",
        region_name=os.getenv("AWS_REGION") or os.getenv("REGION"),
        endpoint_url=os.getenv("S3_ENDPOINT_URL") or None,
        config=Config(signature_version="s3v4"),
    )


@app.post("/api/documents/{document_id}/upload-url")
def upload_url(document_id: UUID, db: Session = Depends(get_db), user: CompanyUser = Depends(current_user)) -> dict[str, str]:
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    try:
        url = s3_client().generate_presigned_url(
            "put_object",
            Params={
                "Bucket": os.environ["S3_BUCKET"],
                "Key": document.storage_key,
                "ContentType": document.content_type,
                "Metadata": {"content-sha256": document.content_sha256},
            },
            ExpiresIn=900,
        )
    except (KeyError, BotoCoreError, ClientError) as exc: raise HTTPException(503, "Object storage unavailable") from exc
    return {
        "url": url,
        "storage_key": document.storage_key,
        "content_type": document.content_type,
        "content_sha256": document.content_sha256,
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
    try:
        metadata = s3_client().head_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(404, "Uploaded object not found") from exc
    uploaded_hash = metadata.get("Metadata", {}).get("content-sha256", "")
    if uploaded_hash.lower() != document.content_sha256.lower():
        raise HTTPException(422, "Uploaded object checksum does not match")
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
        content_length=metadata.get("ContentLength"),
    )


@app.get("/api/documents/{document_id}/download-url")
def download_url(
    document_id: UUID,
    request: Request,
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
) -> StreamingResponse:
    document = tenant_document(db, user, document_id, PermissionLevel.READ)
    try:
        object_response = s3_client().get_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(404, "Document content unavailable") from exc
    audit(db, request, user, AuditAction.DOCUMENT_DOWNLOAD, user.company_id, document.id)
    db.commit()
    return StreamingResponse(
        object_response["Body"].iter_chunks(chunk_size=1024 * 1024),
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
    document = tenant_document(db, user, document_id)
    if document.owner_id != user.id and user.role != UserRole.ADMIN: raise HTTPException(403, "Write access required")
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
    db.add(permission); audit(db, request, user, AuditAction.PERMISSION_GRANTED, user.company_id, document.id); db.commit()
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
    document = tenant_document(db, user, document_id)
    if document.owner_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Owner access required")
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
    document = tenant_document(db, user, data.document_id)
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
    user: CompanyUser = Depends(require_roles(UserRole.ADMIN)),
) -> AccessSuggestionResponse:
    suggestion = db.get(AccessSuggestion, suggestion_id)
    if not suggestion or suggestion.company_id != user.company_id:
        raise HTTPException(404, "Access suggestion not found")
    if suggestion.status != "PENDING":
        raise HTTPException(409, "Access suggestion has already been decided")
    target = db.get(CompanyUser, suggestion.suggested_user_id)
    if not target or target.company_id != user.company_id:
        raise HTTPException(404, "Suggested user not found")
    if data.approve:
        permission_level = data.permission_level or suggestion.permission_level
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
    audit(db, request, user, action, user.company_id, suggestion.document_id,
          details=f"suggestion_id={suggestion.id};approved={data.approve}")
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
    document = tenant_document(db, user, document_id)
    if document.owner_id != user.id and user.role != UserRole.ADMIN: raise HTTPException(403, "Write access required")
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
    document = tenant_document(db, user, document_id, PermissionLevel.WRITE)
    if document.owner_id != user.id:
        raise HTTPException(403, "Only the document owner can create a share")
    if data.expires_at <= now(): raise HTTPException(400, "Expiry must be in the future")
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
            message_id = send_share_otp(link.recipient_email, otp, link.otp_expires_at)
        except EmailDeliveryError as exc:
            db.rollback()
            raise HTTPException(503, "Share verification email could not be sent") from exc
        audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
              document.id, link.id,
              details=f"share_otp recipient={link.recipient_email} message_id={message_id}")
    elif data.recipient_email:
        try:
            message_id = send_share_link(
                link.recipient_email,
                f"{os.getenv('FRONTEND_URL', 'http://localhost:5173').rstrip('/')}/share/{raw}",
                link.expires_at,
            )
        except EmailDeliveryError as exc:
            db.rollback()
            raise HTTPException(503, "Share email could not be sent") from exc
        audit(db, request, user, AuditAction.EMAIL_SENT, user.company_id,
              document.id, link.id,
              details=f"share_link recipient={link.recipient_email} message_id={message_id}")
    audit(db, request, user, AuditAction.SHARE_LINK_CREATED, user.company_id,
          document.id, link.id, details=f"recipient={link.recipient_email}")
    db.commit()
    db.refresh(link)
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    return ShareResponse(id=link.id, url=f"{frontend_url}/share/{raw}", expires_at=link.expires_at,
                         max_downloads=link.max_downloads)


@app.post("/api/shares/{token}/verify-otp")
def verify_share_otp(
    token: str,
    data: OtpVerificationRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    link = db.exec(select(DocumentShareLink).where(DocumentShareLink.token_hash == token_hash(token))).first()
    rate_limit(request, token_hash(token), 5)
    if not link or link.status != ShareLinkStatus.ACTIVE or not link.otp_code_hash:
        raise HTTPException(404, "OTP verification unavailable")
    if not link.otp_expires_at or link.otp_expires_at <= now() or not verify_password(data.otp, link.otp_code_hash):
        raise HTTPException(401, "Invalid or expired OTP")
    link.otp_verified_at = now()
    db.add(link); db.commit()
    response.set_cookie(
        SHARE_SESSION_COOKIE,
        share_session_value(link),
        max_age=600,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development") == "production",
        samesite="lax",
    )
    return {"status": "verified"}


@app.get("/api/shares/{token}", include_in_schema=False)
def legacy_share_link(token: str) -> RedirectResponse:
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    return RedirectResponse(url=f"{frontend_url}/share/{token}", status_code=307)


@app.post("/api/shares/{token}/download-url")
def share_download(
    token: str,
    request: Request,
    data: ShareAccessRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    link = db.exec(select(DocumentShareLink).where(DocumentShareLink.token_hash == token_hash(token))).first()
    if not link or link.status != ShareLinkStatus.ACTIVE or link.expires_at <= now(): raise HTTPException(404, "Share link unavailable")
    passcode = data.passcode if data else None
    if link.passcode_hash and (not passcode or not verify_password(passcode, link.passcode_hash)): raise HTTPException(401, "Passcode required")
    if link.otp_code_hash and (not link.otp_verified_at or not valid_share_session(request, link)):
        raise HTTPException(401, "OTP verification required")
    if not db.get(Document, link.document_id):
        raise HTTPException(404, "Document not found")
    return {"url": f"/api/shares/{token}/download"}


@app.post("/api/shares/{token}/download")
def share_content(
    token: str,
    request: Request,
    data: ShareAccessRequest | None = None,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    link = db.exec(select(DocumentShareLink).where(
        DocumentShareLink.token_hash == token_hash(token)
    )).first()
    if not link or link.status != ShareLinkStatus.ACTIVE or link.expires_at <= now():
        raise HTTPException(404, "Share link unavailable")
    passcode = data.passcode if data else None
    if link.passcode_hash and (not passcode or not verify_password(passcode, link.passcode_hash)):
        raise HTTPException(401, "Passcode required")
    if link.otp_code_hash and (not link.otp_verified_at or not valid_share_session(request, link)):
        raise HTTPException(401, "OTP verification required")
    document = db.get(Document, link.document_id)
    if not document:
        raise HTTPException(404, "Document not found")
    try:
        object_response = s3_client().get_object(
            Bucket=os.environ["S3_BUCKET"],
            Key=document.storage_key,
        )
    except (KeyError, BotoCoreError, ClientError) as exc:
        raise HTTPException(404, "Document content unavailable") from exc
    from sqlalchemy import update
    result = db.exec(update(DocumentShareLink).where(
        DocumentShareLink.id == link.id,
        DocumentShareLink.status == ShareLinkStatus.ACTIVE,
        DocumentShareLink.download_count < DocumentShareLink.max_downloads,
    ).values(download_count=DocumentShareLink.download_count + 1))
    if result.rowcount != 1:
        raise HTTPException(410, "Download quota exhausted")
    db.refresh(link)
    if link.download_count >= link.max_downloads:
        link.status = ShareLinkStatus.EXHAUSTED
    audit(
        db,
        request,
        None,
        AuditAction.DOCUMENT_DOWNLOAD,
        link.company_id,
        document.id,
        link.id,
        details=f"recipient={link.recipient_email}",
    )
    db.add(link)
    db.commit()
    return StreamingResponse(
        object_response["Body"].iter_chunks(chunk_size=1024 * 1024),
        media_type=document.content_type,
        headers=safe_download_headers(document.name),
    )


@app.post("/api/shares/{share_id}/revoke", status_code=204)
def revoke_share(share_id: UUID, db: Session = Depends(get_db),
                 request: Request = None,
                 user: CompanyUser = Depends(current_user)) -> None:
    link = db.get(DocumentShareLink, share_id)
    if not link or link.company_id != user.company_id: raise HTTPException(404, "Share link not found")
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
    return [
        NotificationResponse(
            id=notification.id,
            audit_event_id=event.id,
            action=event.action,
            details=event.details,
            occurred_at=event.occurred_at,
            read_at=notification.read_at,
        )
        for notification, event in rows
    ]


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
    documents = list(db.exec(select(Document).where(Document.company_id == user.company_id)))
    members = list(db.exec(select(CompanyUser).where(CompanyUser.company_id == user.company_id)))
    events = list(db.exec(select(AuditEvent).where(AuditEvent.company_id == user.company_id)))
    breakdown: dict[str, int] = {}
    for event in events:
        breakdown[event.action.value] = breakdown.get(event.action.value, 0) + 1
    return {
        "documents": len(documents),
        "members": len(members),
        "active_members": sum(member.status == UserStatus.ACTIVE for member in members),
        "audit_events": len(events),
        "event_breakdown": breakdown,
        "alerts": sum(event.action in {AuditAction.USER_LOGIN_FAILED, AuditAction.EMAIL_FAILED, AuditAction.ACCESS_DENIED} for event in events),
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
        current_hash = hashlib.sha256(audit_payload(event).encode()).hexdigest()
        legacy_hash = hashlib.sha256(legacy_audit_payload(event).encode()).hexdigest()
        if event.event_hash not in {current_hash, legacy_hash}:
            return {"valid": False, "checked": expected_sequence - 1, "reason": "hash_mismatch"}
        previous_hash = event.event_hash
    audit(
        db,
        request,
        user,
        AuditAction.AUDIT_INTEGRITY_CHECK,
        user.company_id,
        details=f"checked={len(events)} valid=true",
    )
    db.commit()
    return {"valid": True, "checked": len(events)}
