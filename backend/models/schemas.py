from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Index, UniqueConstraint, text
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"
    EXTERNAL_CLIENT = "EXTERNAL_CLIENT"


class UserStatus(str, Enum):
    INVITED = "INVITED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class AccountType(str, Enum):
    CORPORATE = "CORPORATE"
    PERSONAL = "PERSONAL"


class PermissionLevel(str, Enum):
    READ = "READ"
    WRITE = "WRITE"


class ShareLinkStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"


class AuditAction(str, Enum):
    USER_REGISTERED = "USER_REGISTERED"
    USER_LOGIN_SUCCESS = "USER_LOGIN_SUCCESS"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    USER_LOGOUT = "USER_LOGOUT"
    DOCUMENT_CREATED = "DOCUMENT_CREATED"
    DOCUMENT_UPDATED = "DOCUMENT_UPDATED"
    DOCUMENT_DELETED = "DOCUMENT_DELETED"
    GUEST_INVITED = "GUEST_INVITED"
    GUEST_ACTIVATED = "GUEST_ACTIVATED"
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"
    SHARE_LINK_CREATED = "SHARE_LINK_CREATED"
    SHARE_LINK_REVOKED = "SHARE_LINK_REVOKED"
    EXTERNAL_AUTH_PASS = "EXTERNAL_AUTH_PASS"
    DOCUMENT_PREVIEW = "DOCUMENT_PREVIEW"
    DOCUMENT_DOWNLOAD = "DOCUMENT_DOWNLOAD"
    EMAIL_SENT = "EMAIL_SENT"
    EMAIL_FAILED = "EMAIL_FAILED"
    AI_ACCESS_SUGGESTED = "AI_ACCESS_SUGGESTED"
    AI_ACCESS_CONFIRMED = "AI_ACCESS_CONFIRMED"
    AI_ACCESS_REJECTED = "AI_ACCESS_REJECTED"
    ROLE_CHANGED = "ROLE_CHANGED"
    ACCESS_DENIED = "ACCESS_DENIED"
    AUDIT_INTEGRITY_CHECK = "AUDIT_INTEGRITY_CHECK"


PERSONAL_EMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
        "zoho.com",
    }
)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    local_part, separator, domain = normalized.rpartition("@")
    if not separator or not local_part or not domain:
        raise ValueError("A valid email address is required")
    return f"{local_part}@{domain}"


def tenant_key_for_email(email: str) -> tuple[str, AccountType]:
    normalized_email = normalize_email(email)
    domain = normalized_email.rsplit("@", 1)[1]
    account_type = (
        AccountType.PERSONAL
        if domain in PERSONAL_EMAIL_DOMAINS
        else AccountType.CORPORATE
    )
    tenant_key = domain if account_type is AccountType.CORPORATE else normalized_email
    return tenant_key, account_type


def tenant_identity_for_email(email: str) -> tuple[UUID, AccountType]:
    tenant_key, account_type = tenant_key_for_email(email)
    tenant_hash = hashlib.sha256(tenant_key.encode("utf-8")).hexdigest()
    return UUID(hex=tenant_hash[:32]), account_type


class Company(SQLModel, table=True):
    __tablename__ = "companies"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(index=True, max_length=255)
    account_type: AccountType = Field(
        default=AccountType.CORPORATE, nullable=False
    )
    domain_hash: str = Field(max_length=64, unique=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, nullable=False)

    @classmethod
    def for_email(cls, email: str, name: Optional[str] = None) -> "Company":
        normalized_email = normalize_email(email)
        tenant_key, account_type = tenant_key_for_email(normalized_email)
        tenant_hash = hashlib.sha256(tenant_key.encode("utf-8")).hexdigest()
        domain = normalized_email.rsplit("@", 1)[1]
        return cls(
            id=UUID(hex=tenant_hash[:32]),
            name=name or domain,
            account_type=account_type,
            domain_hash=tenant_hash,
        )


class CompanyUser(SQLModel, table=True):
    __tablename__ = "company_users"
    __table_args__ = (UniqueConstraint("email", name="uq_company_users_email"),)

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    company_id: UUID = Field(foreign_key="companies.id", index=True, nullable=False)
    email: str = Field(index=True, max_length=255)
    full_name: str = Field(default="", max_length=255, nullable=False)
    password_hash: str = Field(max_length=255, nullable=False)
    account_type: AccountType = Field(
        default=AccountType.CORPORATE, nullable=False
    )
    role: UserRole = Field(default=UserRole.MEMBER, nullable=False)
    status: UserStatus = Field(default=UserStatus.INVITED, nullable=False)
    invitation_token_hash: Optional[str] = Field(default=None, max_length=128)
    invitation_expires_at: Optional[datetime] = Field(default=None)
    invitation_accepted_at: Optional[datetime] = Field(default=None)
    access_expires_at: Optional[datetime] = Field(default=None, index=True)
    session_version: int = Field(default=0, nullable=False)
    mfa_enabled: bool = Field(default=False, nullable=False)
    mfa_secret_encrypted: Optional[str] = Field(default=None, max_length=512)
    mfa_pending_secret_encrypted: Optional[str] = Field(default=None, max_length=512)
    mfa_recovery_hashes: Optional[str] = Field(default=None)
    mfa_last_verified_step: Optional[int] = Field(default=None)
    invited_by: Optional[UUID] = Field(default=None, foreign_key="company_users.id")
    created_at: datetime = Field(default_factory=utc_now, nullable=False)
    updated_at: datetime = Field(default_factory=utc_now, nullable=False)

    @classmethod
    def for_email(cls, email: str, **kwargs: object) -> "CompanyUser":
        normalized_email = normalize_email(email)
        company_id, account_type = tenant_identity_for_email(normalized_email)
        return cls(
            email=normalized_email,
            company_id=company_id,
            account_type=account_type,
            **kwargs,
        )


class Document(SQLModel, table=True):
    __tablename__ = "documents"
    __table_args__ = (
        Index(
            "uq_documents_company_checksum_active",
            "company_id",
            "content_sha256",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
            sqlite_where=text("deleted_at IS NULL"),
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    company_id: UUID = Field(foreign_key="companies.id", index=True, nullable=False)
    owner_id: UUID = Field(foreign_key="company_users.id", index=True, nullable=False)
    name: str = Field(max_length=255)
    category: str = Field(default="Other", max_length=100, nullable=False, index=True)
    storage_key: str = Field(max_length=1024)
    content_sha256: str = Field(max_length=64)
    content_type: str = Field(
        default="application/octet-stream", max_length=255, nullable=False
    )
    expected_size: Optional[int] = Field(default=None, ge=1)
    upload_verified_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utc_now, nullable=False)
    updated_at: datetime = Field(default_factory=utc_now, nullable=False)
    deleted_at: Optional[datetime] = Field(default=None, index=True)


class DocumentPermission(SQLModel, table=True):
    __tablename__ = "document_permissions"
    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_permissions_document_user",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    document_id: UUID = Field(
        foreign_key="documents.id", index=True, nullable=False
    )
    user_id: UUID = Field(
        foreign_key="company_users.id", index=True, nullable=False
    )
    permission_level: PermissionLevel = Field(
        default=PermissionLevel.READ, nullable=False
    )
    granted_by: UUID = Field(foreign_key="company_users.id", nullable=False)
    granted_at: datetime = Field(default_factory=utc_now, nullable=False)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    revoked_at: Optional[datetime] = Field(default=None)


class AccessSuggestion(SQLModel, table=True):
    __tablename__ = "access_suggestions"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    company_id: UUID = Field(foreign_key="companies.id", index=True, nullable=False)
    document_id: UUID = Field(foreign_key="documents.id", index=True, nullable=False)
    suggested_user_id: UUID = Field(
        foreign_key="company_users.id", index=True, nullable=False
    )
    permission_level: PermissionLevel = Field(nullable=False)
    rationale: str = Field(max_length=1000)
    status: str = Field(default="PENDING", max_length=32, index=True)
    created_by: UUID = Field(foreign_key="company_users.id", nullable=False)
    created_at: datetime = Field(default_factory=utc_now, nullable=False)
    decided_at: Optional[datetime] = Field(default=None)


class DocumentShareLink(SQLModel, table=True):
    __tablename__ = "document_share_links"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    document_id: UUID = Field(
        foreign_key="documents.id", index=True, nullable=False
    )
    company_id: UUID = Field(foreign_key="companies.id", index=True, nullable=False)
    token_hash: str = Field(unique=True, index=True, max_length=128)
    passcode_hash: Optional[str] = Field(default=None, max_length=255)
    otp_code_hash: Optional[str] = Field(default=None, max_length=255)
    otp_expires_at: Optional[datetime] = Field(default=None)
    otp_verified_at: Optional[datetime] = Field(default=None)
    otp_attempts: int = Field(default=0, nullable=False)
    otp_locked_until: Optional[datetime] = Field(default=None)
    recipient_email: str = Field(max_length=255, index=True)
    max_downloads: int = Field(default=1, ge=1, nullable=False)
    download_count: int = Field(default=0, ge=0, nullable=False)
    expires_at: datetime = Field(index=True, nullable=False)
    status: ShareLinkStatus = Field(
        default=ShareLinkStatus.ACTIVE, nullable=False
    )
    revoked_at: Optional[datetime] = Field(default=None)
    created_by: UUID = Field(foreign_key="company_users.id", nullable=False)
    created_at: datetime = Field(default_factory=utc_now, nullable=False)


class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint(
            "company_id",
            "sequence_number",
            name="uq_audit_events_company_sequence",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    company_id: UUID = Field(foreign_key="companies.id", index=True, nullable=False)
    actor_user_id: Optional[UUID] = Field(
        default=None, foreign_key="company_users.id", index=True
    )
    recipient_email: Optional[str] = Field(default=None, max_length=255)
    document_id: Optional[UUID] = Field(
        default=None, foreign_key="documents.id", index=True
    )
    share_link_id: Optional[UUID] = Field(
        default=None, foreign_key="document_share_links.id", index=True
    )
    action: AuditAction = Field(nullable=False)
    details: Optional[str] = Field(default=None)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    request_id: Optional[str] = Field(default=None, max_length=100, index=True)
    user_agent: Optional[str] = Field(default=None, max_length=512)
    sequence_number: int = Field(nullable=False)
    previous_event_hash: Optional[str] = Field(default=None, max_length=128)
    event_hash: str = Field(max_length=128)
    occurred_at: datetime = Field(default_factory=utc_now, index=True, nullable=False)


class UserNotification(SQLModel, table=True):
    __tablename__ = "user_notifications"
    __table_args__ = (
        UniqueConstraint("user_id", "audit_event_id", name="uq_user_notifications_event"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="company_users.id", index=True, nullable=False)
    audit_event_id: UUID = Field(foreign_key="audit_events.id", index=True, nullable=False)
    read_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now, index=True, nullable=False)


class RateLimitBucket(SQLModel, table=True):
    __tablename__ = "rate_limit_buckets"

    key_hash: str = Field(max_length=64, primary_key=True)
    window_started_at: datetime = Field(default_factory=utc_now, nullable=False)
    attempt_count: int = Field(default=0, nullable=False)
