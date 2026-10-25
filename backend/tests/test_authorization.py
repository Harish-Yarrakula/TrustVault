from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import socket
from types import SimpleNamespace
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from fastapi import Request
from jose import jwt
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from fastapi import HTTPException, Response
from models import (
    AuditAction, AuditEvent, Company, CompanyUser, Document, DocumentPermission, DocumentShareLink,
    PermissionLevel, ShareLinkStatus, UserRole, UserStatus,
)
from server import (
    DocumentCreate, GuestInviteRequest, MfaChallengeRequest, MfaCodeRequest, MemberInviteRequest,
    OtpVerificationRequest, PermissionRequest, RegisterRequest, ShareRequest,
    ShareExchangeRequest, audit_payload, client_ip, create_share,
    confirm_mfa, detect_document_type, exchange_share_token, hash_password,
    invite_company_member, now, rate_limit, register, setup_mfa,
    share_link_from_session, share_session_value, tenant_document, totp_code,
    verify_share_otp_for_link,
    archive_audit_event, audit_archive_key, audit_archive_body,
    start_malware_scan, scan_chunk, finish_malware_scan,
    encrypt_mfa_secret, verify_mfa_challenge, verify_document_upload, config_secret,
    audit, audit_payload_candidates, grant_permission, invite_guest,
    list_notifications, me, admin_analytics, create_document,
    safe_download_headers,
    resend_current_share_otp,
)


@pytest.fixture()
def database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        company = Company(id=uuid4(), name="Test", domain_hash=uuid4().hex)
        owner = CompanyUser(
            company_id=company.id,
            email="owner@example.test",
            password_hash="hash",
            full_name="Owner",
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        viewer = CompanyUser(
            company_id=company.id,
            email="viewer@example.test",
            password_hash="hash",
            full_name="Viewer",
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        document = Document(
            company_id=company.id,
            owner_id=owner.id,
            name="secret.txt",
            storage_key="secret",
            content_sha256="0" * 64,
        )
        db.add_all([company, owner, viewer, document])
        db.commit()
        db.refresh(owner)
        db.refresh(viewer)
        db.refresh(document)
        yield db, owner, viewer, document


def test_ungranted_user_cannot_read_document(database):
    db, _, viewer, document = database
    with pytest.raises(Exception, match="Document access denied"):
        tenant_document(db, viewer, document.id)


def test_administrator_does_not_bypass_document_permissions(database):
    db, _, viewer, document = database
    viewer.role = UserRole.ADMIN
    db.add(viewer)
    db.commit()
    with pytest.raises(HTTPException, match="Document access denied"):
        tenant_document(db, viewer, document.id)


def test_corporate_self_registration_is_rejected(database):
    db, _, _, _ = database
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={},
    )
    with pytest.raises(HTTPException, match="administrator invitation"):
        register(
            RegisterRequest(
                full_name="New User",
                email="new@company.example.com",
                password="strong-password",
            ),
            request,
            db,
        )


def test_admin_invitation_creates_member_not_admin(database, monkeypatch):
    db, owner, _, _ = database
    owner.role = UserRole.ADMIN
    db.add(owner)
    db.commit()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="request-1"),
    )
    monkeypatch.setattr("server.send_guest_invitation", lambda *_: "sent")

    invite_company_member(
        MemberInviteRequest(email="invited@company.example.com"),
        request,
        db,
        owner,
    )
    invited = db.exec(
        select(CompanyUser).where(CompanyUser.email == "invited@company.example.com")
    ).one()
    assert invited.role == UserRole.MEMBER
    assert invited.status == UserStatus.INVITED


def test_read_grant_allows_read_but_not_write(database):
    db, owner, viewer, document = database
    db.add(DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission_level=PermissionLevel.READ,
        granted_by=owner.id,
    ))
    db.commit()
    assert tenant_document(db, viewer, document.id).id == document.id
    with pytest.raises(Exception, match="Document access denied"):
        tenant_document(db, viewer, document.id, PermissionLevel.WRITE)


def test_revoked_grant_blocks_immediately(database):
    db, owner, viewer, document = database
    permission = DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission_level=PermissionLevel.WRITE,
        granted_by=owner.id,
    )
    db.add(permission)
    db.commit()
    assert tenant_document(db, viewer, document.id, PermissionLevel.WRITE).id == document.id
    permission.revoked_at = datetime.now(timezone.utc)
    db.add(permission)
    db.commit()
    with pytest.raises(Exception, match="Document access denied"):
        tenant_document(db, viewer, document.id)


def test_audit_payload_changes_when_request_metadata_changes():
    event = SimpleNamespace(
        company_id=uuid4(),
        sequence_number=1,
        action=SimpleNamespace(value="DOCUMENT_DOWNLOAD"),
        actor_user_id=uuid4(),
        document_id=uuid4(),
        share_link_id=None,
        details="opened",
        occurred_at=now(),
        ip_address="127.0.0.1",
        request_id="request-1",
        user_agent="test-agent",
        previous_event_hash=None,
    )
    original = audit_payload(event)
    event.ip_address = "10.0.0.2"
    assert audit_payload(event) != original
    event.ip_address = "127.0.0.1"
    event.occurred_at += timedelta(seconds=1)
    assert audit_payload(event) != original


def test_new_audit_hash_remains_valid_after_database_round_trip(database):
    db, owner, _, _ = database
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="audit-round-trip"),
    )
    audit(db, request, owner, AuditAction.USER_LOGIN_SUCCESS, owner.company_id)
    db.commit()
    event = db.exec(select(AuditEvent).where(
        AuditEvent.company_id == owner.company_id
    )).one()
    assert any(
        hashlib.sha256(payload.encode()).hexdigest() == event.event_hash
        for payload in audit_payload_candidates(event)
    )


def test_document_assignment_creates_recipient_update(database):
    db, owner, recipient, document = database
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="assignment-notification"),
    )
    grant_permission(
        document.id,
        PermissionRequest(user_id=recipient.id, permission_level=PermissionLevel.READ),
        request,
        db,
        owner,
    )

    updates = list_notifications(db, recipient, limit=50)
    assert len(updates) == 1
    assert updates[0].action == AuditAction.PERMISSION_GRANTED
    assert updates[0].document_id == document.id
    assert updates[0].document_name == document.name
    assert updates[0].actor_name == owner.full_name


def test_document_invitation_creates_update_for_invited_recipient(database, monkeypatch):
    db, owner, _, document = database
    monkeypatch.setattr("server.send_guest_invitation", lambda *_args: "sent")
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="guest-assignment-notification"),
    )
    invite_guest(
        GuestInviteRequest(
            email="partner@external.example",
            document_id=document.id,
        ),
        request,
        db,
        owner,
    )
    guest = db.exec(select(CompanyUser).where(
        CompanyUser.email == "partner@external.example"
    )).one()
    updates = list_notifications(db, guest, limit=50)
    assert len(updates) == 1
    assert updates[0].action == AuditAction.GUEST_INVITED
    assert updates[0].document_name == document.name


def test_current_user_response_includes_company_name(database):
    db, owner, _, _ = database
    assert me(db, owner)["company_name"] == "Test"


def test_retry_reuses_same_owners_incomplete_document_upload(database):
    db, owner, _, _ = database
    checksum = "2" * 64
    pending = Document(
        company_id=owner.company_id,
        owner_id=owner.id,
        name="previous-name.pdf",
        category="Other",
        storage_key=f"{owner.company_id}/pending/document.pdf",
        content_sha256=checksum,
        content_type="application/pdf",
        expected_size=123,
    )
    db.add(pending)
    db.commit()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="retry-incomplete-upload"),
    )

    retried = create_document(
        DocumentCreate(
            name="document.pdf",
            category="Contracts",
            content_sha256=checksum,
            content_type="application/pdf",
            file_size=123,
        ),
        request,
        db,
        owner,
    )

    assert retried.id == pending.id
    assert retried.name == "document.pdf"
    assert retried.category == "Contracts"
    assert retried.upload_verified_at is None


def test_duplicate_verified_document_is_not_treated_as_retry(database):
    db, owner, _, document = database
    document.content_sha256 = "3" * 64
    document.content_type = "application/pdf"
    document.expected_size = 123
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="duplicate-verified-upload"),
    )

    with pytest.raises(HTTPException, match="identical contents already exists"):
        create_document(
            DocumentCreate(
                name="duplicate.pdf",
                category="Contracts",
                content_sha256=document.content_sha256,
                content_type="application/pdf",
                file_size=123,
            ),
            request,
            db,
            owner,
        )


def test_admin_analytics_uses_company_events_categories_and_alerts(database):
    db, owner, _, document = database
    owner.role = UserRole.ADMIN
    document.category = "Contracts"
    db.add_all([owner, document])
    db.add(Document(
        company_id=owner.company_id,
        owner_id=owner.id,
        name="policy.pdf",
        category="Policies",
        storage_key="policy",
        content_sha256="1" * 64,
    ))
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="analytics-test"),
    )
    audit(db, request, owner, AuditAction.USER_LOGIN_FAILED, owner.company_id)
    audit(db, request, owner, AuditAction.DOCUMENT_CREATED, owner.company_id)
    old_event = audit(db, request, owner, AuditAction.USER_LOGIN_SUCCESS, owner.company_id)
    old_event.occurred_at = now() - timedelta(days=31)
    db.add(old_event)
    db.commit()

    analytics = admin_analytics(db, owner)

    assert analytics["documents"] == 2
    assert analytics["documents_by_category"] == {"Contracts": 1, "Policies": 1}
    assert analytics["audit_events"] == 3
    assert analytics["events_30d"] == 2
    assert analytics["alerts_30d"] == 1
    assert analytics["unread_alerts"] == 1
    assert sum(point["count"] for point in analytics["activity_by_day"]) == 2
    assert len(analytics["activity_by_day"]) == 30
    assert analytics["recent_alerts"][0]["action"] == AuditAction.USER_LOGIN_FAILED.value
    assert analytics["recent_alerts"][0]["actor_email"] == owner.email


def test_admin_analytics_empty_activity_has_no_fabricated_records(database):
    db, owner, _, document = database
    owner.role = UserRole.ADMIN
    db.add(owner)
    db.delete(document)
    db.commit()

    analytics = admin_analytics(db, owner)

    assert analytics["documents"] == 0
    assert analytics["documents_by_category"] == {}
    assert analytics["audit_events"] == 0
    assert analytics["event_breakdown"] == {}
    assert analytics["events_30d"] == 0
    assert analytics["alerts_30d"] == 0
    assert analytics["unread_alerts"] == 0
    assert analytics["recent_alerts"] == []
    assert len(analytics["activity_by_day"]) == 30
    assert all(point["count"] == 0 for point in analytics["activity_by_day"])


def test_client_ip_uses_direct_client_by_default():
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    assert client_ip(request) == "127.0.0.1"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("quarterly report.pdf", "quarterly report.pdf"),
        ("photo.jpeg", "photo.jpeg"),
        ("diagram.PNG", "diagram.PNG"),
        ("archive.original.pdf", "archive.original.pdf"),
        ("name without extension", "name without extension"),
    ],
)
def test_safe_download_headers_preserve_uploaded_filename(name, expected):
    headers = safe_download_headers(name)
    assert f'filename="{expected}"' in headers["Content-Disposition"]
    assert "filename*=UTF-8''" in headers["Content-Disposition"]


def test_database_rate_limit_persists_attempts(database, monkeypatch):
    db, _, _, _ = database
    monkeypatch.setattr("server.secrets.randbelow", lambda _: 0)
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={},
    )
    rate_limit(request, "login", db, limit=1)
    with pytest.raises(HTTPException, match="Rate limit exceeded"):
        rate_limit(request, "login", db, limit=1)


def test_otp_attempt_limit_locks_share(database):
    db, owner, _, document = database
    link = DocumentShareLink(
        document_id=document.id,
        company_id=owner.company_id,
        token_hash="a" * 64,
        otp_code_hash=hash_password("123456"),
        otp_expires_at=now() + timedelta(days=1),
        recipient_email="recipient@example.test",
        expires_at=now() + timedelta(days=1),
        created_by=owner.id,
        status=ShareLinkStatus.ACTIVE,
    )
    db.add(link)
    db.commit()

    for _ in range(5):
        with pytest.raises(HTTPException, match="Invalid or expired OTP"):
            verify_share_otp_for_link(
                OtpVerificationRequest(otp="000000"),
                Response(),
                db,
                link,
            )

    db.refresh(link)
    assert link.otp_attempts == 5
    assert link.otp_locked_until is not None
    with pytest.raises(HTTPException, match="temporarily locked"):
        verify_share_otp_for_link(
            OtpVerificationRequest(otp="123456"),
            Response(),
            db,
            link,
        )


def test_successful_otp_is_one_time(database):
    db, owner, _, document = database
    link = DocumentShareLink(
        document_id=document.id,
        company_id=owner.company_id,
        token_hash="b" * 64,
        otp_code_hash=hash_password("123456"),
        otp_expires_at=now() + timedelta(days=1),
        recipient_email="recipient@example.test",
        expires_at=now() + timedelta(days=1),
        created_by=owner.id,
        status=ShareLinkStatus.ACTIVE,
    )
    db.add(link)
    db.commit()
    verify_share_otp_for_link(
        OtpVerificationRequest(otp="123456"),
        Response(),
        db,
        link,
    )
    assert link.otp_code_hash is None
    with pytest.raises(HTTPException, match="OTP verification unavailable"):
        verify_share_otp_for_link(
            OtpVerificationRequest(otp="123456"),
            Response(),
            db,
            link,
        )


def test_share_token_is_exchanged_for_a_short_lived_session(database, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    db, owner, _, document = database
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    monkeypatch.setattr(
        "server.verify_document_upload",
        lambda *_args: (document.content_sha256, 1, b"%PDF-1.7"),
    )
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="request-1"),
    )
    result = create_share(
        document.id,
        ShareRequest(expires_at=now() + timedelta(hours=1)),
        request,
        db,
        owner,
    )
    assert "#token=" in result.url
    token = result.url.split("#token=", 1)[1]
    response = Response()
    exchange_share_token(ShareExchangeRequest(token=token), response, db)
    set_cookie = response.headers["set-cookie"].lower()
    assert "samesite=none" in set_cookie
    assert "; secure" in set_cookie
    cookie = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    session_request = SimpleNamespace(cookies={"trustvault_share_session": cookie})
    assert share_link_from_session(session_request, db).document_id == document.id


def test_otp_share_emails_link_and_code_to_recipient(database, monkeypatch):
    db, owner, _, document = database
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    monkeypatch.setenv("FRONTEND_URL", "https://trustvaultweb.netlify.app")
    monkeypatch.setattr(
        "server.verify_document_upload",
        lambda *_args: (document.content_sha256, 1, b"%PDF-1.7"),
    )
    sent = []
    monkeypatch.setattr(
        "server.send_share_otp",
        lambda email, _otp, _expires: sent.append(("otp", email)),
    )
    monkeypatch.setattr(
        "server.send_share_link",
        lambda email, url, _expires, otp_required=False: sent.append(
            ("link", email, url, otp_required)
        ),
    )
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="request-otp-share"),
    )

    result = create_share(
        document.id,
        ShareRequest(
            expires_at=now() + timedelta(hours=1),
            recipient_email="recipient@example.com",
            require_otp=True,
        ),
        request,
        db,
        owner,
    )

    assert sent[0] == ("otp", "recipient@example.com")
    assert sent[1][0:2] == ("link", "recipient@example.com")
    assert sent[1][2] == result.url
    assert sent[1][3] is True


def test_otp_share_requires_recipient_email(database):
    db, owner, _, document = database
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="request-otp-no-recipient"),
    )

    with pytest.raises(HTTPException, match="recipient email is required"):
        create_share(
            document.id,
            ShareRequest(
                expires_at=now() + timedelta(hours=1),
                require_otp=True,
            ),
            request,
            db,
            owner,
        )


def test_resend_share_otp_replaces_expired_code_and_sends_email(database, monkeypatch):
    db, owner, _, document = database
    link = DocumentShareLink(
        document_id=document.id,
        company_id=owner.company_id,
        token_hash="c" * 64,
        otp_code_hash=hash_password("123456"),
        otp_expires_at=now() - timedelta(minutes=1),
        recipient_email="recipient@example.com",
        expires_at=now() + timedelta(hours=1),
        created_by=owner.id,
        status=ShareLinkStatus.ACTIVE,
        otp_attempts=2,
    )
    db.add(link)
    db.commit()
    previous_hash = link.otp_code_hash
    cookie = share_session_value(link)
    request = SimpleNamespace(
        cookies={"trustvault_share_session": cookie},
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="request-resend-otp"),
    )
    sent = []
    monkeypatch.setattr("server.send_share_otp", lambda *args: sent.append(args))
    monkeypatch.setattr("server.secrets.randbelow", lambda _: 654321)
    monkeypatch.setattr("server.rate_limit", lambda *_args, **_kwargs: None)

    result = resend_current_share_otp(request, db)

    assert result == {"status": "sent"}
    assert sent[0][0:2] == ("recipient@example.com", "654321")
    db.refresh(link)
    assert link.otp_code_hash != previous_hash
    assert link.otp_expires_at.replace(tzinfo=timezone.utc) > now()
    assert link.otp_attempts == 0
    assert link.otp_locked_until is None
    verify_share_otp_for_link(
        OtpVerificationRequest(otp="654321"),
        Response(),
        db,
        link,
    )
    assert link.otp_verified_at is not None


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"%PDF-1.7", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"not a supported document", None),
    ],
)
def test_document_type_detection_uses_file_signature(content, expected):
    assert detect_document_type(content) == expected


def test_totp_matches_rfc_vector():
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1) == "287082"


def test_admin_mfa_setup_issues_single_use_recovery_codes(database, monkeypatch):
    db, owner, _, _ = database
    owner.role = UserRole.ADMIN
    db.add(owner)
    db.commit()
    setup = setup_mfa(db, owner)
    current_step = int(now().timestamp()) // 30
    monkeypatch.setattr("server.now", lambda: datetime.fromtimestamp(current_step * 30, timezone.utc))
    response = Response()
    result = confirm_mfa(
        MfaCodeRequest(code=totp_code(setup["secret"], current_step)),
        response,
        db,
        owner,
    )
    assert owner.mfa_enabled
    assert len(result["recovery_codes"]) == 10
    assert all(len(code) == 32 for code in result["recovery_codes"])
    assert result["access_token"]
    assert "trustvault_auth=" in response.headers["set-cookie"]


def test_audit_archive_is_immutable_idempotent_and_hash_addressed(database, monkeypatch):
    db, owner, _, _ = database
    monkeypatch.setenv("AUDIT_ARCHIVE_BUCKET", "audit-test")
    event = SimpleNamespace(
        company_id=owner.company_id,
        sequence_number=1,
        action=AuditAction.USER_LOGIN_SUCCESS,
        actor_user_id=owner.id,
        document_id=None,
        share_link_id=None,
        details=None,
        occurred_at=now(),
        ip_address=None,
        request_id="request-1",
        user_agent=None,
        previous_event_hash=None,
    )
    event.event_hash = hashlib.sha256(audit_payload(event).encode()).hexdigest()

    class FakeStorage:
        def __init__(self):
            self.objects = {}
            self.put_calls = 0

        def head_object(self, Bucket, Key):
            if Key not in self.objects:
                raise ClientError({"Error": {"Code": "404"}}, "HeadObject")

        def put_object(self, Bucket, Key, Body, **kwargs):
            self.put_calls += 1
            self.objects[Key] = Body

        def get_object(self, Bucket, Key):
            return {"Body": BytesIO(self.objects[Key])}

    storage = FakeStorage()
    monkeypatch.setattr("server.s3_client", lambda: storage)
    archive_audit_event(event)
    archive_audit_event(event)
    assert audit_archive_key(event).endswith(f"-{event.event_hash}.json")
    assert storage.put_calls == 1
    assert audit_archive_body(event)


def test_clamav_scanner_stream_protocol(monkeypatch):
    class FakeScanner:
        def __init__(self, result):
            self.result = result
            self.sent = []
            self.closed = False

        def settimeout(self, timeout):
            self.timeout = timeout

        def sendall(self, payload):
            self.sent.append(payload)

        def recv(self, size):
            return self.result

        def close(self):
            self.closed = True

    scanner = FakeScanner(b"stream: OK\0")
    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setattr("server.socket.create_connection", lambda *_args, **_kwargs: scanner)
    active_scanner = start_malware_scan()
    scan_chunk(active_scanner, b"file")
    finish_malware_scan(active_scanner)
    assert scanner.sent == [b"zINSTREAM\0", b"\0\0\0\x04file", b"\0\0\0\0"]
    assert scanner.closed


def test_clamav_detected_file_fails_closed(monkeypatch):
    class FakeScanner:
        def settimeout(self, timeout):
            pass

        def sendall(self, payload):
            pass

        def recv(self, size):
            return b"stream: Eicar-Test-Signature FOUND\0"

        def close(self):
            self.closed = True

    scanner = FakeScanner()
    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setattr("server.socket.create_connection", lambda *_args, **_kwargs: scanner)
    with pytest.raises(HTTPException, match="Malware was detected"):
        finish_malware_scan(scanner)
    assert scanner.closed


def test_clamav_missing_in_production_fails_closed(monkeypatch):
    monkeypatch.delenv("CLAMAV_HOST", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(HTTPException, match="not configured"):
        start_malware_scan()


def test_verified_upload_is_rechecked_and_returns_scanned_bytes(database, monkeypatch):
    db, _, _, document = database
    content = b"%PDF-1.7"
    document.content_type = "application/pdf"
    document.content_sha256 = hashlib.sha256(content).hexdigest()
    document.expected_size = len(content)
    document.upload_verified_at = now()
    db.add(document)
    db.commit()
    body = BytesIO(content)

    class FakeStorage:
        def head_object(self, **kwargs):
            return {"ContentLength": len(content)}

        def get_object(self, **kwargs):
            return {"Body": body}

    class FakeScanner:
        def settimeout(self, timeout):
            pass

        def sendall(self, payload):
            pass

        def recv(self, size):
            return b"stream: OK\0"

        def close(self):
            pass

    monkeypatch.setenv("S3_BUCKET", "documents")
    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setattr("server.s3_client", lambda: FakeStorage())
    monkeypatch.setattr("server.socket.create_connection", lambda *_args, **_kwargs: FakeScanner())

    verified_hash, verified_size, verified_content = verify_document_upload(document, db)
    assert verified_hash == document.content_sha256
    assert verified_size == len(content)
    assert verified_content == content
    assert body.closed


def test_upload_body_closes_when_scanner_connection_fails(database, monkeypatch):
    db, _, _, document = database
    content = b"%PDF-1.7"
    body = BytesIO(content)

    class FakeStorage:
        def head_object(self, **kwargs):
            return {"ContentLength": len(content)}

        def get_object(self, **kwargs):
            return {"Body": body}

    monkeypatch.setenv("S3_BUCKET", "documents")
    monkeypatch.setenv("CLAMAV_HOST", "clamav")
    monkeypatch.setattr("server.s3_client", lambda: FakeStorage())

    def fail_connection(*_args, **_kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(
        "server.socket.create_connection",
        fail_connection,
    )

    with pytest.raises(HTTPException, match="Malware scanner is unavailable"):
        verify_document_upload(document, db)
    assert body.closed


def test_mfa_setup_gate_and_logout_for_existing_cookie(database, monkeypatch):
    db, owner, _, _ = database
    owner.role = UserRole.ADMIN
    owner.password_hash = hash_password("example-password")
    db.add(owner)
    db.commit()
    request = Request({
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/documents",
        "raw_path": b"/api/documents",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 8000),
        "server": ("test", 8000),
    })
    from server import create_access_token, current_user, login

    with pytest.raises(HTTPException, match="MFA enrollment is required"):
        current_user(request, create_access_token(owner), db)

    owner.mfa_enabled = True
    db.add(owner)
    db.commit()
    request.cookies["trustvault_auth"] = "stale-cookie"
    response = login(
        SimpleNamespace(username=owner.email, password="example-password"),
        request,
        db,
    )
    assert response.body and b"mfa_required" in response.body
    assert "trustvault_auth" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_mfa_challenge_prevents_totp_replay(database, monkeypatch):
    db, owner, _, _ = database
    owner.role = UserRole.ADMIN
    owner.mfa_enabled = True
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    owner.mfa_secret_encrypted = encrypt_mfa_secret(owner.id, secret)
    owner.password_hash = hash_password("example-password")
    db.add(owner)
    db.commit()

    step = int(now().timestamp()) // 30
    monkeypatch.setattr(
        "server.now",
        lambda: datetime.fromtimestamp(step * 30, timezone.utc),
    )
    challenge = jwt.encode(
        {
            "sub": str(owner.id),
            "company_id": str(owner.company_id),
            "session_version": owner.session_version,
            "mfa_challenge": True,
            "exp": int(now().timestamp()) + 300,
        },
            config_secret(),
        algorithm="HS256",
    )
    request = SimpleNamespace(
        client=SimpleNamespace(host="127.0.0.1"),
        headers={"user-agent": "test"},
        state=SimpleNamespace(request_id="mfa-request"),
    )
    data = MfaChallengeRequest(challenge_token=challenge, code=totp_code(secret, step))
    response = verify_mfa_challenge(data, request, Response(), db)
    assert response["access_token"]

    with pytest.raises(HTTPException, match="Invalid authenticator or recovery code"):
        verify_mfa_challenge(data, request, Response(), db)
