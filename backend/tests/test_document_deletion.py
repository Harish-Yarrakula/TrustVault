from datetime import timedelta
from uuid import uuid4

from fastapi import HTTPException, Request
import pytest
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

import server
from models import (
    AccessSuggestion,
    AuditAction,
    AuditEvent,
    Company,
    CompanyUser,
    Document,
    DocumentPermission,
    DocumentShareLink,
    PermissionLevel,
    ShareLinkStatus,
    UserRole,
    UserStatus,
)


def test_delete_document_preserves_audit_and_revokes_dependents(monkeypatch):
    test_engine = create_engine("sqlite://")

    @event.listens_for(test_engine, "connect")
    def enable_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SQLModel.metadata.create_all(test_engine)
    company = Company(name="Test", domain_hash=uuid4().hex)
    owner = CompanyUser(
        company_id=company.id,
        email="owner@example.test",
        password_hash="hash",
        role=UserRole.MEMBER,
        status=UserStatus.ACTIVE,
    )
    viewer = CompanyUser(
        company_id=company.id,
        email="viewer@example.test",
        password_hash="hash",
        role=UserRole.MEMBER,
        status=UserStatus.ACTIVE,
    )
    document = Document(
        company_id=company.id,
        owner_id=owner.id,
        name="report.pdf",
        storage_key="report.pdf",
        content_sha256="a" * 64,
        expected_size=10,
    )
    permission = DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission_level=PermissionLevel.READ,
        granted_by=owner.id,
    )
    suggestion = AccessSuggestion(
        company_id=company.id,
        document_id=document.id,
        suggested_user_id=viewer.id,
        permission_level=PermissionLevel.READ,
        rationale="Test suggestion",
        created_by=owner.id,
    )
    share = DocumentShareLink(
        document_id=document.id,
        company_id=company.id,
        token_hash="b" * 64,
        recipient_email=viewer.email,
        expires_at=server.now() + timedelta(days=1),
        created_by=owner.id,
    )
    created_event = AuditEvent(
        company_id=company.id,
        actor_user_id=owner.id,
        document_id=document.id,
        action=AuditAction.DOCUMENT_CREATED,
        sequence_number=1,
        event_hash="c" * 64,
    )
    class FakeStorage:
        def delete_object(self, **_kwargs):
            pass

    monkeypatch.setattr(server, "s3_client", lambda: FakeStorage())
    monkeypatch.setenv("S3_BUCKET", "test-bucket")
    monkeypatch.delenv("AUDIT_ARCHIVE_BUCKET", raising=False)
    request = Request({
        "type": "http",
        "http_version": "1.1",
        "method": "DELETE",
        "scheme": "http",
        "path": f"/api/documents/{document.id}",
        "raw_path": f"/api/documents/{document.id}".encode(),
        "query_string": b"",
        "headers": [(b"user-agent", b"regression-test")],
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    })

    with Session(test_engine) as db:
        db.add_all([company, owner, viewer])
        db.flush()
        db.add(document)
        db.flush()
        db.add_all([permission, suggestion, share, created_event])
        db.commit()
        original_hash = created_event.event_hash

        server.delete_document(document.id, db, request, owner)

        db.expire_all()
        deleted_document = db.get(Document, document.id)
        assert deleted_document is not None
        assert deleted_document.deleted_at is not None
        assert db.get(DocumentPermission, permission.id).revoked_at is not None
        assert db.get(AccessSuggestion, suggestion.id).status == "REJECTED"
        revoked_share = db.get(DocumentShareLink, share.id)
        assert revoked_share.status == ShareLinkStatus.REVOKED
        assert revoked_share.revoked_at is not None
        preserved_event = db.get(AuditEvent, created_event.id)
        assert preserved_event.document_id == document.id
        assert preserved_event.event_hash == original_hash

        deletion_event = db.exec(select(AuditEvent).where(
            AuditEvent.action == AuditAction.DOCUMENT_DELETED,
        )).one()
        assert deletion_event.document_id == document.id
        assert f"document_id={document.id}" in deletion_event.details
        with pytest.raises(HTTPException) as error:
            server.tenant_document(db, owner, document.id)
        assert error.value.status_code == 404

        replacement = Document(
            company_id=company.id,
            owner_id=owner.id,
            name="report-again.pdf",
            storage_key="report-again.pdf",
            content_sha256=document.content_sha256,
            expected_size=10,
        )
        db.add(replacement)
        db.commit()
        assert db.get(Document, replacement.id) is not None
        assert not db.connection().exec_driver_sql("PRAGMA foreign_key_check").fetchall()
