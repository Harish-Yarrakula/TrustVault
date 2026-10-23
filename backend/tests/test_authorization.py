from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from models import Company, CompanyUser, Document, DocumentPermission, PermissionLevel, UserRole, UserStatus
from server import audit_payload, client_ip, tenant_document


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
        ip_address="127.0.0.1",
        request_id="request-1",
        user_agent="test-agent",
        previous_event_hash=None,
    )
    original = audit_payload(event)
    event.ip_address = "10.0.0.2"
    assert audit_payload(event) != original


def test_client_ip_uses_direct_client_by_default():
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    assert client_ip(request) == "127.0.0.1"
