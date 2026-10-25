import hashlib
import hmac
import os

from sqlmodel import Session, select

from db import engine
from models import AuditEvent, Company
from server import archive_audit_event, audit_payload_candidates, startup


def main() -> None:
    if not os.getenv("AUDIT_ARCHIVE_BUCKET"):
        raise RuntimeError("Set AUDIT_ARCHIVE_BUCKET before archiving audit history")
    startup()
    with Session(engine) as db:
        companies = db.exec(select(Company)).all()
        for company in companies:
            events = db.exec(
                select(AuditEvent)
                .where(AuditEvent.company_id == company.id)
                .order_by(AuditEvent.sequence_number)
            ).all()
            previous_hash = None
            for sequence, event in enumerate(events, start=1):
                if event.sequence_number != sequence or event.previous_event_hash != previous_hash:
                    raise RuntimeError(f"Audit chain is invalid for tenant {company.id}")
                if not any(
                    hmac.compare_digest(
                        hashlib.sha256(payload.encode()).hexdigest(), event.event_hash
                    )
                    for payload in audit_payload_candidates(event)
                ):
                    raise RuntimeError(f"Audit chain is invalid for tenant {company.id}")
                archive_audit_event(event)
                previous_hash = event.event_hash
    print("Existing audit events were validated and anchored.")


if __name__ == "__main__":
    main()
