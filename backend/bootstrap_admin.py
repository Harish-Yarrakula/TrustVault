from getpass import getpass

from sqlmodel import Session, select

from db import engine
from models import AccountType, Company, CompanyUser, UserRole, UserStatus, normalize_email
from server import hash_password, startup


def main() -> None:
    startup()
    email = normalize_email(input("Administrator email: "))
    full_name = input("Administrator name: ").strip()
    if not full_name:
        raise ValueError("Administrator name is required")
    password = getpass("Administrator password (12+ characters): ")
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Administrator password must be between 12 and 128 characters")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match")

    company = Company.for_email(email, input("Company name: ").strip() or None)
    if company.account_type != AccountType.CORPORATE:
        raise ValueError("The bootstrap email must use a corporate domain")

    with Session(engine) as db:
        if db.exec(select(CompanyUser.id).where(CompanyUser.email == email)).first():
            raise ValueError("This email is already registered")
        if db.exec(select(CompanyUser.id).where(CompanyUser.company_id == company.id)).first():
            raise ValueError("This tenant already has users; use an existing administrator invitation")
        existing_company = db.get(Company, company.id)
        if existing_company:
            company = existing_company
        else:
            db.add(company)
            db.flush()
        db.add(CompanyUser.for_email(
            email,
            full_name=full_name,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        ))
        db.commit()
    print("Corporate administrator created. Sign in using the configured frontend.")


if __name__ == "__main__":
    main()
