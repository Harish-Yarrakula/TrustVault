from __future__ import annotations

import os
from html import escape
from urllib.parse import quote
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError

load_dotenv()
class EmailDeliveryError(RuntimeError):
    pass


def send_email(
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> str:
    sender = os.getenv("SES_FROM_EMAIL")
    if not sender:
        raise EmailDeliveryError("SES_FROM_EMAIL is not configured")

    client = boto3.client(
        "ses",
        region_name=os.getenv("SES_REGION", os.getenv("AWS_REGION", os.getenv("REGION"))),
    )
    message = {
        "Source": sender,
        "Destination": {"ToAddresses": [recipient]},
        "Message": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": text_body, "Charset": "UTF-8"},
                "Html": {"Data": html_body, "Charset": "UTF-8"},
            },
        },
    }
    configuration_set = os.getenv("SES_CONFIGURATION_SET")
    if configuration_set:
        message["ConfigurationSetName"] = configuration_set

    try:
        response = client.send_email(**message)
    except (BotoCoreError, ClientError) as exc:
        raise EmailDeliveryError("Amazon SES could not send the email") from exc
    return str(response["MessageId"])


def send_guest_invitation(recipient: str, token: str, expires_at: object) -> str:
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    invitation_url = f"{frontend_url.rstrip('/')}/guest/accept?token={quote(token, safe='')}"
    expiration = escape(str(expires_at))
    safe_url = escape(invitation_url, quote=True)
    return send_email(
        recipient,
        "You have been invited to TrustVault",
        (
            "You have been invited to TrustVault.\n\n"
            f"Accept the invitation here: {invitation_url}\n"
            f"This invitation expires at {expiration}."
        ),
        (
            "<p>You have been invited to TrustVault.</p>"
            f'<p><a href="{safe_url}">Accept invitation</a></p>'
            f"<p>This invitation expires at {expiration}.</p>"
        ),
    )


def send_share_otp(recipient: str, otp: str, expires_at: object) -> str:
    expiration = str(expires_at)
    return send_email(
        recipient,
        "Your TrustVault verification code",
        f"Your TrustVault verification code is {otp}. It expires at {expiration}.",
        f"<p>Your TrustVault verification code is "
        f"<strong>{otp}</strong>.</p><p>It expires at {expiration}.</p>",
    )


def send_share_link(recipient: str, share_url: str, expires_at: object) -> str:
    expiration = escape(str(expires_at))
    safe_url = escape(share_url, quote=True)
    return send_email(
        recipient,
        "A TrustVault document was shared with you",
        f"A document was shared with you.\n\nOpen it here: {share_url}\nThis link expires at {expires_at}.",
        f'<p>A document was shared with you.</p><p><a href="{safe_url}">Open document</a></p>'
        f"<p>This link expires at {expiration}.</p>",
    )
if __name__ == "__main__":
    from datetime import datetime, timedelta, timezone

    # Replace with your test recipient email
    TEST_RECIPIENT = "trustvaulttest3@outlook.com"
    expiry_time = datetime.now(timezone.utc) + timedelta(hours=24)

    print(f"Sending test emails to: {TEST_RECIPIENT}...")

    try:
        # Test 1: Send OTP
        otp_id = send_share_otp(
            recipient=TEST_RECIPIENT,
            otp="749201",
            expires_at=expiry_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        print(f" [1/2] OTP Sent! SES Message ID: {otp_id}")

        # Test 2: Send Guest Invitation
        invite_id = send_guest_invitation(
            recipient=TEST_RECIPIENT,
            token="test-token-uuid-v4-abc-123",
            expires_at=expiry_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        print(f" [2/2] Invitation Sent! SES Message ID: {invite_id}")

    except EmailDeliveryError as err:
        print(f"\n Delivery failed: {err}")
        if err.__cause__:
            print(f"Underlying AWS error: {err.__cause__}")