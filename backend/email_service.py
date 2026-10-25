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


def send_share_link(
    recipient: str,
    share_url: str,
    expires_at: object,
    otp_required: bool = False,
) -> str:
    expiration = escape(str(expires_at))
    safe_url = escape(share_url, quote=True)
    otp_note = (
        "\nA separate email contains the required verification code."
        if otp_required
        else ""
    )
    html_otp_note = (
        "<p>A separate email contains the required verification code.</p>"
        if otp_required
        else ""
    )
    return send_email(
        recipient,
        "A TrustVault document was shared with you",
        (
            f"A document was shared with you.\n\nOpen it here: {share_url}"
            f"{otp_note}\nThis link expires at {expires_at}."
        ),
        f'<p>A document was shared with you.</p><p><a href="{safe_url}">Open document</a></p>'
        f"{html_otp_note}<p>This link expires at {expiration}.</p>",
    )