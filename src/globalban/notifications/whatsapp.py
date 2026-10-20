from __future__ import annotations

import base64
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from globalban.models.decisions import DetectionAlert
from globalban.privacy.masking import mask_ip

_SID = re.compile(r"^AC[0-9a-fA-F]{32}$")
_WHATSAPP_NUMBER = re.compile(r"^whatsapp:\+[1-9][0-9]{7,14}$")


def build_whatsapp_message(alert: DetectionAlert) -> dict[str, Any]:
    """Build a minimal masked notification; transport and credentials are caller-owned."""
    return {
        "type": "text",
        "text": (
            f"GlobalBan review alert {alert.rule_id}: {alert.failure_count} "
            f"authentication failures from {mask_ip(alert.source_ip)}. "
            "This is a review signal, not proof of identity or intent."
        ),
    }


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        del request, fp, code, message, headers, new_url
        return None


class WhatsAppNotifier:
    """Send an explicitly requested, minimized alert through the Twilio API."""

    def __init__(
        self,
        *,
        account_sid: str | None = None,
        auth_token: str | None = None,
        sender: str | None = None,
        recipient: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._account_sid = account_sid or os.getenv("GLOBALBAN_TWILIO_ACCOUNT_SID")
        self._auth_token = auth_token or os.getenv("GLOBALBAN_TWILIO_AUTH_TOKEN")
        self._sender = sender or os.getenv(
            "GLOBALBAN_WHATSAPP_FROM", "whatsapp:+14155238886"
        )
        self._recipient = recipient or os.getenv("GLOBALBAN_WHATSAPP_TO")
        if not self._account_sid or not _SID.fullmatch(self._account_sid):
            raise ValueError("A valid Twilio account SID is required")
        if not self._auth_token or any(char in self._auth_token for char in "\r\n"):
            raise ValueError("A valid Twilio auth token is required")
        if not self._sender or not _WHATSAPP_NUMBER.fullmatch(self._sender):
            raise ValueError("A valid WhatsApp sender number is required")
        if not self._recipient or not _WHATSAPP_NUMBER.fullmatch(self._recipient):
            raise ValueError("A valid WhatsApp recipient number is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._timeout_seconds = timeout_seconds

    def send_alert(self, alert: DetectionAlert) -> None:
        """Send only the preformatted message with a masked source address."""
        message = build_whatsapp_message(alert)["text"]
        credentials = base64.b64encode(
            f"{self._account_sid}:{self._auth_token}".encode("utf-8")
        ).decode("ascii")
        data = urlencode(
            {"From": self._sender, "To": self._recipient, "Body": message}
        ).encode("utf-8")
        request = Request(
            "https://api.twilio.com/2010-04-01/Accounts/"
            f"{self._account_sid}/Messages.json",
            data=data,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        opener = build_opener(_RejectRedirects())
        try:
            with opener.open(request, timeout=self._timeout_seconds) as response:
                if response.status >= 300:
                    raise RuntimeError(f"Twilio returned HTTP {response.status}")
        except HTTPError as exc:
            raise RuntimeError(f"Twilio returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"Could not reach Twilio: {exc.reason}") from exc