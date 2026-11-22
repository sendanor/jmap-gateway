"""Verify the Postfix delivery report for the dsn-envelope acceptance scenario."""

import argparse
from email import policy
from email.parser import BytesParser
import imaplib
import json
import os
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit


def matching_report(message, envelope_id, recipient):
    for part in message.walk():
        if part.get_content_type() != "message/delivery-status":
            continue
        fields = part.get_payload()
        if fields[0].get("Original-Envelope-Id") != envelope_id:
            continue
        for result in fields[1:]:
            address = result.get("Final-Recipient", "").partition(";")[2].strip()
            if address == recipient and result.get("Action") == "delivered" and result.get("Status", "").startswith("2."):
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="Private gateway config for the sender's IMAP account")
    args = parser.parse_args()
    upstream = json.loads(args.config.read_text())["IMAP"]
    address = urlsplit("//" + upstream["Address"])
    tls = ssl.create_default_context(cafile=upstream.get("CAFile") or None)
    subject = os.environ["JMAP_ACCEPTANCE_SUBJECT"]
    envelope_id = f"JMAP DSN =+ {subject.split()[-1]}"
    recipient = os.environ["JMAP_RECIPIENT"]
    deadline = time.monotonic() + 20
    with imaplib.IMAP4_SSL(address.hostname, address.port, ssl_context=tls, timeout=10) as client:
        client.login(upstream["Username"], upstream["Password"])
        while time.monotonic() < deadline:
            assert client.select("INBOX", readonly=True)[0] == "OK"
            status, ids = client.uid("SEARCH", None, "HEADER", "Content-Type", '"multipart/report"')
            assert status == "OK"
            matches = 0
            for uid in ids[0].split():
                status, fields = client.uid("FETCH", uid, "(BODY.PEEK[])")
                assert status == "OK"
                raw = next(part[1] for part in fields if isinstance(part, tuple))
                if matching_report(BytesParser(policy=policy.default).parsebytes(raw), envelope_id, recipient):
                    matches += 1
            if matches:
                assert matches == 1
                print("Verified a correlated SMTP delivery report through sender IMAP")
                return
            time.sleep(0.5)
    raise AssertionError("No correlated delivered SMTP report reached the sender's IMAP inbox")


if __name__ == "__main__":
    main()
