"""Verify exactly one acceptance message through the controlled recipient's IMAP."""
import email
import imaplib
import os
import ssl
import time
from email import policy


def address_values(header):
    # BytesParser represents raw SMTPUTF8 octets as surrogate escapes.
    return [a.addr_spec.encode("utf-8", "surrogateescape").decode("utf-8") for a in header.addresses]


def verify_message(client, uid, subject, header_recipient):
    status, parts = client.uid("FETCH", uid, "(BODY.PEEK[])")
    if status != "OK":
        raise RuntimeError("Recipient IMAP fetch failed")
    raw = next(part[1] for part in parts if isinstance(part, tuple))
    message = email.message_from_bytes(raw, policy=policy.default)
    plain = message.get_body(preferencelist=("plain",))
    if (
        message["Subject"] != subject
        or address_values(message["To"]) != [header_recipient]
        or "Bcc" in message
        or plain is None
        or plain.get_content().strip() != f"This message verifies {subject}."
    ):
        raise RuntimeError("Recipient message content did not match")
    sender = os.environ.get("JMAP_HEADER_SENDER")
    if sender is not None and address_values(message["From"]) != [sender]:
        raise RuntimeError("Recipient message sender did not match")
    if os.environ.get("JMAP_SCENARIO") == "draft-headers":
        message_id = f"<{subject.split()[-1]}@jmap.test>"
        trace = [str(value) for value in message.get_all("X-JMAP-Trace", [])]
        if (
            message["Message-ID"] != message_id
            or trace != ["first", "second continued"]
            or message["List-Id"] != "Postin otsaketesti"
        ):
            raise RuntimeError("Recipient draft headers did not match")
        attachments = list(message.iter_attachments())
        if len(attachments) != 1:
            raise RuntimeError("Recipient MIME attachment missing")
        attached = attachments[0]
        part_trace = [str(value) for value in attached.get_all("X-Part-Trace", [])]
        if (
            attached.get_filename() != "fixture.bin"
            or attached["Content-Description"] != "Liite ää"
            or part_trace != trace
            or attached.get_payload(decode=True) != bytes([0, 13, 10, 127, 128, 255])
        ):
            raise RuntimeError("Recipient MIME part headers or attachment bytes did not match")

    if os.environ.get("JMAP_SCENARIO") == "forward-attachment":
        mode = os.environ.get("JMAP_EMBEDDED_FORMAT", "7bit")
        media_type = "message/global" if mode == "global" else "message/rfc822"
        encoding = "7bit" if mode == "7bit" else "8bit"
        attachments = list(message.iter_attachments())
        if (
            len(attachments) != 1
            or attachments[0].get_content_type() != media_type
            or attachments[0].get_filename() != "forwarded.eml"
            or attachments[0]["Content-Transfer-Encoding"] != encoding
        ):
            raise RuntimeError("Wrong attached message MIME framing")
        delimiter = b"\r\n--" + message.get_boundary().encode("ascii")
        part_type = b"content-type: " + media_type.encode("ascii")
        blobs = [
            entity.split(b"\r\n\r\n", 1)[1] for entity in raw.split(delimiter)[1:-1]
            if part_type in entity.split(b"\r\n\r\n", 1)[0].lower()
        ]
        prefix = "Välitetty" if mode == "global" else "Forwarded"
        content_type = "text/plain" if mode == "7bit" else "text/plain; charset=utf-8"
        embedded_encoding = "" if mode == "7bit" else "Content-Transfer-Encoding: 8bit\r\n"
        content = ".Original archived text." if mode == "7bit" else ".Alkuperäinen teksti."
        embedded = (
            "From: archived@example.test\r\n"
            f"Subject: {prefix} {subject}\r\n"
            "Bcc: original-private@example.test\r\n"
            f"Content-Type: {content_type}\r\n{embedded_encoding}\r\n"
            f"{content}\r\n"
        ).encode("utf-8")
        if blobs != [embedded]:
            raise RuntimeError("Recipient's attached message bytes did not match")



def main():
    subject = os.environ["JMAP_ACCEPTANCE_SUBJECT"]
    if not subject.startswith("JMAP acceptance ") or not all(
        ch.isascii() and (ch.isalnum() or ch in " -") for ch in subject
    ):
        raise ValueError("Expected an acceptance subject")
    context = ssl.create_default_context(cafile=os.environ.get("JMAP_RECIPIENT_IMAP_CA"))
    with imaplib.IMAP4_SSL(
        os.environ["JMAP_RECIPIENT_IMAP_HOST"],
        int(os.environ.get("JMAP_RECIPIENT_IMAP_PORT", "993")),
        ssl_context=context,
        timeout=10,
    ) as client:
        client.login(
            os.environ["JMAP_RECIPIENT_IMAP_USERNAME"],
            os.environ["JMAP_RECIPIENT_IMAP_PASSWORD"],
        )
        if client.select("INBOX", readonly=True)[0] != "OK":
            raise RuntimeError("Cannot select recipient INBOX")
        deadline = time.monotonic() + 30
        found_at = None
        while time.monotonic() < deadline:
            status, result = client.uid("SEARCH", "HEADER", "Subject", f'"{subject}"')
            if status != "OK":
                raise RuntimeError("Recipient IMAP search failed")
            uids = result[0].split()
            if len(uids) > 1:
                raise RuntimeError("Duplicate delivery in recipient INBOX")
            if len(uids) == 1:
                if found_at is None:
                    header_recipient = os.environ.get("JMAP_HEADER_RECIPIENT", os.environ["JMAP_RECIPIENT"])
                    verify_message(client, uids[0], subject, header_recipient)
                    found_at = time.monotonic()
                elif time.monotonic() - found_at >= 2:
                    print("Verified one matching message through recipient IMAP")
                    return
            time.sleep(1)
    raise RuntimeError("Recipient delivery timed out")


if __name__ == "__main__":
    main()
