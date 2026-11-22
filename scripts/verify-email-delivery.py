#!/usr/bin/env python3
"""Check EmailDelivery with a disposable account, real IMAP and authenticated SMTP."""

import argparse
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import imaplib
import json
from pathlib import Path
import smtplib
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


def read_event(stream):
    event = {}
    for line in stream:
        field, _, value = line.decode("utf-8").rstrip("\r\n").partition(": ")
        if not field and event:
            return event
        event[field] = json.loads(value) if field == "data" else value
    raise AssertionError("event stream ended prematurely")


def connect_imap(upstream):
    address = urlsplit("//" + upstream["Address"])
    context = ssl.create_default_context(cafile=upstream.get("CAFile") or None)
    return imaplib.IMAP4_SSL(address.hostname, address.port, ssl_context=context, timeout=15)


def deliver(config, subject):
    upstream = config["SMTP"]
    address = urlsplit("//" + upstream["Address"])
    context = ssl.create_default_context(cafile=upstream.get("CAFile") or None)
    mailbox = config["IdentityEmail"]
    message = EmailMessage()
    message["From"] = mailbox
    message["To"] = mailbox
    message["Date"] = formatdate()
    message["Message-ID"] = make_msgid(domain=mailbox.rsplit("@", 1)[1])
    message["Subject"] = subject
    message.set_content("Controlled EmailDelivery fixture.")
    if upstream["Mode"] == "tls":
        client = smtplib.SMTP_SSL(address.hostname, address.port, timeout=15, context=context)
    else:
        client = smtplib.SMTP(address.hostname, address.port, timeout=15)
    with client:
        if upstream["Mode"] == "starttls":
            client.starttls(context=context)
        client.login(upstream["Username"], upstream["Password"])
        assert client.send_message(message, from_addr=mailbox, to_addrs=[mailbox]) == {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="Private config for a disposable gateway account")
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("stage", choices=("before", "after"))
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    gateway_tls = ssl.create_default_context(cafile=config["TLSCert"])
    origin = config["PublicOrigin"]
    auth = {"Authorization": "Bearer " + config["Token"]}
    with urlopen(Request(origin + "/.well-known/jmap", headers=auth), context=gateway_tls, timeout=15) as response:
        session = json.load(response)
    assert session["apiUrl"].startswith(origin + "/")
    assert session["eventSourceUrl"].startswith(origin + "/")
    account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    assert account == config["AccountID"]

    def call(method, **params):
        request = Request(session["apiUrl"], headers={**auth, "Content-Type": "application/json"}, data=json.dumps({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [[method, {"accountId": account, **params}, "verify"]],
        }).encode())
        with urlopen(request, context=gateway_tls, timeout=20) as response:
            (name, result, tag), = json.load(response)["methodResponses"]
        assert name == method and tag == "verify", (method, result.get("type"))
        return result

    def stream(event_id=None):
        url = session["eventSourceUrl"].replace("{types}", "EmailDelivery")
        url = url.replace("{closeafter}", "state").replace("{ping}", "1")
        headers = auth if event_id is None else {**auth, "Last-Event-ID": event_id}
        return urlopen(Request(url, headers=headers), context=gateway_tls, timeout=20)

    def delivery_state(event):
        assert event["event"] == "state" and event["data"]["@type"] == "StateChange"
        changed = event["data"]["changed"]
        assert all(set(kinds) == {"EmailDelivery"} for kinds in changed.values())
        assert changed[account]["EmailDelivery"]
        return changed[account]["EmailDelivery"]

    if args.stage == "before":
        label = "EmailDelivery-" + uuid4().hex
        subject = label + "-existing"
        imap = config["IMAP"]
        with connect_imap(imap) as client:
            client.login(imap["Username"], imap["Password"])
            assert client.append("INBOX", None, None, f"Subject: {subject}\r\n\r\nFixture.\r\n".encode())[0] == "OK"
        email_id, = call("Email/query", filter={"subject": subject})["ids"]
        target = call("Mailbox/set", create={"target": {"name": label}})["created"]["target"]["id"]
        with stream() as events:
            initial = read_event(events)
        before = delivery_state(initial)

        for patch in ({"keywords/$seen": True}, {"mailboxIds": {target: True}}):
            changed = call("Email/set", update={email_id: patch})
            assert email_id in changed["updated"] and changed["oldState"] != changed["newState"]
        deleted = call("Email/set", destroy=[email_id])
        assert deleted["destroyed"] == [email_id]
        args.checkpoint.write_text(json.dumps({
            "eventId": initial["id"], "deliveryState": before, "emailState": deleted["newState"],
            "subject": label + "-arrival",
        }))
        print("Recorded delivery state before flag change, move and deletion")
        return

    saved = json.loads(args.checkpoint.read_text())
    with stream(saved["eventId"]) as events:
        assert read_event(events)["event"] == "ping"
        deliver(config, saved["subject"])
        event = read_event(events)
        while event["event"] == "ping":
            event = read_event(events)
        assert delivery_state(event) != saved["deliveryState"] and event["id"] != saved["eventId"]
        assert set(event["data"]["changed"]) == {account}
    delivered, = call("Email/query", filter={"subject": saved["subject"]})["ids"]
    delta = call("Email/changes", sinceState=saved["emailState"])
    assert delivered in delta["created"]
    print("Verified delivery-only notification for real SMTP-to-IMAP arrival after restart")


if __name__ == "__main__":
    main()
