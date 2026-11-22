#!/usr/bin/env python3
"""Verify mailbox and Email identity through a real IMAP RENAME and gateway restart."""

import argparse
import imaplib
import json
import ssl
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="Private gateway config for a disposable account")
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("stage", choices=("before", "after"))
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    assert config.get("MailboxMetadataVendor"), "Configure MailboxMetadataVendor on the test account"
    headers = {"Authorization": "Bearer " + config["Token"], "Content-Type": "application/json"}
    gateway_tls = ssl.create_default_context(cafile=config["TLSCert"])
    discovery = config["PublicOrigin"] + "/.well-known/jmap"
    with urlopen(Request(discovery, headers=headers), context=gateway_tls, timeout=20) as response:
        session = json.load(response)
    assert session["apiUrl"].startswith(config["PublicOrigin"] + "/")
    account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    assert account == config["AccountID"]

    def call(method, **params):
        body = {
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [[method, {"accountId": account, **params}, "verify"]],
        }
        request = Request(session["apiUrl"], headers=headers, data=json.dumps(body).encode())
        with urlopen(request, context=gateway_tls, timeout=30) as response:
            (name, result, tag), = json.load(response)["methodResponses"]
        assert name == method and tag == "verify", (method, result.get("type"))
        return result

    if args.stage == "before":
        original = "JMAP-rename-" + uuid4().hex
        renamed = original + "-external"
        result = call(
            "Mailbox/set",
            create={
                "parent": {"name": original, "sortOrder": 17},
                "child": {"name": "Child", "parentId": "#parent", "sortOrder": 19},
            },
        )
        parent = result["created"]["parent"]["id"]
        child = result["created"]["child"]["id"]
        imap = config["IMAP"]
        host, port = imap["Address"].rsplit(":", 1)
        imap_tls = ssl.create_default_context(cafile=imap.get("CAFile") or None)
        with imaplib.IMAP4_SSL(host, int(port), ssl_context=imap_tls, timeout=15) as client:
            client.login(imap["Username"], imap["Password"])
            assert "METADATA" in client.capabilities
            assert client.append(
                original + "/Child", None, None, b"Subject: Stable identity\r\n\r\nOriginal fixture.\r\n"
            )[0] == "OK"
            mailbox_state = call("Mailbox/get")["state"]
            email_id, = call("Email/query", filter={"inMailbox": child})["ids"]
            email_state = call("Email/get", ids=[email_id])["state"]
            assert client.rename(original, renamed)[0] == "OK"
            assert client.create(original)[0] == "OK"
            assert client.create(original + "/Child")[0] == "OK"
            assert client.append(
                original + "/Child", None, None, b"Subject: Replacement\r\n\r\nReplacement fixture.\r\n"
            )[0] == "OK"
        args.checkpoint.write_text(json.dumps({
            "original": original, "renamed": renamed, "parent": parent, "child": child,
            "mailboxState": mailbox_state, "emailState": email_state, "emailId": email_id,
        }))
        print("Renamed an IMAP subtree externally and reused its old paths")
        return

    saved = json.loads(args.checkpoint.read_text())
    mailboxes = call("Mailbox/get")["list"]
    by_id = {mailbox["id"]: mailbox for mailbox in mailboxes}
    parent, child = by_id[saved["parent"]], by_id[saved["child"]]
    assert parent["name"] == saved["renamed"] and parent["sortOrder"] == 17
    assert child["parentId"] == parent["id"] and child["name"] == "Child" and child["sortOrder"] == 19
    replacement, = (box for box in mailboxes if box["name"] == saved["original"])
    replacement_child, = (box for box in mailboxes if box["parentId"] == replacement["id"])
    assert replacement["id"] != parent["id"] and replacement_child["id"] != child["id"]

    updates = call("Mailbox/changes", sinceState=saved["mailboxState"])
    assert parent["id"] in updates["updated"] and not updates["destroyed"]
    assert {replacement["id"], replacement_child["id"]} <= set(updates["created"])
    email, = call("Email/get", ids=[saved["emailId"]])["list"]
    assert email["mailboxIds"] == {child["id"]: True} and email["subject"] == "Stable identity"
    replacement_email, = call("Email/query", filter={"inMailbox": replacement_child["id"]})["ids"]
    assert replacement_email != saved["emailId"]
    changes = call("Email/changes", sinceState=saved["emailState"])
    assert replacement_email in changes["created"] and saved["emailId"] not in changes["destroyed"]

    final_name = saved["renamed"] + "-jmap"
    result = call("Mailbox/set", update={parent["id"]: {"name": final_name}})
    assert parent["id"] in result["updated"], result.get("notUpdated")
    records = call("Mailbox/get", ids=[parent["id"], child["id"]])["list"]
    assert records[0]["name"] == final_name and records[1]["parentId"] == parent["id"]
    assert call("Email/query", filter={"inMailbox": child["id"]})["ids"] == [saved["emailId"]]
    print("Verified stable Mailbox and Email IDs, path reuse, sync changes and a subsequent JMAP rename")


if __name__ == "__main__":
    main()
