"""Verify the read-only JMAP Calendar preview against disposable CalDAV accounts."""
import argparse
from base64 import b64encode
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import uuid4


PREVIEW = "https://github.com/sendanor/jmap-gateway/capabilities/calendars-preview"
CORE = "urn:ietf:params:jmap:core"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, url, headers, cafile=None, body=None):
    context = ssl.create_default_context(cafile=cafile)
    opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
    req = Request(url, method=method, headers=headers, data=body)
    try:
        with opener.open(req, timeout=15) as result:
            return result.status, result.read()
    except HTTPError as result:
        return result.code, b""


def dav(config, method, collection, body=None):
    auth = b64encode(f'{config["Username"]}:{config["Password"]}'.encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/xml"}
    if method == "PROPFIND":
        headers["Depth"] = "0"
    return request(
        method, urljoin(config["URL"], collection), headers,
        config.get("CAFile"), body,
    )[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="gateway configuration for the disposable fixture")
    parser.add_argument("checkpoint", type=Path, help="checkpoint shared across the gateway restart")
    parser.add_argument("phase", choices=["before", "after", "unavailable"])
    parser.add_argument("--caldav-home", required=True, help="primary CalDAV account home path")
    parser.add_argument("--other-caldav-home", required=True, help="additional CalDAV account home path")
    parser.add_argument("--gateway-ca", help="CA for the gateway HTTPS endpoint")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    account = config["AccountID"]
    other, rejected = config["AdditionalAccounts"]
    primary_dav = config["CalDAV"]
    other_dav = other["CalDAV"]
    session_url = config["PublicOrigin"] + "/.well-known/jmap"
    headers = {"Authorization": "Bearer " + config["Token"], "Content-Type": "application/json"}
    assert request("GET", session_url, {}, args.gateway_ca)[0] == 401, "Unexpected unauthenticated session status"
    status, body = request("GET", session_url, headers, args.gateway_ca)
    assert status == 200, "Authenticated session discovery failed"
    session = json.loads(body)
    assert session["apiUrl"] == config["PublicOrigin"] + "/jmap", "Unexpected advertised API origin"
    assert PREVIEW in session["capabilities"] and "urn:ietf:params:jmap:calendars" not in session["capabilities"]
    assert session["primaryAccounts"][PREVIEW] == account
    assert PREVIEW in session["accounts"][other["AccountID"]]["accountCapabilities"]

    def jmap(method, target, **values):
        status, data = request(
            "POST", session["apiUrl"], headers, args.gateway_ca, json.dumps({
                "using": [CORE, PREVIEW],
                "methodCalls": [[method, {"accountId": target, **values}, "calendar"]],
            }).encode(),
        )
        assert status == 200, "Unexpected JMAP HTTP status"
        (name, result, tag), = json.loads(data)["methodResponses"]
        assert name in (method, "error") and tag == "calendar", "Invalid response invocation"
        return result

    if args.phase == "unavailable":
        assert jmap("Calendar/get", account) == {"type": "serverUnavailable"}
        print("Offline CalDAV returned a JMAP serverUnavailable error")
        return

    if args.phase == "before":
        marker = "jmap-acceptance-" + uuid4().hex
        first_path = args.caldav_home + marker + "/"
        other_path = args.other_caldav_home + marker + "/"
        body = (
            '<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">'
            f"<D:set><D:prop><D:displayname>{marker}</D:displayname></D:prop></D:set></C:mkcalendar>"
        ).encode()
        assert dav(primary_dav, "MKCALENDAR", first_path, body=body) == 201, "Primary CalDAV creation failed"
        assert dav(other_dav, "MKCALENDAR", other_path, body=body) == 201, "Secondary CalDAV creation failed"
        assert dav(primary_dav, "PROPFIND", first_path) == 207, "Primary CalDAV access failed"
        assert dav(other_dav, "PROPFIND", first_path) in (403, 404), "CalDAV exposed the primary collection"
        first = jmap("Calendar/get", account)
        second = jmap("Calendar/get", other["AccountID"])
        record = next(c for c in first["list"] if c["name"] == marker)
        separate = next(c for c in second["list"] if c["name"] == marker)
        assert record["id"] != separate["id"], "Calendar IDs were reused across accounts"
        denied = jmap("Calendar/get", other["AccountID"], ids=[record["id"]])
        assert denied["notFound"] == [record["id"]] and denied["list"] == []
        assert jmap("Calendar/get", rejected["AccountID"]) == {"type": "serverUnavailable"}
        checkpoint = {"marker": marker, "state": first["state"], "id": record["id"]}
        fd = os.open(args.checkpoint, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump(checkpoint, file)
        print("CalDAV creation, JMAP discovery, account isolation and CalDAV auth rejection verified")
        return

    saved = json.loads(args.checkpoint.read_text())
    record_id, marker = saved["id"], saved["marker"]
    before = jmap("Calendar/get", account, ids=[record_id], properties=["name"])
    assert before["state"] == saved["state"] and before["list"] == [{"id": record_id, "name": marker}]
    path = args.caldav_home + marker + "/"
    body = b"""<D:propertyupdate xmlns:D="DAV:">
      <D:set><D:prop><D:displayname>Hybrid calendar</D:displayname></D:prop></D:set>
    </D:propertyupdate>"""
    assert dav(primary_dav, "PROPPATCH", path, body=body) == 207, "CalDAV update failed"
    update = jmap("Calendar/changes", account, sinceState=saved["state"])
    assert update["updated"] == [record_id] and update["created"] == update["destroyed"] == []
    after = jmap("Calendar/get", account, ids=[record_id], properties=["name"])
    assert after["state"] == update["newState"] and after["list"] == [{"id": record_id, "name": "Hybrid calendar"}]
    assert dav(primary_dav, "DELETE", path) in (200, 204), "CalDAV deletion failed"
    removal = jmap("Calendar/changes", account, sinceState=update["newState"])
    assert removal["destroyed"] == [record_id] and removal["created"] == removal["updated"] == []
    assert dav(other_dav, "DELETE", args.other_caldav_home + marker + "/") in (200, 204)
    print("Calendar IDs and state survived restart. CalDAV rename and deletion propagated through JMAP")


if __name__ == "__main__":
    main()
